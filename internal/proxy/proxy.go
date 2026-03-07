// Package proxy implements the HTTP/HTTPS reverse proxy core of MetalWAF.
// It routes incoming requests to the correct upstream pool based on the Host
// header, enforces per-IP rate limiting, rewrites forwarding headers, handles
// WebSocket upgrades, and supports per-site https_only redirects.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metalwaf/metalwaf/internal/database"
	"github.com/metalwaf/metalwaf/internal/waf"
)

// siteEntry groups a site's configuration with its upstream pool.
type siteEntry struct {
	site *database.Site
	pool *UpstreamPool
}

// LogSink is implemented by analytics.Collector.
// Using an interface here avoids importing the analytics package from proxy.
type LogSink interface {
	Submit(*database.RequestLog)
}

// Handler is the core reverse proxy HTTP handler.
// It routes requests by Host header to the upstream pool of the matching site.
type Handler struct {
	store      database.Store
	mu         sync.RWMutex
	sites      map[string]*siteEntry // lowercase domain → entry
	limiter    *rateLimiter          // global per-IP limiter
	siteLimits *rateLimiterMap       // per-site per-IP limiters
	ipChecker  *IPChecker            // global allow/block lists
	waf        *waf.Engine           // nil until SetWAF is called
	sink       LogSink               // nil until SetSink is called
}

// SetWAF attaches a WAF engine to the handler.
func (h *Handler) SetWAF(e *waf.Engine) { h.waf = e }

// SetSink attaches the analytics collector as the request-log sink.
// When set, all request logs are submitted to the sink asynchronously;
// when nil the proxy falls back to a direct goroutine-per-request write.

func (h *Handler) SetSink(s LogSink) { h.sink = s }

// New creates a Handler, loads all enabled sites from the database, and starts
// background health check goroutines for each upstream pool.
// The provided ctx controls the lifetime of those goroutines.
func New(ctx context.Context, store database.Store) (*Handler, error) {
	h := &Handler{
		store:      store,
		sites:      make(map[string]*siteEntry),
		limiter:    newRateLimiter(defaultRPS, defaultBurst),
		siteLimits: newRateLimiterMap(),
		ipChecker:  BuildIPChecker(nil),
	}
	if err := h.Reload(ctx); err != nil {
		return nil, err
	}
	return h, nil
}

// Reload refreshes the in-memory site and upstream configuration from the
// database. It is safe to call concurrently with ServeHTTP; the write lock
// is held only while swapping the map.
//
// Call this after creating, updating, or deleting sites via the API (Phase 4).
func (h *Handler) Reload(ctx context.Context) error {
	sites, err := h.store.ListSites(ctx)
	if err != nil {
		return fmt.Errorf("proxy reload: listing sites: %w", err)
	}

	newMap := make(map[string]*siteEntry, len(sites))
	perSite := make(map[string][2]float64, len(sites))
	for _, s := range sites {
		if !s.Enabled {
			continue
		}
		ups, err := h.store.ListUpstreamsBySite(ctx, s.ID)
		if err != nil {
			return fmt.Errorf("proxy reload: listing upstreams for %q: %w", s.Domain, err)
		}
		pool, err := NewPool(ups)
		if err != nil {
			return fmt.Errorf("proxy reload: building pool for %q: %w", s.Domain, err)
		}
		pool.StartHealthChecks(ctx)
		newMap[strings.ToLower(s.Domain)] = &siteEntry{site: s, pool: pool}
		if s.RateLimitRPS > 0 {
			perSite[s.ID] = [2]float64{s.RateLimitRPS, float64(s.RateLimitBurst)}
		}
	}

	// Load IP lists for the global checker.
	ipLists, err := h.store.ListIPLists(ctx, nil, nil)
	if err != nil {
		return fmt.Errorf("proxy reload: listing ip lists: %w", err)
	}

	h.mu.Lock()
	h.sites = newMap
	h.ipChecker = BuildIPChecker(ipLists)
	h.mu.Unlock()

	h.siteLimits.rebuild(perSite)

	slog.Info("proxy: configuration loaded", "sites", len(newMap))
	return nil
}

// ServeHTTP implements http.Handler.
//
// Request pipeline:
//  1. Global IP blocklist check (403 if blocked)
//  2. Global rate limiting — skip if IP is allowlisted (429 if exceeded)
//  3. Site lookup by Host header (404 if not found)
//  4. Per-site rate limiting — skip if IP is allowlisted (429 if exceeded)
//  5. https_only redirect: HTTP → HTTPS 301
//  6. WAF inspection — skip if IP is allowlisted (block/detect/off per site mode)
//  7. Weighted round-robin upstream selection (503 if none healthy)
//  8. httputil.ReverseProxy forward with header rewriting
//     (WebSocket upgrades are handled transparently by the standard library)
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := clientIP(r)
	lw := newLoggingRW(w)

	// ── Global IP allow/block check ────────────────────────────────────────
	h.mu.RLock()
	checker := h.ipChecker
	h.mu.RUnlock()
	allowed, blocked := checker.Check(ip)
	if blocked {
		http.Error(lw, "403 Forbidden", http.StatusForbidden)
		h.storeRequestLog(r, nil, ip, lw, start, nil)
		return
	}

	// ── Global rate limiting (skip if allowlisted) ─────────────────────────
	if !allowed && !h.limiter.allow(ip) {
		lw.Header().Set("Retry-After", "1")
		http.Error(lw, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// ── Site lookup by Host header ─────────────────────────────────────────
	host := strings.ToLower(stripPort(r.Host))
	h.mu.RLock()
	entry, ok := h.sites[host]
	h.mu.RUnlock()

	if !ok {
		http.Error(lw, "404 site not found", http.StatusNotFound)
		return
	}

	// ── Per-site rate limiting (skip if globally allowlisted) ──────────────
	if !allowed && !h.siteLimits.allow(entry.site.ID, ip) {
		lw.Header().Set("Retry-After", "1")
		http.Error(lw, "429 Too Many Requests", http.StatusTooManyRequests)
		h.storeRequestLog(r, entry.site, ip, lw, start, nil)
		return
	}

	// ── HTTPS-only redirect ────────────────────────────────────────────────
	if entry.site.HTTPSOnly && r.TLS == nil {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// ── WAF inspection (skip if globally allowlisted) ─────────────────────
	var wafResult *waf.InspectResult
	if !allowed && h.waf != nil {
		wafResult = h.waf.Inspect(r, entry.site)
		if wafResult.Blocked {
			for _, m := range wafResult.MatchedRules {
				slog.Warn("waf: request blocked",
					"domain", host,
					"ip", ip,
					"path", r.URL.Path,
					"rule", m.Rule.Name,
					"score", wafResult.Score,
				)
			}
			waf.WriteBlocked(lw)
			h.storeRequestLog(r, entry.site, ip, lw, start, wafResult)
			return
		}
		for _, m := range wafResult.MatchedRules {
			slog.Info("waf: threat detected",
				"domain", host,
				"ip", ip,
				"path", r.URL.Path,
				"rule", m.Rule.Name,
				"score", wafResult.Score,
			)
		}
	}

	// ── Upstream selection ─────────────────────────────────────────────────
	upstream := entry.pool.Next()
	if upstream == nil {
		slog.Warn("proxy: no healthy upstreams", "domain", host)
		http.Error(lw, "503 no healthy upstreams", http.StatusServiceUnavailable)
		h.storeRequestLog(r, entry.site, ip, lw, start, wafResult)
		return
	}

	// ── Reverse proxy ──────────────────────────────────────────────────────
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	buildReverseProxy(upstream, ip, proto).ServeHTTP(lw, r)
	h.storeRequestLog(r, entry.site, ip, lw, start, wafResult)
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code and
// bytes written so the proxy can persist a request log entry.
type loggingResponseWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int64
	wroteHeader  bool
}

func newLoggingRW(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	if !lw.wroteHeader {
		lw.status = code
		lw.wroteHeader = true
	}
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lw.ResponseWriter.Write(b)
	lw.bytesWritten += int64(n)
	return n, err
}

// storeRequestLog persists a request log entry via the analytics sink when
// available, or falls back to a direct async write to the store.
func (h *Handler) storeRequestLog(r *http.Request, site *database.Site, ip string,
	lw *loggingResponseWriter, start time.Time, result *waf.InspectResult) {

	l := &database.RequestLog{
		Timestamp:  start,
		ClientIP:   ip,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		StatusCode: lw.status,
		BytesSent:  lw.bytesWritten,
		DurationMS: time.Since(start).Milliseconds(),
		UserAgent:  r.Header.Get("User-Agent"),
	}
	if site != nil {
		l.SiteID = &site.ID
	}
	if result != nil {
		l.Blocked = result.Blocked
		l.ThreatScore = result.Score
		if len(result.MatchedRules) > 0 {
			// Only set rule_id FK for custom rules that exist in the DB.
			// Builtin rules are in-memory only and have no waf_rules row.
			if top := result.MatchedRules[0].Rule; !top.Builtin && top.ID != "" {
				l.RuleID = &top.ID
			}
		}
	}

	// Use collector sink when available (preferred path: non-blocking, updates aggregator).
	if h.sink != nil {
		h.sink.Submit(l)
		return
	}

	// Fallback: direct goroutine write (no aggregator update).
	if h.store == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.store.CreateRequestLog(ctx, l); err != nil {
			slog.Warn("proxy: failed to write request log", "error", err)
		}
	}()
}

// buildReverseProxy constructs a configured httputil.ReverseProxy for the
// given upstream URL. The Director injects forwarding headers and rewrites the
// Host header. WebSocket upgrades are handled automatically by the standard
// library (no extra code needed since Go 1.12).
func buildReverseProxy(target *url.URL, ip, proto string) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(target)

	base := rp.Director
	rp.Director = func(req *http.Request) {
		base(req)
		setForwardHeaders(req, ip, proto)
		// Rewrite Host to the upstream host so the backend can serve correctly.
		req.Host = target.Host
	}

	rp.ModifyResponse = func(resp *http.Response) error {
		stripResponseHeaders(resp.Header)
		return nil
	}

	rp.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		slog.Warn("proxy: upstream error",
			"upstream", target.Host,
			"path", req.URL.Path,
			"error", err,
		)
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
	}

	return rp
}
