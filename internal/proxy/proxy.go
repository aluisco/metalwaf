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

	"github.com/metalwaf/metalwaf/internal/database"
	"github.com/metalwaf/metalwaf/internal/waf"
)

// siteEntry groups a site's configuration with its upstream pool.
type siteEntry struct {
	site *database.Site
	pool *UpstreamPool
}

// Handler is the core reverse proxy HTTP handler.
// It routes requests by Host header to the upstream pool of the matching site.
type Handler struct {
	store   database.Store
	mu      sync.RWMutex
	sites   map[string]*siteEntry // lowercase domain → entry
	limiter *rateLimiter
	waf     *waf.Engine // nil until SetWAF is called
}

// SetWAF attaches a WAF engine to the handler. Requests will be inspected
// before being forwarded to the upstream. Safe to call before the server starts.
func (h *Handler) SetWAF(e *waf.Engine) {
	h.waf = e
}

// New creates a Handler, loads all enabled sites from the database, and starts
// background health check goroutines for each upstream pool.
// The provided ctx controls the lifetime of those goroutines.
func New(ctx context.Context, store database.Store) (*Handler, error) {
	h := &Handler{
		store:   store,
		sites:   make(map[string]*siteEntry),
		limiter: newRateLimiter(defaultRPS, defaultBurst),
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
	}

	h.mu.Lock()
	h.sites = newMap
	h.mu.Unlock()

	slog.Info("proxy: configuration loaded", "sites", len(newMap))
	return nil
}

// ServeHTTP implements http.Handler.
//
// Request pipeline:
//  1. Per-IP rate limiting (429 if exceeded)
//  2. Site lookup by Host header (404 if not found)
//  3. https_only redirect: HTTP → HTTPS 301
//  4. WAF inspection (block/detect/off depending on site mode)
//  5. Weighted round-robin upstream selection (503 if none healthy)
//  6. httputil.ReverseProxy forward with header rewriting
//     (WebSocket upgrades are handled transparently by the standard library)
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	// ── Rate limiting ──────────────────────────────────────────────────────
	if !h.limiter.allow(ip) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// ── Site lookup by Host header ─────────────────────────────────────────
	host := strings.ToLower(stripPort(r.Host))
	h.mu.RLock()
	entry, ok := h.sites[host]
	h.mu.RUnlock()

	if !ok {
		http.Error(w, "404 site not found", http.StatusNotFound)
		return
	}

	// ── HTTPS-only redirect ────────────────────────────────────────────────
	if entry.site.HTTPSOnly && r.TLS == nil {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// ── WAF inspection ─────────────────────────────────────────────────────
	if h.waf != nil {
		result := h.waf.Inspect(r, entry.site)
		if result.Blocked {
			for _, m := range result.MatchedRules {
				slog.Warn("waf: request blocked",
					"domain", host,
					"ip", ip,
					"path", r.URL.Path,
					"rule", m.Rule.Name,
					"score", result.Score,
				)
			}
			waf.WriteBlocked(w)
			return
		}
		for _, m := range result.MatchedRules {
			slog.Info("waf: threat detected",
				"domain", host,
				"ip", ip,
				"path", r.URL.Path,
				"rule", m.Rule.Name,
				"score", result.Score,
			)
		}
	}

	// ── Upstream selection ─────────────────────────────────────────────────
	upstream := entry.pool.Next()
	if upstream == nil {
		slog.Warn("proxy: no healthy upstreams", "domain", host)
		http.Error(w, "503 no healthy upstreams", http.StatusServiceUnavailable)
		return
	}

	// ── Reverse proxy ──────────────────────────────────────────────────────
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	buildReverseProxy(upstream, ip, proto).ServeHTTP(w, r)
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
