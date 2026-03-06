package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/metalwaf/metalwaf/internal/analytics"
	"github.com/metalwaf/metalwaf/internal/database"
)

type analyticsHandler struct {
	store database.Store
	agg   *analytics.Aggregator // nil when no aggregator is configured
}

// ListLogs handles GET /api/v1/logs
//
// Query params (all optional):
//   - site_id  (UUID)
//   - ip       (string)
//   - blocked  ("true"/"false")
//   - from     (RFC3339 timestamp)
//   - to       (RFC3339 timestamp)
//   - limit    (int, default 100, max 1000)
//   - offset   (int, default 0)
func (h *analyticsHandler) ListLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f := database.RequestLogFilter{
		Limit:  100,
		Offset: 0,
	}

	if sid := q.Get("site_id"); sid != "" {
		if !validUUID(sid) {
			respondError(w, http.StatusBadRequest, "invalid site_id")
			return
		}
		f.SiteID = &sid
	}
	if ip := q.Get("ip"); ip != "" {
		f.ClientIP = ip
	}
	if b := q.Get("blocked"); b != "" {
		v, err := parseBoolParam(b)
		if err != nil {
			respondError(w, http.StatusBadRequest, "blocked must be true or false")
			return
		}
		f.Blocked = v
	}
	if from := q.Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			respondError(w, http.StatusBadRequest, "from must be an RFC3339 timestamp (e.g. 2006-01-02T15:04:05Z)")
			return
		}
		f.From = &t
	}
	if to := q.Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			respondError(w, http.StatusBadRequest, "to must be an RFC3339 timestamp (e.g. 2006-01-02T15:04:05Z)")
			return
		}
		f.To = &t
	}
	if lim := q.Get("limit"); lim != "" {
		n, err := strconv.Atoi(lim)
		if err != nil || n <= 0 || n > 1000 {
			respondError(w, http.StatusBadRequest, "limit must be between 1 and 1000")
			return
		}
		f.Limit = n
	}
	if off := q.Get("offset"); off != "" {
		n, err := strconv.Atoi(off)
		if err != nil || n < 0 {
			respondError(w, http.StatusBadRequest, "offset must be >= 0")
			return
		}
		f.Offset = n
	}

	logs, err := h.store.ListRequestLogs(r.Context(), f)
	if err != nil {
		slog.Error("api: list logs", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	total, err := h.store.CountRequestLogs(r.Context(), f)
	if err != nil {
		slog.Error("api: count logs", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	type logEntry struct {
		ID          string  `json:"id"`
		SiteID      *string `json:"site_id"`
		Timestamp   string  `json:"timestamp"`
		ClientIP    string  `json:"client_ip"`
		Method      string  `json:"method"`
		Host        string  `json:"host"`
		Path        string  `json:"path"`
		Query       string  `json:"query,omitempty"`
		StatusCode  int     `json:"status_code"`
		BytesSent   int64   `json:"bytes_sent"`
		DurationMS  int64   `json:"duration_ms"`
		Blocked     bool    `json:"blocked"`
		ThreatScore int     `json:"threat_score"`
		UserAgent   string  `json:"user_agent"`
	}

	entries := make([]logEntry, 0, len(logs))
	for _, l := range logs {
		entries = append(entries, logEntry{
			ID:          l.ID,
			SiteID:      l.SiteID,
			Timestamp:   l.Timestamp.Format(time.RFC3339),
			ClientIP:    l.ClientIP,
			Method:      l.Method,
			Host:        l.Host,
			Path:        l.Path,
			Query:       l.Query,
			StatusCode:  l.StatusCode,
			BytesSent:   l.BytesSent,
			DurationMS:  l.DurationMS,
			Blocked:     l.Blocked,
			ThreatScore: l.ThreatScore,
			UserAgent:   l.UserAgent,
		})
	}

	respond(w, http.StatusOK, map[string]any{
		"logs":   entries,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

// Metrics handles GET /api/v1/metrics
// Returns aggregate request counts for the last 24 h, all time, real-time
// per-minute rates, a 60-minute traffic timeline, and top-N breakdowns.
func (h *analyticsHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()
	since24h := now.Add(-24 * time.Hour)
	f24h := database.RequestLogFilter{From: &since24h, Limit: 1}

	// All-time totals
	totalAll, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{Limit: 1})
	if err != nil {
		slog.Error("api: metrics count all", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	blockedAll, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		Blocked: boolPtr(true), Limit: 1,
	})
	if err != nil {
		slog.Error("api: metrics count blocked all", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Last 24 hours
	total24h, err := h.store.CountRequestLogs(ctx, f24h)
	if err != nil {
		slog.Error("api: metrics count 24h", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	blocked24h, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		From: &since24h, Blocked: boolPtr(true), Limit: 1,
	})
	if err != nil {
		slog.Error("api: metrics count blocked 24h", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	var blockRate24h float64
	if total24h > 0 {
		blockRate24h = float64(blocked24h) / float64(total24h)
	}

	// Top-N breakdowns (last 24 h)
	topIPs, _ := h.store.TopClientIPs(ctx, f24h, 10)
	topPaths, _ := h.store.TopPaths(ctx, f24h, 10)
	topRules, _ := h.store.TopRules(ctx, f24h, 10)
	statusCodes, _ := h.store.StatusCodeDist(ctx, f24h)
	perSite, _ := h.store.RequestsPerSite(ctx, f24h)

	// Ensure slices are never null in the JSON output
	if topIPs == nil {
		topIPs = []database.CountEntry{}
	}
	if topPaths == nil {
		topPaths = []database.CountEntry{}
	}
	if topRules == nil {
		topRules = []database.CountEntry{}
	}
	if statusCodes == nil {
		statusCodes = []database.CountEntry{}
	}
	if perSite == nil {
		perSite = []database.CountEntry{}
	}

	// Real-time data from in-memory aggregator
	var reqPerMin, blockedPerMin int64
	var traffic []analytics.MinuteStat
	if h.agg != nil {
		reqPerMin, blockedPerMin = h.agg.LastMinute()
		traffic = h.agg.Snapshot(60)
	} else {
		traffic = []analytics.MinuteStat{}
	}

	respond(w, http.StatusOK, map[string]any{
		"requests_total":    totalAll,
		"requests_24h":      total24h,
		"blocked_total":     blockedAll,
		"blocked_24h":       blocked24h,
		"block_rate_24h":    blockRate24h,
		"requests_per_min":  reqPerMin,
		"blocked_per_min":   blockedPerMin,
		"traffic_60min":     traffic,
		"top_ips":           topIPs,
		"top_paths":         topPaths,
		"top_rules":         topRules,
		"status_codes":      statusCodes,
		"requests_per_site": perSite,
		"generated_at":      now.Format(time.RFC3339),
	})
}

// Prometheus handles GET /api/v1/metrics/prometheus
// Returns current metrics in Prometheus text exposition format (v0.0.4).
func (h *analyticsHandler) Prometheus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()
	since24h := now.Add(-24 * time.Hour)

	totalAll, _ := h.store.CountRequestLogs(ctx, database.RequestLogFilter{Limit: 1})
	blockedAll, _ := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		Blocked: boolPtr(true), Limit: 1,
	})
	total24h, _ := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		From: &since24h, Limit: 1,
	})
	blocked24h, _ := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		From: &since24h, Blocked: boolPtr(true), Limit: 1,
	})

	var reqPerMin, blockedPerMin int64
	if h.agg != nil {
		reqPerMin, blockedPerMin = h.agg.LastMinute()
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP metalwaf_requests_total Total HTTP requests processed all time\n")
	fmt.Fprintf(w, "# TYPE metalwaf_requests_total counter\n")
	fmt.Fprintf(w, "metalwaf_requests_total %d\n", totalAll)
	fmt.Fprintf(w, "# HELP metalwaf_requests_blocked_total Total blocked HTTP requests all time\n")
	fmt.Fprintf(w, "# TYPE metalwaf_requests_blocked_total counter\n")
	fmt.Fprintf(w, "metalwaf_requests_blocked_total %d\n", blockedAll)
	fmt.Fprintf(w, "# HELP metalwaf_requests_last_24h HTTP requests in the last 24 hours\n")
	fmt.Fprintf(w, "# TYPE metalwaf_requests_last_24h gauge\n")
	fmt.Fprintf(w, "metalwaf_requests_last_24h %d\n", total24h)
	fmt.Fprintf(w, "# HELP metalwaf_blocked_last_24h Blocked HTTP requests in the last 24 hours\n")
	fmt.Fprintf(w, "# TYPE metalwaf_blocked_last_24h gauge\n")
	fmt.Fprintf(w, "metalwaf_blocked_last_24h %d\n", blocked24h)
	fmt.Fprintf(w, "# HELP metalwaf_requests_per_minute HTTP requests in the last completed minute\n")
	fmt.Fprintf(w, "# TYPE metalwaf_requests_per_minute gauge\n")
	fmt.Fprintf(w, "metalwaf_requests_per_minute %d\n", reqPerMin)
	fmt.Fprintf(w, "# HELP metalwaf_blocked_per_minute Blocked HTTP requests in the last completed minute\n")
	fmt.Fprintf(w, "# TYPE metalwaf_blocked_per_minute gauge\n")
	fmt.Fprintf(w, "metalwaf_blocked_per_minute %d\n", blockedPerMin)
}

// defaultBlockThreshold is the blocked-requests-per-minute threshold used
// when no alert_block_threshold setting has been configured.
const defaultBlockThreshold = 20

// Alerts handles GET /api/v1/alerts
// Returns a list of currently active alerts based on real-time thresholds.
// The alert_block_threshold setting (default 20) controls when a
// "high_block_rate" alert is raised.
func (h *analyticsHandler) Alerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	threshold := int64(defaultBlockThreshold)
	if s, err := h.store.GetSetting(ctx, "alert_block_threshold"); err == nil && s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			threshold = n
		}
	}

	type alert struct {
		Type        string `json:"type"`
		Severity    string `json:"severity"`
		Message     string `json:"message"`
		Value       int64  `json:"value"`
		Threshold   int64  `json:"threshold"`
		TriggeredAt string `json:"triggered_at"`
	}

	alerts := make([]alert, 0)

	if h.agg != nil {
		if blocked := h.agg.BlockedLastMinute(); blocked > threshold {
			alerts = append(alerts, alert{
				Type:        "high_block_rate",
				Severity:    "warning",
				Message:     fmt.Sprintf("%d requests blocked in the last minute (threshold: %d)", blocked, threshold),
				Value:       blocked,
				Threshold:   threshold,
				TriggeredAt: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	respond(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func boolPtr(b bool) *bool { return &b }
