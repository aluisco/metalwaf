package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/metalwaf/metalwaf/internal/database"
)

type analyticsHandler struct {
	store database.Store
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
// Returns aggregate request counts for the last 24 h and all time.
func (h *analyticsHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()
	since24h := now.Add(-24 * time.Hour)

	// All time
	totalAll, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{Limit: 1})
	if err != nil {
		slog.Error("api: metrics count all", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	blockedAll, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		Blocked: boolPtr(true),
		Limit:   1,
	})
	if err != nil {
		slog.Error("api: metrics count blocked all", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Last 24 hours
	total24h, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		From:  &since24h,
		Limit: 1,
	})
	if err != nil {
		slog.Error("api: metrics count 24h", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	blocked24h, err := h.store.CountRequestLogs(ctx, database.RequestLogFilter{
		From:    &since24h,
		Blocked: boolPtr(true),
		Limit:   1,
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

	respond(w, http.StatusOK, map[string]any{
		"requests_total": totalAll,
		"requests_24h":   total24h,
		"blocked_total":  blockedAll,
		"blocked_24h":    blocked24h,
		"block_rate_24h": blockRate24h,
		"generated_at":   now.Format(time.RFC3339),
	})
}

func boolPtr(b bool) *bool { return &b }
