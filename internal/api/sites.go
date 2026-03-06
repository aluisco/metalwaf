package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/metalwaf/metalwaf/internal/database"
)

type sitesHandler struct {
	store  database.Store
	reload func(ctx context.Context) error // called after mutations
}

// ─── Response DTOs ────────────────────────────────────────────────────────────

// siteResponse omits internal fields from the DB model.
type siteResponse struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Domain         string  `json:"domain"`
	WAFMode        string  `json:"waf_mode"`
	HTTPSOnly      bool    `json:"https_only"`
	Enabled        bool    `json:"enabled"`
	RateLimitRPS   float64 `json:"rate_limit_rps"`
	RateLimitBurst int     `json:"rate_limit_burst"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

type upstreamResponse struct {
	ID        string `json:"id"`
	SiteID    string `json:"site_id"`
	URL       string `json:"url"`
	Weight    int    `json:"weight"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toSiteResp(s *database.Site) siteResponse {
	return siteResponse{
		ID:             s.ID,
		Name:           s.Name,
		Domain:         s.Domain,
		WAFMode:        s.WAFMode,
		HTTPSOnly:      s.HTTPSOnly,
		Enabled:        s.Enabled,
		RateLimitRPS:   s.RateLimitRPS,
		RateLimitBurst: s.RateLimitBurst,
		CreatedAt:      s.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      s.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func toUpstreamResp(u *database.Upstream) upstreamResponse {
	return upstreamResponse{
		ID:        u.ID,
		SiteID:    u.SiteID,
		URL:       u.URL,
		Weight:    u.Weight,
		Enabled:   u.Enabled,
		CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// ─── Sites CRUD ───────────────────────────────────────────────────────────────

func (h *sitesHandler) List(w http.ResponseWriter, r *http.Request) {
	sites, err := h.store.ListSites(r.Context())
	if err != nil {
		slog.Error("api: list sites", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	resp := make([]siteResponse, 0, len(sites))
	for _, s := range sites {
		resp = append(resp, toSiteResp(s))
	}
	respond(w, http.StatusOK, resp)
}

type createSiteRequest struct {
	Name           string  `json:"name"`
	Domain         string  `json:"domain"`
	WAFMode        string  `json:"waf_mode"`
	HTTPSOnly      bool    `json:"https_only"`
	Enabled        *bool   `json:"enabled"`
	RateLimitRPS   float64 `json:"rate_limit_rps"`
	RateLimitBurst int     `json:"rate_limit_burst"`
}

func (h *sitesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createSiteRequest
	if err := decode(r, &req, 4096); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateSiteInput(req.Name, req.Domain, req.WAFMode); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	site := &database.Site{
		Name:           strings.TrimSpace(req.Name),
		Domain:         strings.ToLower(strings.TrimSpace(req.Domain)),
		WAFMode:        req.WAFMode,
		HTTPSOnly:      req.HTTPSOnly,
		Enabled:        enabled,
		RateLimitRPS:   req.RateLimitRPS,
		RateLimitBurst: req.RateLimitBurst,
	}
	if err := h.store.CreateSite(r.Context(), site); err != nil {
		slog.Error("api: create site", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r.Context())
	respondCreated(w, toSiteResp(site))
}

func (h *sitesHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid site ID")
		return
	}
	site, err := h.store.GetSiteByID(r.Context(), id)
	if err != nil {
		slog.Error("api: get site", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if site == nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}
	respond(w, http.StatusOK, toSiteResp(site))
}

type updateSiteRequest struct {
	Name           *string  `json:"name"`
	Domain         *string  `json:"domain"`
	WAFMode        *string  `json:"waf_mode"`
	HTTPSOnly      *bool    `json:"https_only"`
	Enabled        *bool    `json:"enabled"`
	RateLimitRPS   *float64 `json:"rate_limit_rps"`
	RateLimitBurst *int     `json:"rate_limit_burst"`
}

func (h *sitesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid site ID")
		return
	}
	site, err := h.store.GetSiteByID(r.Context(), id)
	if err != nil {
		slog.Error("api: update site lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if site == nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}

	var req updateSiteRequest
	if err := decode(r, &req, 4096); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != nil {
		site.Name = strings.TrimSpace(*req.Name)
	}
	if req.Domain != nil {
		site.Domain = strings.ToLower(strings.TrimSpace(*req.Domain))
	}
	if req.WAFMode != nil {
		site.WAFMode = *req.WAFMode
	}
	if req.HTTPSOnly != nil {
		site.HTTPSOnly = *req.HTTPSOnly
	}
	if req.Enabled != nil {
		site.Enabled = *req.Enabled
	}
	if req.RateLimitRPS != nil {
		site.RateLimitRPS = *req.RateLimitRPS
	}
	if req.RateLimitBurst != nil {
		site.RateLimitBurst = *req.RateLimitBurst
	}

	if err := validateSiteInput(site.Name, site.Domain, site.WAFMode); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := h.store.UpdateSite(r.Context(), site); err != nil {
		slog.Error("api: update site", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r.Context())
	respond(w, http.StatusOK, toSiteResp(site))
}

func (h *sitesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid site ID")
		return
	}
	if err := h.store.DeleteSite(r.Context(), id); err != nil {
		slog.Error("api: delete site", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	h.triggerReload(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// ─── Upstreams CRUD ───────────────────────────────────────────────────────────

func (h *sitesHandler) ListUpstreams(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid site ID")
		return
	}
	ups, err := h.store.ListUpstreamsBySite(r.Context(), id)
	if err != nil {
		slog.Error("api: list upstreams", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	resp := make([]upstreamResponse, 0, len(ups))
	for _, u := range ups {
		resp = append(resp, toUpstreamResp(u))
	}
	respond(w, http.StatusOK, resp)
}

type createUpstreamRequest struct {
	URL     string `json:"url"`
	Weight  int    `json:"weight"`
	Enabled *bool  `json:"enabled"`
}

func (h *sitesHandler) CreateUpstream(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	if !validUUID(siteID) {
		respondError(w, http.StatusBadRequest, "invalid site ID")
		return
	}
	// Verify site exists.
	site, err := h.store.GetSiteByID(r.Context(), siteID)
	if err != nil || site == nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}

	var req createUpstreamRequest
	if err := decode(r, &req, 2048); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateUpstreamURL(req.URL); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	weight := req.Weight
	if weight <= 0 {
		weight = 1
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	upstream := &database.Upstream{
		SiteID:  siteID,
		URL:     strings.TrimRight(req.URL, "/"),
		Weight:  weight,
		Enabled: enabled,
	}
	if err := h.store.CreateUpstream(r.Context(), upstream); err != nil {
		slog.Error("api: create upstream", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r.Context())
	respondCreated(w, toUpstreamResp(upstream))
}

type updateUpstreamRequest struct {
	URL     *string `json:"url"`
	Weight  *int    `json:"weight"`
	Enabled *bool   `json:"enabled"`
}

func (h *sitesHandler) UpdateUpstream(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !validUUID(uid) {
		respondError(w, http.StatusBadRequest, "invalid upstream ID")
		return
	}
	upstream, err := h.store.GetUpstreamByID(r.Context(), uid)
	if err != nil {
		slog.Error("api: update upstream lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if upstream == nil {
		respondError(w, http.StatusNotFound, "upstream not found")
		return
	}

	var req updateUpstreamRequest
	if err := decode(r, &req, 2048); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URL != nil {
		if err := validateUpstreamURL(*req.URL); err != nil {
			respondError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		upstream.URL = strings.TrimRight(*req.URL, "/")
	}
	if req.Weight != nil {
		if *req.Weight <= 0 {
			respondError(w, http.StatusUnprocessableEntity, "weight must be > 0")
			return
		}
		upstream.Weight = *req.Weight
	}
	if req.Enabled != nil {
		upstream.Enabled = *req.Enabled
	}

	if err := h.store.UpdateUpstream(r.Context(), upstream); err != nil {
		slog.Error("api: update upstream", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r.Context())
	respond(w, http.StatusOK, toUpstreamResp(upstream))
}

func (h *sitesHandler) DeleteUpstream(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !validUUID(uid) {
		respondError(w, http.StatusBadRequest, "invalid upstream ID")
		return
	}
	if err := h.store.DeleteUpstream(r.Context(), uid); err != nil {
		slog.Error("api: delete upstream", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	h.triggerReload(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (h *sitesHandler) triggerReload(ctx context.Context) {
	if h.reload == nil {
		return
	}
	if err := h.reload(ctx); err != nil {
		slog.Warn("api: proxy reload after mutation", "error", err)
	}
}

func validateSiteInput(name, domain, wafMode string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name is required")
	}
	if len(name) > 100 {
		return errors.New("name must be 100 characters or fewer")
	}
	if strings.TrimSpace(domain) == "" {
		return errors.New("domain is required")
	}
	if len(domain) > 253 {
		return errors.New("domain must be 253 characters or fewer")
	}
	switch wafMode {
	case "block", "detect", "off":
	default:
		return errors.New(`waf_mode must be "block", "detect", or "off"`)
	}
	return nil
}

// validateUpstreamURL checks that a URL is a well-formed http/https URL
// without embedded credentials (prevents SSRF via scheme confusion and
// credential leakage in access logs).
func validateUpstreamURL(raw string) error {
	if raw == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("url scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("url must include a host")
	}
	if u.User != nil {
		return errors.New("url must not include credentials (user:pass@host is not allowed)")
	}
	return nil
}

func validUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func parseBoolParam(v string) (*bool, error) {
	if v == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, errors.New("must be true or false")
	}
	return &b, nil
}
