package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/metalwaf/metalwaf/internal/database"
)

type ipListHandler struct {
	store  database.Store
	reload func(ctx context.Context) error
}

// ipListResponse is the JSON shape returned to clients.
type ipListResponse struct {
	ID        string  `json:"id"`
	SiteID    *string `json:"site_id"`
	Type      string  `json:"type"`
	CIDR      string  `json:"cidr"`
	Comment   string  `json:"comment"`
	CreatedAt string  `json:"created_at"`
}

func toIPListResp(l *database.IPList) ipListResponse {
	return ipListResponse{
		ID:        l.ID,
		SiteID:    l.SiteID,
		Type:      l.Type,
		CIDR:      l.CIDR,
		Comment:   l.Comment,
		CreatedAt: l.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// List handles GET /api/v1/ip-lists
// Optional query params: ?type=allow|block  ?site_id=<uuid>
func (h *ipListHandler) List(w http.ResponseWriter, r *http.Request) {
	var siteID *string
	var listType *string

	if s := r.URL.Query().Get("site_id"); s != "" {
		if !validUUID(s) {
			respondError(w, http.StatusBadRequest, "invalid site_id")
			return
		}
		siteID = &s
	}
	if t := r.URL.Query().Get("type"); t != "" {
		if t != "allow" && t != "block" {
			respondError(w, http.StatusBadRequest, "type must be allow or block")
			return
		}
		listType = &t
	}

	entries, err := h.store.ListIPLists(r.Context(), siteID, listType)
	if err != nil {
		slog.Error("api: list ip-lists", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	resp := make([]ipListResponse, 0, len(entries))
	for _, e := range entries {
		resp = append(resp, toIPListResp(e))
	}
	respond(w, http.StatusOK, resp)
}

type createIPListRequest struct {
	SiteID  *string `json:"site_id"`
	Type    string  `json:"type"`
	CIDR    string  `json:"cidr"`
	Comment string  `json:"comment"`
}

// Create handles POST /api/v1/ip-lists
func (h *ipListHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createIPListRequest
	if err := decode(r, &req, 4096); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Type = strings.TrimSpace(req.Type)
	req.CIDR = strings.TrimSpace(req.CIDR)

	if req.Type != "allow" && req.Type != "block" {
		respondError(w, http.StatusUnprocessableEntity, "type must be allow or block")
		return
	}
	if req.CIDR == "" {
		respondError(w, http.StatusUnprocessableEntity, "cidr is required")
		return
	}
	if !validCIDROrIP(req.CIDR) {
		respondError(w, http.StatusUnprocessableEntity, "cidr must be a valid IP or CIDR (e.g. 1.2.3.4 or 10.0.0.0/8)")
		return
	}
	if req.SiteID != nil && !validUUID(*req.SiteID) {
		respondError(w, http.StatusBadRequest, "invalid site_id")
		return
	}

	entry := &database.IPList{
		SiteID:  req.SiteID,
		Type:    req.Type,
		CIDR:    req.CIDR,
		Comment: strings.TrimSpace(req.Comment),
	}
	if err := h.store.CreateIPList(r.Context(), entry); err != nil {
		slog.Error("api: create ip-list", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r)
	respondCreated(w, toIPListResp(entry))
}

// Delete handles DELETE /api/v1/ip-lists/{id}
func (h *ipListHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid id")
		return
	}
	entry, err := h.store.GetIPListByID(r.Context(), id)
	if err != nil {
		slog.Error("api: delete ip-list lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if entry == nil {
		respondError(w, http.StatusNotFound, "ip-list entry not found")
		return
	}
	if err := h.store.DeleteIPList(r.Context(), id); err != nil {
		slog.Error("api: delete ip-list", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	h.triggerReload(r)
	w.WriteHeader(http.StatusNoContent)
}

// triggerReload fires the reload callback (if set) asynchronously so it never
// delays the HTTP response.
func (h *ipListHandler) triggerReload(r *http.Request) {
	if h.reload == nil {
		return
	}
	ctx := r.Context()
	go func() {
		if err := h.reload(ctx); err != nil {
			slog.Warn("api: ip-list reload failed", "error", err)
		}
	}()
}

// validCIDROrIP returns true if s is a valid CIDR block or a plain IP address.
func validCIDROrIP(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}
