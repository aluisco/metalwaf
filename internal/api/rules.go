package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/metalwaf/metalwaf/internal/database"
)

type rulesHandler struct {
	store  database.Store
	reload func(ctx context.Context) error // called after mutations
}

type ruleResponse struct {
	ID          string  `json:"id"`
	SiteID      *string `json:"site_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Field       string  `json:"field"`
	Operator    string  `json:"operator"`
	Value       string  `json:"value"`
	Action      string  `json:"action"`
	Score       int     `json:"score"`
	Enabled     bool    `json:"enabled"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

func toRuleResp(r *database.WAFRule) ruleResponse {
	return ruleResponse{
		ID:          r.ID,
		SiteID:      r.SiteID,
		Name:        r.Name,
		Description: r.Description,
		Field:       r.Field,
		Operator:    r.Operator,
		Value:       r.Value,
		Action:      r.Action,
		Score:       r.Score,
		Enabled:     r.Enabled,
		CreatedAt:   r.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   r.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// List handles GET /api/v1/rules
// Optional query param: site_id (UUID)
func (h *rulesHandler) List(w http.ResponseWriter, r *http.Request) {
	var siteID *string
	if sid := r.URL.Query().Get("site_id"); sid != "" {
		if !validUUID(sid) {
			respondError(w, http.StatusBadRequest, "invalid site_id")
			return
		}
		siteID = &sid
	}
	rules, err := h.store.ListWAFRules(r.Context(), siteID)
	if err != nil {
		slog.Error("api: list rules", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	resp := make([]ruleResponse, 0, len(rules))
	for _, ru := range rules {
		resp = append(resp, toRuleResp(ru))
	}
	respond(w, http.StatusOK, resp)
}

type createRuleRequest struct {
	SiteID      *string `json:"site_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Field       string  `json:"field"`
	Operator    string  `json:"operator"`
	Value       string  `json:"value"`
	Action      string  `json:"action"`
	Score       int     `json:"score"`
	Enabled     *bool   `json:"enabled"`
}

func (h *rulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRuleRequest
	if err := decode(r, &req, 8192); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateRuleInput(req.Name, req.Field, req.Operator, req.Action, req.Value, req.Score); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if req.SiteID != nil && !validUUID(*req.SiteID) {
		respondError(w, http.StatusUnprocessableEntity, "invalid site_id")
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &database.WAFRule{
		SiteID:      req.SiteID,
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		Field:       req.Field,
		Operator:    req.Operator,
		Value:       req.Value,
		Action:      req.Action,
		Score:       req.Score,
		Enabled:     enabled,
	}
	if err := h.store.CreateWAFRule(r.Context(), rule); err != nil {
		slog.Error("api: create rule", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r.Context())
	respondCreated(w, toRuleResp(rule))
}

func (h *rulesHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}
	rule, err := h.store.GetWAFRuleByID(r.Context(), id)
	if err != nil {
		slog.Error("api: get rule", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rule == nil {
		respondError(w, http.StatusNotFound, "rule not found")
		return
	}
	respond(w, http.StatusOK, toRuleResp(rule))
}

type updateRuleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Field       *string `json:"field"`
	Operator    *string `json:"operator"`
	Value       *string `json:"value"`
	Action      *string `json:"action"`
	Score       *int    `json:"score"`
	Enabled     *bool   `json:"enabled"`
}

func (h *rulesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}
	rule, err := h.store.GetWAFRuleByID(r.Context(), id)
	if err != nil {
		slog.Error("api: update rule lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rule == nil {
		respondError(w, http.StatusNotFound, "rule not found")
		return
	}

	var req updateRuleRequest
	if err := decode(r, &req, 8192); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != nil {
		rule.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		rule.Description = strings.TrimSpace(*req.Description)
	}
	if req.Field != nil {
		rule.Field = *req.Field
	}
	if req.Operator != nil {
		rule.Operator = *req.Operator
	}
	if req.Value != nil {
		rule.Value = *req.Value
	}
	if req.Action != nil {
		rule.Action = *req.Action
	}
	if req.Score != nil {
		rule.Score = *req.Score
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	if err := validateRuleInput(rule.Name, rule.Field, rule.Operator, rule.Action, rule.Value, rule.Score); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := h.store.UpdateWAFRule(r.Context(), rule); err != nil {
		slog.Error("api: update rule", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.triggerReload(r.Context())
	respond(w, http.StatusOK, toRuleResp(rule))
}

func (h *rulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(id) {
		respondError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}
	if err := h.store.DeleteWAFRule(r.Context(), id); err != nil {
		slog.Error("api: delete rule", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	h.triggerReload(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *rulesHandler) triggerReload(ctx context.Context) {
	if h.reload == nil {
		return
	}
	if err := h.reload(ctx); err != nil {
		slog.Warn("api: waf reload after rule mutation", "error", err)
	}
}

// ─── Validation ───────────────────────────────────────────────────────────────

var (
	validFields = map[string]bool{
		"uri": true, "query": true, "body": true,
		"header": true, "ip": true, "user_agent": true, "method": true,
	}
	validOperators = map[string]bool{
		"contains": true, "regex": true, "equals": true,
		"startswith": true, "endswith": true, "cidr": true,
	}
	validActions = map[string]bool{
		"block": true, "detect": true, "allow": true,
	}
)

func validateRuleInput(name, field, operator, action, value string, score int) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name is required")
	}
	if len(name) > 100 {
		return errors.New("name must be 100 characters or fewer")
	}
	if !validFields[field] {
		return errors.New("field must be one of: uri, query, body, header, ip, user_agent, method")
	}
	if !validOperators[operator] {
		return errors.New("operator must be one of: contains, regex, equals, startswith, endswith, cidr")
	}
	if !validActions[action] {
		return errors.New("action must be one of: block, detect, allow")
	}
	if strings.TrimSpace(value) == "" {
		return errors.New("value is required")
	}
	if len(value) > 4096 {
		return errors.New("value must be 4096 characters or fewer")
	}
	if score < 0 || score > 1000 {
		return errors.New("score must be between 0 and 1000")
	}
	return nil
}
