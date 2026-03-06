package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/metalwaf/metalwaf/internal/database"
)

// protectedKeys are settings that must NOT be modifiable through the API
// to prevent privilege escalation or system compromise.
var protectedKeys = map[string]bool{
	"license_key": true,
}

type settingsHandler struct {
	store database.Store
}

// GetAll handles GET /api/v1/settings
// Returns all settings except protected keys.
func (h *settingsHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	all, err := h.store.GetAllSettings(r.Context())
	if err != nil {
		slog.Error("api: get settings", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	// Strip protected keys before returning.
	for k := range protectedKeys {
		delete(all, k)
	}
	respond(w, http.StatusOK, all)
}

type setSettingRequest struct {
	Value string `json:"value"`
}

// Set handles PUT /api/v1/settings/{key}
func (h *settingsHandler) Set(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := validateSettingKey(key); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if protectedKeys[key] {
		respondError(w, http.StatusForbidden,
			"this setting cannot be modified through the API")
		return
	}

	var req setSettingRequest
	if err := decode(r, &req, 4096); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.store.SetSetting(r.Context(), key, req.Value); err != nil {
		slog.Error("api: set setting", "key", key, "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	respond(w, http.StatusOK, map[string]string{key: req.Value})
}

func validateSettingKey(key string) error {
	if key == "" {
		return errors.New("setting key is required")
	}
	if len(key) > 128 {
		return errors.New("setting key must be 128 characters or fewer")
	}
	// Allow only alphanumeric, underscore, and dash to prevent injection
	// via key names in future SQL concatenation paths.
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-') {
			return errors.New("setting key may only contain letters, digits, underscores, and hyphens")
		}
	}
	return nil
}

// validateSettingValue is intentionally permissive — values are stored as
// text and the application interprets them. The key name determines semantics.
func validateSettingValue(v string) error {
	if len(strings.TrimSpace(v)) == 0 {
		return errors.New("value must not be empty")
	}
	return nil
}
