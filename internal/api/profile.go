package api

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/metalwaf/metalwaf/internal/auth"
	"github.com/metalwaf/metalwaf/internal/database"
)

type profileHandler struct {
	store database.Store
}

// userResponse is a safe user representation that never exposes
// password hashes or raw TOTP secrets.
type userResponse struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toUserResp(u *database.User) userResponse {
	return userResponse{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Role:        u.Role,
		TOTPEnabled: u.TOTPEnabled,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// Get handles GET /api/v1/profile — returns the authenticated user's profile.
func (h *profileHandler) Get(w http.ResponseWriter, r *http.Request) {
	c := auth.ClaimsFromCtx(r.Context())
	if c == nil {
		respondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	user, err := h.store.GetUserByID(r.Context(), c.UserID)
	if err != nil {
		slog.Error("api: get profile", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if user == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}
	respond(w, http.StatusOK, toUserResp(user))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword handles PUT /api/v1/profile/password.
// Requires the current password to prevent unauthorised password changes
// if an access token is compromised.
func (h *profileHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	c := auth.ClaimsFromCtx(r.Context())
	if c == nil {
		respondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req changePasswordRequest
	if err := decode(r, &req, 1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if err := validateNewPassword(req.NewPassword); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	user, err := h.store.GetUserByID(r.Context(), c.UserID)
	if err != nil || user == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	// Verify current password before allowing the change.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		respondError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("api: hashing new password", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	user.PasswordHash = string(newHash)
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		slog.Error("api: updating password", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Revoke all existing sessions for this user so old tokens can't be reused.
	if err := h.store.DeleteSessionsByUserID(r.Context(), user.ID); err != nil {
		slog.Warn("api: revoking sessions after password change", "error", err)
	}

	slog.Info("api: password changed", "user_id", user.ID)
	respond(w, http.StatusOK, map[string]string{
		"message": "password updated — all existing sessions have been revoked",
	})
}

type updateProfileRequest struct {
	Email string `json:"email"`
}

// Update handles PUT /api/v1/profile — lets any authenticated user update their own email.
func (h *profileHandler) Update(w http.ResponseWriter, r *http.Request) {
	c := auth.ClaimsFromCtx(r.Context())
	if c == nil {
		respondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req updateProfileRequest
	if err := decode(r, &req, 1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, err := h.store.GetUserByID(r.Context(), c.UserID)
	if err != nil || user == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		slog.Error("api: update profile", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	slog.Info("api: profile updated", "user_id", user.ID)
	respond(w, http.StatusOK, toUserResp(user))
}

func validateNewPassword(p string) error {
	if len(p) < 12 {
		return errors.New("new_password must be at least 12 characters")
	}
	if len(p) > 128 {
		return errors.New("new_password must be 128 characters or fewer")
	}
	return nil
}
