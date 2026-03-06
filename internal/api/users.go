package api

import (
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/metalwaf/metalwaf/internal/auth"
	"github.com/metalwaf/metalwaf/internal/database"
)

type usersHandler struct {
	store database.Store
}

// List handles GET /api/v1/users — returns all users (admin only).
func (h *usersHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		slog.Error("api: list users", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	resp := make([]userResponse, len(users))
	for i, u := range users {
		resp[i] = toUserResp(u)
	}
	respond(w, http.StatusOK, resp)
}

type createUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // "admin" | "viewer"
}

// Create handles POST /api/v1/users — creates a new user (admin only).
func (h *usersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decode(r, &req, 2048); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if req.Role != "admin" && req.Role != "viewer" {
		req.Role = "viewer"
	}
	if err := validateNewPassword(req.Password); err != nil {
		respondError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	// Check for duplicate username.
	existing, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		slog.Error("api: create user lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if existing != nil {
		respondError(w, http.StatusConflict, "username already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("api: hashing password for new user", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	u := &database.User{
		ID:           uuid.NewString(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         req.Role,
	}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		slog.Error("api: create user", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	slog.Info("api: user created", "username", u.Username, "role", u.Role)
	respond(w, http.StatusCreated, toUserResp(u))
}

// Get handles GET /api/v1/users/{id} — returns a single user (admin only).
func (h *usersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := h.store.GetUserByID(r.Context(), id)
	if err != nil {
		slog.Error("api: get user", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if u == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}
	respond(w, http.StatusOK, toUserResp(u))
}

type updateUserRequest struct {
	Email    string `json:"email"`
	Role     string `json:"role"`     // optional; "admin" | "viewer"
	Password string `json:"password"` // optional; if non-empty, forces a reset
}

// Update handles PUT /api/v1/users/{id} — updates email, role, optionally resets
// password. Admins cannot demote themselves.
func (h *usersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateUserRequest
	if err := decode(r, &req, 2048); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	u, err := h.store.GetUserByID(r.Context(), id)
	if err != nil {
		slog.Error("api: update user lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if u == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	// Prevent an admin from demoting themselves.
	claims := auth.ClaimsFromCtx(r.Context())
	if claims != nil && claims.UserID == id && req.Role == "viewer" {
		respondError(w, http.StatusBadRequest, "cannot demote your own admin account")
		return
	}

	if req.Email != "" {
		u.Email = req.Email
	}
	if req.Role == "admin" || req.Role == "viewer" {
		u.Role = req.Role
	}

	if req.Password != "" {
		if err := validateNewPassword(req.Password); err != nil {
			respondError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		u.PasswordHash = string(hash)
		// Revoke all sessions after forced password reset.
		_ = h.store.DeleteSessionsByUserID(r.Context(), u.ID)
	}

	if err := h.store.UpdateUser(r.Context(), u); err != nil {
		slog.Error("api: update user", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	slog.Info("api: user updated", "user_id", id)
	respond(w, http.StatusOK, toUserResp(u))
}

// Delete handles DELETE /api/v1/users/{id} — deletes a user. Admins cannot
// delete themselves.
func (h *usersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	claims := auth.ClaimsFromCtx(r.Context())
	if claims != nil && claims.UserID == id {
		respondError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	u, err := h.store.GetUserByID(r.Context(), id)
	if err != nil {
		slog.Error("api: delete user lookup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if u == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	// Revoke sessions before deletion.
	_ = h.store.DeleteSessionsByUserID(r.Context(), id)

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		slog.Error("api: delete user", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	slog.Info("api: user deleted", "user_id", id)
	w.WriteHeader(http.StatusNoContent)
}

// RevokeSessions handles POST /api/v1/users/{id}/revoke-sessions — forces all
// sessions for a user to expire immediately.
func (h *usersHandler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.DeleteSessionsByUserID(r.Context(), id); err != nil {
		slog.Error("api: revoke sessions", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	slog.Info("api: sessions revoked by admin", "target_user_id", id)
	w.WriteHeader(http.StatusNoContent)
}
