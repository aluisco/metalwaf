package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type ctxKey string

const ctxClaims ctxKey = "auth_claims"

// RequireAuth is an HTTP middleware that validates the Bearer access token
// and injects the claims into the request context on success.
// Returns 401 Unauthorized with a JSON error body on failure.
func (iss *Issuer) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := extractBearer(r)
		if raw == "" {
			writeAuthJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "missing Authorization: Bearer <token> header"})
			return
		}
		claims, err := iss.ValidateAccessToken(raw)
		if err != nil {
			writeAuthJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "token invalid or expired"})
			return
		}
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), ctxClaims, claims),
		))
	})
}

// RequireAdmin wraps RequireAuth and additionally enforces the admin role.
// Returns 403 Forbidden if the authenticated user is not an admin.
func (iss *Issuer) RequireAdmin(next http.Handler) http.Handler {
	return iss.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := ClaimsFromCtx(r.Context()); c == nil || c.Role != "admin" {
			writeAuthJSON(w, http.StatusForbidden,
				map[string]string{"error": "admin role required"})
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// ClaimsFromCtx retrieves validated JWT claims from the request context.
// Returns nil if the request has not passed through RequireAuth.
func ClaimsFromCtx(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxClaims).(*Claims)
	return c
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

// writeAuthJSON is a minimal JSON writer used internally by auth middleware.
// The api package has its own respond helpers; this one exists to avoid a
// circular import between auth and api.
func writeAuthJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
