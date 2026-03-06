package api

import (
	"context"
	"net/http"

	"github.com/metalwaf/metalwaf/internal/auth"
	"github.com/metalwaf/metalwaf/internal/database"
)

// Options configures the API router. ProxyReload, WAFReload and CertReload are
// called after mutations that require the respective subsystem to reload its
// config. Any can be nil (no-op, useful in tests).
type Options struct {
	Store       database.Store
	Issuer      *auth.Issuer
	ProxyReload func(ctx context.Context) error
	WAFReload   func(ctx context.Context) error
	CertReload  func(ctx context.Context) error
	MasterKey   []byte // AES-256-GCM key for private key encryption at rest
}

// NewRouter builds and returns the complete /api/v1 handler.
// All routes are registered on a new ServeMux (Go 1.22+ method+path patterns).
// A security-headers middleware wraps the entire mux.
func NewRouter(opts Options) http.Handler {
	mux := http.NewServeMux()

	authH := auth.NewHandler(opts.Store, opts.Issuer)
	sitesH := &sitesHandler{store: opts.Store, reload: opts.ProxyReload}
	rulesH := &rulesHandler{store: opts.Store, reload: opts.WAFReload}
	certsH := &certsHandler{store: opts.Store, masterKey: opts.MasterKey, reload: opts.CertReload}
	analyticsH := &analyticsHandler{store: opts.Store}
	settingsH := &settingsHandler{store: opts.Store}
	profileH := &profileHandler{store: opts.Store}

	iss := opts.Issuer

	// ── Auth (public endpoints) ──────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/auth/login", authH.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authH.Refresh)

	// ── Auth (requires access token) ────────────────────────────────────────
	mux.Handle("POST /api/v1/auth/logout",
		iss.RequireAuth(http.HandlerFunc(authH.Logout)))
	mux.Handle("POST /api/v1/auth/logout-all",
		iss.RequireAuth(http.HandlerFunc(authH.LogoutAll)))
	mux.Handle("POST /api/v1/auth/totp/setup",
		iss.RequireAuth(http.HandlerFunc(authH.TOTPSetup)))
	mux.Handle("POST /api/v1/auth/totp/verify",
		iss.RequireAuth(http.HandlerFunc(authH.TOTPVerify)))
	mux.Handle("POST /api/v1/auth/totp/disable",
		iss.RequireAuth(http.HandlerFunc(authH.TOTPDisable)))

	// ── Profile (own user, any role) ─────────────────────────────────────────
	mux.Handle("GET /api/v1/profile",
		iss.RequireAuth(http.HandlerFunc(profileH.Get)))
	mux.Handle("PUT /api/v1/profile/password",
		iss.RequireAuth(http.HandlerFunc(profileH.ChangePassword)))

	// ── Sites (read: any role; write: admin) ─────────────────────────────────
	mux.Handle("GET /api/v1/sites",
		iss.RequireAuth(http.HandlerFunc(sitesH.List)))
	mux.Handle("POST /api/v1/sites",
		iss.RequireAdmin(http.HandlerFunc(sitesH.Create)))
	mux.Handle("GET /api/v1/sites/{id}",
		iss.RequireAuth(http.HandlerFunc(sitesH.Get)))
	mux.Handle("PUT /api/v1/sites/{id}",
		iss.RequireAdmin(http.HandlerFunc(sitesH.Update)))
	mux.Handle("DELETE /api/v1/sites/{id}",
		iss.RequireAdmin(http.HandlerFunc(sitesH.Delete)))

	// ── Upstreams (nested under sites) ───────────────────────────────────────
	mux.Handle("GET /api/v1/sites/{id}/upstreams",
		iss.RequireAuth(http.HandlerFunc(sitesH.ListUpstreams)))
	mux.Handle("POST /api/v1/sites/{id}/upstreams",
		iss.RequireAdmin(http.HandlerFunc(sitesH.CreateUpstream)))
	mux.Handle("PUT /api/v1/sites/{id}/upstreams/{uid}",
		iss.RequireAdmin(http.HandlerFunc(sitesH.UpdateUpstream)))
	mux.Handle("DELETE /api/v1/sites/{id}/upstreams/{uid}",
		iss.RequireAdmin(http.HandlerFunc(sitesH.DeleteUpstream)))

	// ── WAF Rules (read: any role; write: admin) ──────────────────────────────
	mux.Handle("GET /api/v1/rules",
		iss.RequireAuth(http.HandlerFunc(rulesH.List)))
	mux.Handle("POST /api/v1/rules",
		iss.RequireAdmin(http.HandlerFunc(rulesH.Create)))
	mux.Handle("GET /api/v1/rules/{id}",
		iss.RequireAuth(http.HandlerFunc(rulesH.Get)))
	mux.Handle("PUT /api/v1/rules/{id}",
		iss.RequireAdmin(http.HandlerFunc(rulesH.Update)))
	mux.Handle("DELETE /api/v1/rules/{id}",
		iss.RequireAdmin(http.HandlerFunc(rulesH.Delete)))

	// ── Analytics (read-only, any role) ──────────────────────────────────────
	mux.Handle("GET /api/v1/logs",
		iss.RequireAuth(http.HandlerFunc(analyticsH.ListLogs)))
	mux.Handle("GET /api/v1/metrics",
		iss.RequireAuth(http.HandlerFunc(analyticsH.Metrics)))

	// ── Settings (admin only) ─────────────────────────────────────────────────
	mux.Handle("GET /api/v1/settings",
		iss.RequireAdmin(http.HandlerFunc(settingsH.GetAll)))
	mux.Handle("PUT /api/v1/settings/{key}",
		iss.RequireAdmin(http.HandlerFunc(settingsH.Set)))

	// ── Certificates (read: any role; write: admin) ──────────────────────────
	// POST /letsencrypt must be registered before /{id} so it isn't swallowed
	// by the {id} wildcard on paths like "letsencrypt".
	mux.Handle("POST /api/v1/certificates/letsencrypt",
		iss.RequireAdmin(http.HandlerFunc(certsH.RequestACME)))
	mux.Handle("GET /api/v1/certificates",
		iss.RequireAuth(http.HandlerFunc(certsH.List)))
	mux.Handle("POST /api/v1/certificates",
		iss.RequireAdmin(http.HandlerFunc(certsH.Create)))
	mux.Handle("GET /api/v1/certificates/{id}",
		iss.RequireAuth(http.HandlerFunc(certsH.Get)))
	mux.Handle("DELETE /api/v1/certificates/{id}",
		iss.RequireAdmin(http.HandlerFunc(certsH.Delete)))

	return securityHeaders(mux)
}

// securityHeaders adds defensive HTTP response headers to all API responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}
