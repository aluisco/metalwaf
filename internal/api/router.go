package api

import (
	"context"
	"net/http"

	"github.com/metalwaf/metalwaf/internal/analytics"
	"github.com/metalwaf/metalwaf/internal/auth"
	"github.com/metalwaf/metalwaf/internal/database"
	"github.com/metalwaf/metalwaf/internal/waf"
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
	MasterKey   []byte                // AES-256-GCM key for private key encryption at rest
	Aggregator  *analytics.Aggregator // optional; nil disables real-time metrics
	WAFEngine   *waf.Engine           // optional; nil disables built-in rule endpoints
}

// NewRouter builds and returns the complete /api/v1 handler.
// All routes are registered on a new ServeMux (Go 1.22+ method+path patterns).
// A security-headers middleware wraps the entire mux.
func NewRouter(opts Options) http.Handler {
	mux := http.NewServeMux()

	authH := auth.NewHandler(opts.Store, opts.Issuer)
	sitesH := &sitesHandler{store: opts.Store, reload: opts.ProxyReload}
	rulesH := &rulesHandler{store: opts.Store, reload: opts.WAFReload, engine: opts.WAFEngine}
	certsH := &certsHandler{store: opts.Store, masterKey: opts.MasterKey, reload: opts.CertReload}
	analyticsH := &analyticsHandler{store: opts.Store, agg: opts.Aggregator}
	settingsH := &settingsHandler{store: opts.Store}
	profileH := &profileHandler{store: opts.Store}
	usersH := &usersHandler{store: opts.Store}
	ipListH := &ipListHandler{store: opts.Store, reload: opts.ProxyReload}

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

	// ── Users (admin only) ───────────────────────────────────────────────────
	mux.Handle("GET /api/v1/users",
		iss.RequireAdmin(http.HandlerFunc(usersH.List)))
	mux.Handle("POST /api/v1/users",
		iss.RequireAdmin(http.HandlerFunc(usersH.Create)))
	mux.Handle("GET /api/v1/users/{id}",
		iss.RequireAdmin(http.HandlerFunc(usersH.Get)))
	mux.Handle("PUT /api/v1/users/{id}",
		iss.RequireAdmin(http.HandlerFunc(usersH.Update)))
	mux.Handle("DELETE /api/v1/users/{id}",
		iss.RequireAdmin(http.HandlerFunc(usersH.Delete)))
	mux.Handle("POST /api/v1/users/{id}/revoke-sessions",
		iss.RequireAdmin(http.HandlerFunc(usersH.RevokeSessions)))

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
	// Static sub-paths must be registered before the {id} wildcard.
	mux.Handle("GET /api/v1/rules/categories",
		iss.RequireAuth(http.HandlerFunc(rulesH.Categories)))
	mux.Handle("GET /api/v1/rules/builtin",
		iss.RequireAuth(http.HandlerFunc(rulesH.Builtin)))
	mux.Handle("GET /api/v1/rules/export",
		iss.RequireAdmin(http.HandlerFunc(rulesH.Export)))
	mux.Handle("POST /api/v1/rules/import",
		iss.RequireAdmin(http.HandlerFunc(rulesH.Import)))
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
	// Prometheus scrape endpoint — registered before the /{key} wildcard to
	// avoid ambiguity. Uses the same auth guard as the JSON metrics endpoint.
	mux.Handle("GET /api/v1/metrics/prometheus",
		iss.RequireAuth(http.HandlerFunc(analyticsH.Prometheus)))
	mux.Handle("GET /api/v1/alerts",
		iss.RequireAuth(http.HandlerFunc(analyticsH.Alerts)))

	// ── Settings (admin only) ─────────────────────────────────────────────────
	mux.Handle("GET /api/v1/settings",
		iss.RequireAdmin(http.HandlerFunc(settingsH.GetAll)))
	mux.Handle("PUT /api/v1/settings/{key}",
		iss.RequireAdmin(http.HandlerFunc(settingsH.Set)))

	// ── IP Lists (admin only) ─────────────────────────────────────────────────
	mux.Handle("GET /api/v1/ip-lists",
		iss.RequireAdmin(http.HandlerFunc(ipListH.List)))
	mux.Handle("POST /api/v1/ip-lists",
		iss.RequireAdmin(http.HandlerFunc(ipListH.Create)))
	mux.Handle("DELETE /api/v1/ip-lists/{id}",
		iss.RequireAdmin(http.HandlerFunc(ipListH.Delete)))

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
