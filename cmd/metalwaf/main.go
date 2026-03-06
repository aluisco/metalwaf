package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"io/fs"

	"github.com/metalwaf/metalwaf/internal/api"
	"github.com/metalwaf/metalwaf/internal/auth"
	"github.com/metalwaf/metalwaf/internal/certificates"
	"github.com/metalwaf/metalwaf/internal/config"
	"github.com/metalwaf/metalwaf/internal/database"
	"github.com/metalwaf/metalwaf/internal/database/sqlite"
	"github.com/metalwaf/metalwaf/internal/frontend"
	"github.com/metalwaf/metalwaf/internal/license"
	"github.com/metalwaf/metalwaf/internal/proxy"
	"github.com/metalwaf/metalwaf/internal/waf"
)

const version = "0.1.0-lite"

const banner = `
  __  __      _        ___        ___    _    _____
 |  \/  | ___| |_ __ _| \ \      / / \  | |  |  ___|
 | |\/| |/ _ \ __/ _  | |\ \ /\ / / _ \ | |  | |_
 | |  | |  __/ || (_| | | \ V  V / ___ \| |__| _|
 |_|  |_|\___|\__\__,_|_|  \_/\_/_/   \_\____|_|

 Reverse Proxy + Web Application Firewall  v%s
 ─────────────────────────────────────────────────
`

func main() {
	var (
		configPath = flag.String("config", "configs/metalwaf.yaml", "Path to YAML config file")
		showVer    = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("MetalWAF %s\n", version)
		os.Exit(0)
	}

	fmt.Printf(banner, version)

	// ── Load configuration ──────────────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: loading config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid configuration: %v\n", err)
		os.Exit(1)
	}
	// ── Configure structured logger ─────────────────────────────────────────
	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
		logLevel = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler
	if cfg.Log.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))

	slog.Info("starting MetalWAF", "version", version)

	// ── Signal context ──────────────────────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// ── Initialize database store ───────────────────────────────────────────
	// The DB is opened before license validation because the license key is
	// stored in the settings table — the dashboard is the single place where
	// users manage their license key.
	//
	// Backend selection:
	//   database.dsn set   → PostgreSQL  (Phase 1b — not yet implemented)
	//   database.dsn empty → SQLite      (current default)
	if cfg.Database.DSN != "" {
		slog.Error("PostgreSQL backend is not yet implemented",
			"hint", "remove database.dsn from the config file or unset METALWAF_DB_DSN to use SQLite")
		os.Exit(1)
	}
	var store database.Store
	store, err = sqlite.New(ctx, cfg.Database.SQLitePath)
	if err != nil {
		slog.Error("failed to open SQLite store", "path", cfg.Database.SQLitePath, "error", err)
		os.Exit(1)
	}
	slog.Info("store ready", "backend", "sqlite", "path", cfg.Database.SQLitePath)
	defer store.Close()

	// ── Bootstrap license key from environment variable ─────────────────────
	// METALWAF_LICENSE_KEY is a one-time bootstrap helper for Docker/k8s
	// deployments where the UI is not available on first run. If set, the key
	// is persisted to the database so subsequent restarts don't need it.
	// The env var is intentionally NOT read at every startup — the DB is the
	// single source of truth after the first boot.
	if bootstrapKey := os.Getenv("METALWAF_LICENSE_KEY"); bootstrapKey != "" {
		if existing, _ := store.GetSetting(ctx, "license_key"); existing == "" {
			if werr := store.SetSetting(ctx, "license_key", bootstrapKey); werr != nil {
				slog.Warn("license: could not persist bootstrap key to database", "error", werr)
			} else {
				slog.Info("license: key saved to database from METALWAF_LICENSE_KEY (bootstrap)")
			}
		}
	}

	// ── License validation ──────────────────────────────────────────────────
	// Read the key from the settings table — single source of truth.
	// The local encrypted cache (grace period) is stored next to the DB file.
	licenseKey, _ := store.GetSetting(ctx, "license_key")
	cacheDir := filepath.Dir(cfg.Database.SQLitePath)
	if cacheDir == "." {
		cacheDir = "data"
	}
	lic := license.Validate(ctx, licenseKey, cacheDir, version)
	slog.Info("edition active", "edition", lic.Edition())

	// ── Seed default admin user ─────────────────────────────────────────────
	if err := seedAdminUser(ctx, store); err != nil {
		slog.Error("failed to seed admin user", "error", err)
		os.Exit(1)
	}

	// ── Certificate manager ──────────────────────────────────────────────────
	// METALWAF_MASTER_KEY (hex-encoded 32-byte AES-256 key) enables encryption
	// of private keys at rest. If not set, keys are stored as plaintext — fine
	// for development, but set the env var in production.
	var masterKey []byte
	if mkHex := os.Getenv("METALWAF_MASTER_KEY"); mkHex != "" {
		masterKey, err = hex.DecodeString(mkHex)
		if err != nil {
			slog.Warn("METALWAF_MASTER_KEY is not valid hex — private keys stored unencrypted", "error", err)
			masterKey = nil
		} else {
			slog.Info("certificates: private key encryption enabled (AES-256-GCM)")
		}
	}
	certManager := certificates.NewManager(store, masterKey)
	if err := certManager.Load(ctx); err != nil {
		slog.Warn("certificates: error loading from database", "error", err)
	}

	// ── Reverse proxy handler ────────────────────────────────────────────────
	proxyHandler, err := proxy.New(ctx, store)
	if err != nil {
		slog.Error("failed to initialize proxy", "error", err)
		os.Exit(1)
	}

	// ── WAF engine ───────────────────────────────────────────────────────────
	wafEngine := waf.New(store, waf.DefaultThreshold)
	if err := wafEngine.Reload(ctx); err != nil {
		slog.Warn("waf: could not load custom rules from database", "error", err)
	}
	proxyHandler.SetWAF(wafEngine)
	slog.Info("WAF engine ready", "rules", wafEngine.RuleCount(), "threshold", waf.DefaultThreshold)

	// ── Auth issuer ──────────────────────────────────────────────────────────
	// Apply defaults for token lifetimes when not set in config.
	if cfg.Auth.AccessTokenMinutes <= 0 {
		cfg.Auth.AccessTokenMinutes = 15
	}
	if cfg.Auth.RefreshTokenDays <= 0 {
		cfg.Auth.RefreshTokenDays = 7
	}
	// If no JWT secret is configured, generate an ephemeral one for this run.
	// Sessions will not survive a restart — set METALWAF_JWT_SECRET for
	// persistence. This allows the proxy and API to start without pre-configuration.
	if cfg.Auth.JWTSecret == "" {
		b := make([]byte, 32)
		if _, rerr := rand.Read(b); rerr != nil {
			slog.Error("auth: failed to generate ephemeral JWT secret", "error", rerr)
			os.Exit(1)
		}
		cfg.Auth.JWTSecret = hex.EncodeToString(b)
		slog.Warn("auth: no jwt_secret configured — using ephemeral key (sessions will not survive restart)",
			"hint", "set METALWAF_JWT_SECRET or auth.jwt_secret in config for persistent sessions")
	}

	issuer, err := auth.NewIssuer(
		cfg.Auth.JWTSecret,
		cfg.Auth.AccessTokenMinutes,
		cfg.Auth.RefreshTokenDays,
	)
	if err != nil {
		slog.Error("auth: invalid JWT configuration", "error", err)
		os.Exit(1)
	}

	// ── REST API router ──────────────────────────────────────────────────────
	apiRouter := api.NewRouter(api.Options{
		Store:       store,
		Issuer:      issuer,
		ProxyReload: proxyHandler.Reload,
		WAFReload:   wafEngine.Reload,
		CertReload:  certManager.Reload,
		MasterKey:   masterKey,
	})

	// ── Admin / health server (:9090) ────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := store.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"error","message":"database unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q,"edition":%q}`, version, lic.Edition())
	})
	mux.Handle("/api/", apiRouter)
	slog.Info("REST API ready", "base", "https://"+cfg.Server.AdminAddr+"/api/v1")

	// Serve embedded React SPA for all other paths.
	// Requests that match /api/ or /healthz are already handled above;
	// everything else is routed to the SPA so react-router can handle it.
	webFS, err := fs.Sub(frontend.FS, "web/dist")
	if err != nil {
		slog.Error("frontend: failed to sub embed FS", "error", err)
		os.Exit(1)
	}
	spaHandler := spaFileServer(http.FS(webFS))
	mux.Handle("/", spaHandler)

	// Admin TLS: generate a self-signed cert with SANs for localhost/loopback
	// and the configured admin host (if any). This allows browsers to offer
	// the "proceed anyway" warning rather than a hard reject.
	adminHost, _, _ := net.SplitHostPort(cfg.Server.AdminAddr)
	if adminHost == "" || adminHost == "0.0.0.0" || adminHost == "::" {
		adminHost = "" // already covered by localhost entries below
	}
	adminSANs := []string{"localhost", "127.0.0.1", "::1"}
	if adminHost != "" && adminHost != "localhost" {
		adminSANs = append(adminSANs, adminHost)
	}
	adminCert, err := certificates.GenerateSelfSignedForHosts(adminSANs...)
	if err != nil {
		slog.Error("failed to generate admin TLS certificate", "error", err)
		os.Exit(1)
	}

	adminSrv := &http.Server{
		Addr:    cfg.Server.AdminAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*adminCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		slog.Info("admin server listening (TLS)", "addr", "https://"+cfg.Server.AdminAddr)
		if err := adminSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("admin server error", "error", err)
		}
	}()

	// ── HTTP proxy server (:80) ──────────────────────────────────────────────
	// Wrap with ACME challenge handler: intercepts /.well-known/acme-challenge/*
	// for Let's Encrypt HTTP-01 validation; all other requests go to the proxy.
	httpSrv := &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      certManager.AcmeChallengeHandler(proxyHandler),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		slog.Info("HTTP proxy listening", "addr", cfg.Server.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP proxy error", "error", err)
		}
	}()

	// ── HTTPS proxy server (:443) ────────────────────────────────────────────
	// TLS config uses the certificate manager: manual certs (from DB) take
	// priority, then Let's Encrypt via autocert, then the built-in self-signed
	// fallback. No restart required when certs change.
	httpsSrv := &http.Server{
		Addr:         cfg.Server.HTTPSAddr,
		Handler:      proxyHandler,
		TLSConfig:    certManager.TLSConfig(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		slog.Info("HTTPS proxy listening", "addr", cfg.Server.HTTPSAddr)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS proxy error", "error", err)
		}
	}()

	// ── Session prune goroutine ─────────────────────────────────────────────
	// Periodically removes expired sessions so the table doesn't grow without
	// bound. Runs every hour; errors are logged as warnings (non-fatal).
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if perr := store.PruneExpiredSessions(context.Background()); perr != nil {
					slog.Warn("session prune error", "error", perr)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// ── Certificate expiry check goroutine ───────────────────────────────────
	// Logs a warning for any manually-uploaded certificate expiring in < 30 days.
	// Let's Encrypt certs are auto-renewed by autocert; this covers manual ones.
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				certManager.CheckExpiry(context.Background())
			case <-ctx.Done():
				return
			}
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	<-ctx.Done()
	slog.Info("shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()

	for _, srv := range []*http.Server{adminSrv, httpSrv, httpsSrv} {
		if err := srv.Shutdown(shutCtx); err != nil {
			slog.Error("server shutdown error", "addr", srv.Addr, "error", err)
		}
	}

	slog.Info("MetalWAF stopped")
}

// seedAdminUser creates a default admin account when no users exist yet.
// The password is read from METALWAF_ADMIN_PASSWORD; if unset, a default is
// used and a warning is logged.
func seedAdminUser(ctx context.Context, store database.Store) error {
	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("listing users: %w", err)
	}
	if len(users) > 0 {
		return nil // users already exist — never overwrite
	}

	password := os.Getenv("METALWAF_ADMIN_PASSWORD")
	if password == "" {
		password = "changeme123!"
		slog.Warn("METALWAF_ADMIN_PASSWORD not set — using insecure default password, change it immediately",
			"username", "admin")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	admin := &database.User{
		Username:     "admin",
		Email:        "admin@metalwaf.local",
		PasswordHash: string(hash),
		Role:         "admin",
	}
	if err := store.CreateUser(ctx, admin); err != nil {
		return fmt.Errorf("creating admin user: %w", err)
	}
	slog.Info("default admin user created", "username", "admin")
	return nil
}

// spaFileServer returns a handler that serves files from root.
// For any path that does not correspond to an existing file, it falls back to
// serving /index.html so that React Router can handle the route on the client.
func spaFileServer(root http.FileSystem) http.Handler {
	fileServer := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := root.Open(r.URL.Path)
		if err != nil {
			// File not found — serve index.html for SPA client-side routing.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		f.Close()
		fileServer.ServeHTTP(w, r)
	})
}
