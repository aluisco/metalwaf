package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/metalwaf/metalwaf/internal/config"
	"github.com/metalwaf/metalwaf/internal/database"
	"github.com/metalwaf/metalwaf/internal/database/sqlite"
	"github.com/metalwaf/metalwaf/internal/license"
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
		// Validation errors are warnings until the affected phases are
		// implemented. We log them prominently so the operator knows what
		// needs to be fixed before going to production.
		fmt.Fprintf(os.Stderr, "WARN: config validation: %v\n", err)
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

	// ── Admin / health HTTP server (Phase 1 placeholder) ────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := store.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"error","message":"database unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q,"edition":%q}`, version, lic.Edition())
	})

	srv := &http.Server{
		Addr:         cfg.Server.AdminAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("admin server listening", "addr", cfg.Server.AdminAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin server error", "error", err)
		}
	}()

	// ── Graceful shutdown ───────────────────────────────────────────────────
	<-ctx.Done()
	slog.Info("shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
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
		return nil // users already exist
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
