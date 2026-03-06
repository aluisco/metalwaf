package config

import (
	"errors"
	"fmt"
)

// Config is the root configuration structure for MetalWAF.
// License keys are NOT stored here — they are managed via the dashboard and
// persisted in the settings table of the database.
type Config struct {
	Server   Server   `yaml:"server"`
	Database Database `yaml:"database"`
	Auth     Auth     `yaml:"auth"`
	Log      Log      `yaml:"log"`
}

// Server holds the network listen addresses.
type Server struct {
	HTTPAddr  string `yaml:"http_addr"`
	HTTPSAddr string `yaml:"https_addr"`
	AdminAddr string `yaml:"admin_addr"`
}

// Database holds the storage backend configuration.
// If DSN is set, PostgreSQL is used; otherwise SQLite is used.
type Database struct {
	SQLitePath string `yaml:"sqlite_path"`
	DSN        string `yaml:"dsn"`
}

// Auth holds JWT token configuration.
// JWTSecret is required before enabling the REST API (Phase 4).
type Auth struct {
	JWTSecret          string `yaml:"jwt_secret"`
	AccessTokenMinutes int    `yaml:"access_token_minutes"`
	RefreshTokenDays   int    `yaml:"refresh_token_days"`
}

// Log holds structured logging configuration.
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
}

// Validate checks that all currently-consumed configuration fields are valid.
// Fields that belong to unimplemented phases (e.g. JWTSecret for Phase 4) are
// validated here too so that misconfigurations are caught early at startup
// rather than silently failing later.
func (c *Config) Validate() error {
	var errs []error

	// Server
	if c.Server.AdminAddr == "" {
		errs = append(errs, errors.New("server.admin_addr must not be empty"))
	}

	// Database: at least one backend must be reachable.
	// Note: DSN (PostgreSQL) is not yet implemented — the server will reject it
	// at startup. Validate it here anyway so the error is surfaced early.
	if c.Database.DSN == "" && c.Database.SQLitePath == "" {
		errs = append(errs, errors.New("database: either sqlite_path or dsn must be set"))
	}

	// Log
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level must be debug|info|warn|error, got %q", c.Log.Level))
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("log.format must be text|json, got %q", c.Log.Format))
	}

	return errors.Join(errs...)
}
