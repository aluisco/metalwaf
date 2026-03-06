package config

// Config is the root configuration structure for MetalWAF.
type Config struct {
	Edition  string   `yaml:"edition"` // lite, pro
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
// SQLitePath is used for the "lite" edition; DSN for "pro" (PostgreSQL).
type Database struct {
	SQLitePath string `yaml:"sqlite_path"`
	DSN        string `yaml:"dsn"`
}

// Auth holds JWT token configuration.
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
