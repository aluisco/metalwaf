package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaults defines the out-of-the-box configuration values.
var defaults = Config{
	Edition: "lite",
	Server: Server{
		HTTPAddr:  ":80",
		HTTPSAddr: ":443",
		AdminAddr: ":9090",
	},
	Database: Database{
		SQLitePath: "data/metalwaf.db",
	},
	Auth: Auth{
		AccessTokenMinutes: 15,
		RefreshTokenDays:   7,
	},
	Log: Log{
		Level:  "info",
		Format: "text",
	},
}

// Load reads the YAML config file at path (empty = use defaults) and overlays
// values from environment variables.
func Load(path string) (*Config, error) {
	cfg := defaults

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// Config file is optional; skip if not found.
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("reading config file %q: %w", path, err)
			}
		} else {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return nil, fmt.Errorf("parsing config file %q: %w", path, err)
			}
		}
	}

	applyEnv(&cfg)
	return &cfg, nil
}

// applyEnv overlays config fields with values from environment variables.
func applyEnv(cfg *Config) {
	if v := os.Getenv("METALWAF_EDITION"); v != "" {
		cfg.Edition = strings.ToLower(v)
	}
	if v := os.Getenv("METALWAF_HTTP_ADDR"); v != "" {
		cfg.Server.HTTPAddr = v
	}
	if v := os.Getenv("METALWAF_HTTPS_ADDR"); v != "" {
		cfg.Server.HTTPSAddr = v
	}
	if v := os.Getenv("METALWAF_ADMIN_ADDR"); v != "" {
		cfg.Server.AdminAddr = v
	}
	if v := os.Getenv("METALWAF_SQLITE_PATH"); v != "" {
		cfg.Database.SQLitePath = v
	}
	if v := os.Getenv("METALWAF_DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("METALWAF_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("METALWAF_LOG_LEVEL"); v != "" {
		cfg.Log.Level = strings.ToLower(v)
	}
	if v := os.Getenv("METALWAF_LOG_FORMAT"); v != "" {
		cfg.Log.Format = strings.ToLower(v)
	}
}
