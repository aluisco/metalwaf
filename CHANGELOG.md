# Changelog

All notable changes to this project are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### In progress
- Phase 2: HTTP/HTTPS reverse proxy + virtual hosting
- Phase 3: WAF Engine (SQLi, XSS, RCE, LFI)
- Phase 4: JWT auth + dashboard REST API
- Phase 5: TLS certificate management + Let's Encrypt
- Phase 6: Embedded React dashboard frontend
- Phase 7: Rate limiting + IP blocklist
- Phase 8: Analytics + metrics visualization
- Phase 9: Full OWASP CRS rules + custom rules
- Phase 10: Hardening, tests, packaging, Docker

---

## [0.1.0] - 2026-03-06

### Added
- **Initial scaffolding** — complete Go project structure
- **`go.mod`** with dependencies: `modernc.org/sqlite`, `google/uuid`, `golang-jwt/jwt/v5`, `golang.org/x/crypto`, `gopkg.in/yaml.v3`
- **`internal/config`** — configuration structs (`Config`, `Server`, `Database`, `Auth`, `Log`) and loader with YAML + environment variable support
- **`internal/database/interface.go`** — full `Store` interface with all domain models: `User`, `Session`, `Site`, `Upstream`, `WAFRule`, `Certificate`, `RequestLog`
- **`internal/database/sqlite/store.go`** — SQLite implementation of the `Store` interface (~500 lines); zero CGO (`modernc.org/sqlite`)
- **`internal/database/sqlite/migrate.go`** — transactional migration runner using `//go:embed`, versioned by filename
- **`internal/database/sqlite/migrations/001_initial.sql`** — initial schema: 8 tables (`users`, `sessions`, `sites`, `upstreams`, `waf_rules`, `certificates`, `request_logs`, `settings`) + 9 indexes
- **SQLite configured** with `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`
- **`cmd/metalwaf/main.go`** — entrypoint with: config loading, structured logger (`log/slog`), store initialization, `admin` user seeding, HTTP server on `:9090` with graceful shutdown
- **`GET /healthz`** — health endpoint with database ping
- **Automatic seeding** of the `admin` user on first run (bcrypt password, configurable via `METALWAF_ADMIN_PASSWORD`)
- **`configs/metalwaf.yaml`** — documented default configuration
- **`.gitignore`** — binaries, `data/`, `web/dist/`, `.env` files
- **`LICENSE`** — MIT License (LITE edition)
- **Licensing model defined**: LITE = free and open source (MIT); PRO = paid commercial with priority support + SLA

[0.1.0]: https://github.com/metalwaf/metalwaf/releases/tag/v0.1.0
[Unreleased]: https://github.com/metalwaf/metalwaf/compare/v0.1.0...HEAD
