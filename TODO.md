# MetalWAF — TODO

Development progress by phase. Completed tasks are marked with `[x]`.

---

## ✅ Phase 1 — Scaffolding + Database (DONE)

- [x] Create project directory structure
- [x] Define `go.mod` with all dependencies
- [x] Implement `internal/config`: structs + YAML + env var loader
- [x] Define `database.Store` interface + complete domain models
- [x] Implement SQLite store: Users, Sessions, Sites, Upstreams, WAF Rules, Certificates, RequestLogs, Settings
- [x] Embedded migration runner (`//go:embed`), versioned and transactional
- [x] Initial SQL schema (8 tables + 9 indexes)
- [x] `cmd/metalwaf/main.go` entrypoint with graceful shutdown
- [x] `GET /healthz` endpoint
- [x] Automatic `admin` user seeding
- [x] Structured logger with `log/slog` (text/json, configurable level)
- [x] `configs/metalwaf.yaml`
- [x] `.gitignore`, `README.md`, `CHANGELOG.md`, `TODO.md`
- [x] `LICENSE` file (MIT — LITE edition)
- [x] Licensing model: LITE = free open source (MIT); PRO = paid commercial with priority support + SLA

---

## ⏸ Phase 1b — PostgreSQL Support (Optional Backend) — DEFERRED

> Deferred intentionally. SQLite covers all current use cases. PostgreSQL can be added in isolation at any point without touching the rest of the codebase — the `Store` interface already abstracts the backend completely.

- [ ] Define a build-time interface selector: if `database.dsn` is set (or `METALWAF_DB_DSN`), use PostgreSQL; otherwise use SQLite
- [ ] `internal/database/postgres/store.go` — PostgreSQL implementation of the `Store` interface (`pgx/v5` driver)
- [ ] `internal/database/postgres/migrate.go` — migration runner adapted for PostgreSQL (uses `schema_migrations` table same as SQLite)
- [ ] `internal/database/postgres/migrations/001_initial.sql` — PostgreSQL-compatible initial schema (same structure, adapted data types)
- [ ] `--db-migrate` CLI flag in `cmd/metalwaf/main.go` — when present: run migrations and exit (do not start the server)
- [ ] Update `cmd/metalwaf/main.go` to pick SQLite or PostgreSQL store at startup based on `database.dsn`
- [ ] Document migration procedure in `README.md` (already done) and `configs/metalwaf.yaml` (already done)
- [ ] Integration tests against a real PostgreSQL instance (Docker Compose for CI)

---

## ✅ Phase 2 — HTTP/HTTPS Reverse Proxy + Virtual Hosting (DONE)

- [x] `internal/proxy/upstream.go` — `UpstreamPool` struct with backend list and periodic health checks
- [x] `internal/proxy/proxy.go` — core reverse proxy using `net/http/httputil.ReverseProxy`; route by `Host` header to the site's upstream pool
- [x] `internal/proxy/rewrite.go` — header rewriting: add `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`; strip sensitive upstream headers
- [x] WebSocket support (`Upgrade: websocket`) in the proxy — handled automatically by `httputil.ReverseProxy` since Go 1.12
- [x] `internal/proxy/ratelimit.go` — per-IP rate limiter using token bucket (`golang.org/x/time/rate`)
- [x] HTTP listener on `:80`
- [x] HTTPS listener on `:443` (self-signed certificate at startup; Phase 5 replaces it with the certificate manager)
- [x] Virtual hosting: load enabled sites from DB on startup; `Handler.Reload()` for live updates (Phase 4 API)
- [x] `https_only` mode: automatic HTTP → HTTPS 301 redirect when enabled on a site
- [x] Upstream health checks: mark as `down` after 3 consecutive HEAD probe failures, recover automatically
- [x] Unit tests for proxy core and header rewriter (13 tests, all passing)

---

## ✅ Phase 3 — WAF Engine

- [x] `internal/waf/engine.go` — anomaly-scoring inspection engine (ActionBlock + ActionDetect + ActionAllow)
- [x] `internal/waf/analyzer.go` — request field extraction: URI, query (URL-decoded), body (512 KB with restore), IP, User-Agent, headers
- [x] `internal/waf/signatures_sqli.go` — 12 patterns × 3 fields = 36 rules (UNION SELECT, SLEEP, DDL, xp_cmdshell, …)
- [x] `internal/waf/signatures_xss.go` — 11 patterns × 3 fields = 33 rules (<script>, javascript:, event handlers, …)
- [x] `internal/waf/signatures_rce.go` — 8 patterns × 3 fields = 24 rules (shell_exec, $(), backtick, SSTI, …)
- [x] `internal/waf/signatures_traversal.go` — 7 patterns × 2 fields = 14 rules (../,  %2f, null byte, sensitive paths, …)
- [x] `internal/waf/signatures_scanner.go` — 14 User-Agent rules (sqlmap, nikto, nmap, nuclei, burp, …)
- [x] `internal/waf/rule.go` — Rule type, constants (Field/Operator/Action/Category), FromDB converter
- [x] Anomaly scoring: ActionBlock = instant block; ActionDetect = accumulate score; blocks at threshold (default 100)
- [x] Per-site modes: `off` / `detect` / `block`
- [x] 403 HTML response (dark theme) returned on block via `waf.WriteBlocked()`
- [x] `internal/waf/engine_test.go` — 15 tests covering all categories, modes, allow override, body restore
- [x] `internal/proxy/proxy.go` — WAF wired into ServeHTTP: inspect after HTTPS redirect, before upstream selection
- [x] `cmd/metalwaf/main.go` — WAF engine initialized before servers start, rules loaded from DB

---

## ✅ Phase 4 — Authentication + REST API (DONE)

- [x] `internal/auth/jwt.go` — `Issuer`, `Claims`, `TokenPair`; HS256 access tokens (15 min) + refresh tokens (7 days); algorithm pinning prevents alg:none confusion attacks
- [x] `internal/auth/totp.go` — RFC 6238 TOTP inline (no external dependency): `GenerateTOTPSecret`, `TOTPUri`, `ValidateTOTP`, ±1-period clock window
- [x] `internal/auth/middleware.go` — `Issuer.RequireAuth` / `Issuer.RequireAdmin` HTTP middleware; claims injected into request context; `ClaimsFromCtx` helper
- [x] `internal/auth/handler.go` — `POST /api/v1/auth/login` (per-IP rate limit, timing-safe username enumeration prevention), `POST /api/v1/auth/refresh` (token rotation + replay detection), `POST /api/v1/auth/logout`, `POST /api/v1/auth/logout-all`, TOTP setup/verify/disable
- [x] `internal/api/respond.go` — consistent `{"data":...}` / `{"error":"..."}` JSON envelope
- [x] `internal/api/router.go` — Go 1.22+ `http.ServeMux` with 30+ method+path routes; security headers middleware (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`, `Referrer-Policy`)
- [x] `internal/api/sites.go` — Sites + Upstreams CRUD with UUID validation, WAFMode enum check, upstream URL scheme/credential validation (SSRF prevention)
- [x] `internal/api/rules.go` — WAF Rules CRUD with field/operator/action ENUM validation; triggers WAF engine reload on mutation
- [x] `internal/api/analytics.go` — `GET /api/v1/logs` (paginated, filtered) + `GET /api/v1/metrics` (24h + all-time counters)
- [x] `internal/api/settings.go` — `GET/PUT /api/v1/settings`; protected keys (e.g. `license_key`) cannot be modified via API
- [x] `internal/api/profile.go` — `GET /api/v1/profile` + `PUT /api/v1/profile/password` (requires current password; revokes all sessions after change)
- [x] `cmd/metalwaf/main.go` — wires `auth.NewIssuer`, mounts `api.NewRouter` on admin mux under `/api/`, adds hourly session prune goroutine; `cfg.Validate()` is now fatal (not warn)
- [x] `internal/auth/jwt_test.go` + `internal/auth/handler_test.go` + `internal/api/router_test.go` — 49 new tests (77 total, all passing)

---

## ✅ Phase 5 — TLS Certificates

- [x] `internal/certificates/encrypt.go` — AES-256-GCM `EncryptKey`/`DecryptKey`; passthrough when `masterKey` is nil; `SHA-256` key derivation
- [x] `internal/certificates/parse.go` — `ParsePair(certPEM, keyPEM)` validates cert+key, rejects expired certs, sets `Leaf`; `FirstDomain`, `CertInfo`
- [x] `internal/certificates/acme_cache.go` — `autocert.Cache` backed by the `settings` table (`acme:` prefix, base64-encoded)
- [x] `internal/certificates/manager.go` — `Manager` orchestrator: loads manual certs from DB, Let's Encrypt via `autocert`, self-signed fallback (P-256 ECDSA, 10-year); SNI dispatch; hot-reload without restart
- [x] `internal/api/certificates.go` — REST handlers: `List`, `Create` (upload), `Get`, `Delete`, `RequestACME`; private key never returned in responses
- [x] `internal/api/router.go` — added `CertReload`/`MasterKey` to `Options`; real certificate routes replace the stub (5 routes)
- [x] `cmd/metalwaf/main.go` — parses `METALWAF_MASTER_KEY`; wires `certManager`; HTTP server wrapped with `AcmeChallengeHandler` for HTTP-01; HTTPS uses `certManager.TLSConfig()`; 24 h expiry-check goroutine
- [x] `internal/certificates/manager_test.go` — 17 tests: encrypt/decrypt, parse pair, ACME cache, manager SNI dispatch, wildcard, fallback, reload swap
- [x] 94 tests total, all passing

---

## 🔲 Phase 6 — Embedded React Frontend

- [ ] Initialize React project with Vite (`web/`)
- [ ] Configure `//go:embed web/dist` in `cmd/metalwaf/main.go`
- [ ] `Login.jsx` page with form + TOTP support
- [ ] `Dashboard.jsx` page — real-time metrics: requests/min, blocked threats, top IPs, traffic graph (last 24 h)
- [ ] `Sites.jsx` page — list, create, edit and delete sites + upstreams
- [ ] `WAFRules.jsx` page — rule editor: global and per-site; enable/disable toggle
- [ ] `Certificates.jsx` page — manual cert upload, "Get with Let's Encrypt" button, expiry status
- [ ] `Analytics.jsx` page — log table with filters (IP, site, blocked, date range) + charts
- [ ] `Settings.jsx` page — global config: anomaly score threshold, default WAF mode, log retention
- [ ] `<Navbar />` component with edition indicator (LITE badge)
- [ ] HTTP client with automatic refresh token interceptor
- [ ] Dark/light theme persisted in `localStorage`
- [ ] Production build integrated into `Makefile`
- [ ] Tests for critical components (Jest + React Testing Library)

---

## 🔲 Phase 7 — Rate Limiting + Access Control Lists

- [ ] Configurable global rate limiting (requests/sec for the whole instance)
- [ ] Per-site rate limiting (requests/sec per IP)
- [ ] Per-route rate limiting (e.g. `/api/` stricter than `/static/`)
- [ ] 429 response with `Retry-After` header
- [ ] IP allowlist: IPs/CIDR ranges that are never blocked by the WAF or rate limiter
- [ ] IP blocklist: IPs/CIDR ranges that always receive 403
- [ ] GeoIP: country-based blocking (MaxMind GeoLite2 database integration) — *optional*
- [ ] Persist lists in the DB and manage from the dashboard

---

## 🔲 Phase 8 — Analytics and Metrics

- [ ] `internal/analytics/collector.go` — channel-based collector; writes `RequestLog` to the DB asynchronously (does not block the proxy)
- [ ] `internal/analytics/aggregator.go` — aggregate metrics in 1-min / 1-h / 1-day windows, in memory and in the DB
- [ ] Metrics exposed at `GET /api/v1/metrics`:
  - Total, blocked and allowed requests
  - Top 10 IPs by request count
  - Top 10 most attacked paths
  - Top 10 most triggered rules
  - Status code distribution
  - Requests per site
- [ ] `GET /api/v1/metrics/prometheus` — Prometheus format for external scraping
- [ ] Basic alerting: blocked-requests-per-minute threshold → dashboard notification (WebSocket or polling)
- [ ] Configurable log retention: automatic purge of records older than N days
- [ ] Tests for collector and aggregator

---

## 🔲 Phase 9 — Full OWASP CRS Rules + Custom Rules

- [ ] Port the main OWASP Core Rule Set rules into MetalWAF's native format
- [ ] Custom rule syntax: `{ field, operator, value, action, score }` + validation
- [ ] Advanced operator support: `regex`, `cidr`, `startswith`, `endswith`, `not_contains`
- [ ] Rule groups: enable/disable entire categories (SQLi, XSS, scanners, etc.)
- [ ] Ruleset import/export in JSON
- [ ] "Paranoia" mode with levels 1–4 (same as ModSecurity CRS)
- [ ] Coverage tests for each attack category

---

## 🔲 Phase 10 — Hardening, Tests and Packaging

- [ ] Unit test coverage ≥ 80% for critical packages (`waf`, `proxy`, `auth`, `database`)
- [ ] End-to-end integration tests with a real server + HTTP client
- [ ] Basic load tests (verify the proxy handles ≥ 10k req/s on modest hardware)
- [ ] HTTP security headers on the dashboard: `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `HSTS`
- [ ] `Makefile` with targets: `build`, `build-all` (cross-compile), `test`, `lint`, `docker`
- [ ] Multi-stage `Dockerfile` (Go builder + final `scratch` or `distroless` image)
- [ ] `docker-compose.yml` for local development
- [ ] `configs/metalwaf.service` — systemd unit file
- [ ] Document and validate required environment variables on startup (clear error if mandatory PRO vars are missing)
- [ ] API documentation page (embedded OpenAPI 3.0 / Swagger)
- [ ] `install.sh` installation script for Linux
- [ ] Release binaries for: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`

---

## 🔲 Future — PRO Edition (Commercial)

> PRO is a **paid commercial** product. Licenses available at metalwaf.io.
> Includes all LITE features plus everything below, with priority support and SLA.

- [ ] PostgreSQL driver (`internal/database/postgres/store.go`) implementing the same `Store` interface
- [ ] PostgreSQL migrations in `internal/database/postgres/migrations/`
- [ ] Let's Encrypt wildcard with DNS-01 challenge (integrations: Cloudflare, Route53, and others)
- [ ] Load balancing strategies: round-robin, least-connections, IP hash, sticky sessions
- [ ] Multi-tenancy: organizations, per-org roles, data isolation
- [ ] Clustering / HA: multiple MetalWAF nodes with shared state in PostgreSQL
- [ ] SSO: SAML 2.0, OIDC (Keycloak, Entra ID, Google Workspace, etc.)
- [ ] API Keys for the REST API (in addition to JWT)
- [ ] Per-plan/tier rate limiting (for SaaS)
- [ ] SIEM export: syslog (RFC 5424), HTTP webhook, S3/MinIO
- [ ] Canary deployments: route a percentage of traffic to alternative upstreams
- [ ] Audit trail: log all dashboard actions

---

## 🔲 Technical Debt / Ongoing Improvements

- [ ] Add justified `//nolint` directives and configure `.golangci.yml`
- [ ] Pre-compile regex rules when loading them (cache `*regexp.Regexp`)
- [ ] Goroutine pool for WAF analysis under high request volume
- [ ] Add tracing with OpenTelemetry
- [ ] Apply `context.WithTimeout` to all database calls
- [ ] Server log rotation (integration with `lumberjack`)
- [ ] Go GC and runtime metrics in the Prometheus endpoint
