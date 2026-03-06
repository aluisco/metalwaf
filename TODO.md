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

---

## 🔲 Phase 2 — HTTP/HTTPS Reverse Proxy + Virtual Hosting

- [ ] `internal/proxy/upstream.go` — `UpstreamPool` struct with backend list and periodic health checks
- [ ] `internal/proxy/proxy.go` — core reverse proxy using `net/http/httputil.ReverseProxy`; route by `Host` header to the site's upstream pool
- [ ] `internal/proxy/rewrite.go` — header rewriting: add `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`; strip sensitive upstream headers
- [ ] WebSocket support (`Upgrade: websocket`) in the proxy
- [ ] `internal/proxy/ratelimit.go` — per-IP rate limiter using token bucket (`golang.org/x/time/rate`); configurable limits per site
- [ ] HTTP listener on `:80`
- [ ] HTTPS listener on `:443` (minimal TLS config to allow startup without a cert, extended in Phase 5)
- [ ] Virtual hosting: load enabled sites from DB on startup and on config changes
- [ ] `https_only` mode: automatic HTTP → HTTPS redirect when enabled on a site
- [ ] Upstream health checks: mark as `down` after N consecutive failures, recover automatically
- [ ] Unit tests for proxy core and header rewriter

---

## 🔲 Phase 3 — WAF Engine

- [ ] `internal/waf/engine.go` — HTTP middleware that intercepts every request before forwarding to the proxy
- [ ] `internal/waf/analyzer.go` — request field extraction: URI, query string, headers, body (with size limit), IP, User-Agent
- [ ] `internal/waf/signatures/sqli.go` — SQL Injection signatures (basic patterns + ported OWASP CRS regexes)
- [ ] `internal/waf/signatures/xss.go` — Cross-Site Scripting signatures
- [ ] `internal/waf/signatures/rce.go` — Remote Code Execution / Command Injection signatures
- [ ] `internal/waf/signatures/traversal.go` — Path Traversal / Local File Inclusion signatures
- [ ] `internal/waf/signatures/scanner.go` — known scanner detection (Nmap, Nikto, sqlmap, etc.) by User-Agent and request patterns
- [ ] `internal/waf/rules/loader.go` — load custom rules from DB on startup; live reload without restart
- [ ] `internal/waf/rules/owasp.go` — basic embedded OWASP CRS ruleset
- [ ] Anomaly scoring system: accumulate score per request; block if it exceeds the configurable threshold
- [ ] Per-site modes: `off` / `detect` / `block`
- [ ] 403 response with customizable HTML body on block
- [ ] Unit tests per signature + end-to-end integration tests

---

## 🔲 Phase 4 — Authentication + REST API

- [ ] `internal/auth/jwt.go` — generate and validate access tokens (15 min) and refresh tokens (7 days) with `golang-jwt/jwt/v5`
- [ ] `internal/auth/handler.go` — handlers: `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`
- [ ] `internal/auth/middleware.go` — middleware that validates the Bearer token on protected API routes
- [ ] 2FA TOTP: activation, QR generation, verification during login
- [ ] `internal/api/router.go` — API router setup under `/api/v1/`
- [ ] `internal/api/sites.go` — sites and upstreams CRUD (`GET/POST/PUT/DELETE /api/v1/sites`)
- [ ] `internal/api/rules.go` — WAF rules CRUD (`GET/POST/PUT/DELETE /api/v1/rules`)
- [ ] `internal/api/certificates.go` — certificate management (`GET/POST/DELETE /api/v1/certificates`)
- [ ] `internal/api/analytics.go` — logs and metrics (`GET /api/v1/logs`, `GET /api/v1/metrics`)
- [ ] `internal/api/settings.go` — global system settings
- [ ] Consistent JSON responses: `{"data":..., "error":...}` envelope
- [ ] API-level rate limiting to prevent brute force on the login endpoint
- [ ] API handler tests

---

## 🔲 Phase 5 — TLS Certificates

- [ ] `internal/certificates/upload.go` — receive and parse certificates: `.pem`, `.crt`+`.key`, `.pfx`/`.p12`; validate expiry and cert↔key consistency
- [ ] `internal/certificates/store.go` — persist CertPEM and KeyPEM in the DB (encrypted at rest with AES-GCM using `METALWAF_MASTER_KEY`)
- [ ] `internal/certificates/letsencrypt.go` — integration with `golang.org/x/crypto/acme/autocert`; HTTP-01 challenge; store certs in DB
- [ ] `internal/certificates/manager.go` — orchestrator: on startup, build `tls.Config` with certs for all active sites; hot rotation without restart
- [ ] Auto-renewal: goroutine that checks expiry every 24 h and renews if fewer than 30 days remain
- [ ] Near-expiry notification in the dashboard
- [ ] Tests: format parsing, key-pair validation, renewal flow

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

## 🔲 Future — PRO Edition

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
