# MetalWAF

> Web Application Firewall + Reverse Proxy written entirely in Go, with an embedded React dashboard. No external runtime dependencies — a single binary.

---

## Editions

| | **LITE** | **PRO** |
|---|:---:|:---:|
| **Price** | **Free** (MIT) | **Commercial** |
| **Support** | Community (GitHub Issues) | Priority support + SLA |
| **Source** | Open source | Proprietary |

> PRO licenses are available at **[metalwaf.io](https://metalwaf.io)** (coming soon).
> Contact us at **sales@metalwaf.io** for pricing and enterprise inquiries.

---

## Features

| Feature | LITE (free) | PRO (paid) |
|---|:---:|:---:|
| HTTP/HTTPS reverse proxy | ✅ | ✅ |
| Domain-based virtual hosting | ✅ | ✅ |
| WAF Engine (OWASP Top 10) | ✅ | ✅ |
| SQLi, XSS, RCE, LFI, SSRF detection | ✅ | ✅ |
| Anomaly scoring system | ✅ | ✅ |
| Detect-only / block mode | ✅ | ✅ |
| Rate limiting per IP / route / global | ✅ | ✅ |
| IP blocklist (CIDR) | ✅ | ✅ |
| Manual TLS certificates (.pem / .pfx) | ✅ | ✅ |
| Automatic Let's Encrypt (HTTP-01) | ✅ | ✅ |
| Embedded React dashboard | ✅ | ✅ |
| JWT auth + refresh tokens | ✅ | ✅ |
| 2FA TOTP | ✅ | ✅ |
| Analytics: logs, metrics, top IPs | ✅ | ✅ |
| SQLite (default, zero-config) | ✅ | ✅ |
| PostgreSQL (optional, self-service migration) | ✅ | ✅ |
| Let's Encrypt wildcard (DNS-01) | ❌ | ✅ |
| Load balancing | ❌ | ✅ |
| Multi-tenancy | ❌ | ✅ |
| Clustering / HA | ❌ | ✅ |
| SSO / SAML / OIDC | ❌ | ✅ |
| SIEM export (syslog, S3, webhook) | ❌ | ✅ |
| **Priority support + SLA** | ❌ | ✅ |

---

## Requirements

- **Go 1.22+** — backend compilation
- **Node.js 20+** — frontend compilation (development only)
- CGO-free — SQLite via `modernc.org/sqlite` (pure Go)

---

## Quick start

### Clone and build

```bash
git clone https://github.com/metalwaf/metalwaf.git
cd metalwaf

# Backend only (no UI)
go build -o metalwaf ./cmd/metalwaf

# Full build (backend + embedded frontend)
make build
```

### Run

```bash
# Using default configuration
./metalwaf

# Pointing to a specific config file
./metalwaf --config /etc/metalwaf/metalwaf.yaml

# Key environment variables
METALWAF_ADMIN_PASSWORD=mysecret \
METALWAF_JWT_SECRET=super-secure-key \
./metalwaf
```

### Docker

```bash
docker build -t metalwaf:latest .
docker run -d \
  -p 80:80 -p 443:443 -p 9090:9090 \
  -v metalwaf_data:/app/data \
  -e METALWAF_ADMIN_PASSWORD=mysecret \
  -e METALWAF_JWT_SECRET=super-secure-key \
  metalwaf:latest
```

---

## Configuration

The main configuration file is `configs/metalwaf.yaml`. All values can be overridden via environment variables.

```yaml
server:
  http_addr:  ":80"
  https_addr: ":443"
  admin_addr: ":9090"  # dashboard + REST API

database:
  # SQLite by default — zero config, single file.
  sqlite_path: "data/metalwaf.db"

  # Optional: switch to PostgreSQL instead of SQLite.
  # Set this DSN and run:  ./metalwaf --db-migrate
  # dsn: "postgres://user:password@localhost:5432/metalwaf?sslmode=disable"

auth:
  access_token_minutes: 15
  refresh_token_days: 7

log:
  level: info      # debug | info | warn | error
  format: text     # text | json
```

### Environment variables

| Variable | Description |
|---|---|
| `METALWAF_HTTP_ADDR` | HTTP listen address |
| `METALWAF_HTTPS_ADDR` | HTTPS listen address |
| `METALWAF_ADMIN_ADDR` | Admin panel listen address |
| `METALWAF_SQLITE_PATH` | Path to the SQLite database file (default `data/metalwaf.db`) |
| `METALWAF_DB_DSN` | PostgreSQL DSN — if set, PostgreSQL is used instead of SQLite |
| `METALWAF_LICENSE_KEY` | License key bootstrap (saved to DB on first run; not needed afterwards) |
| `METALWAF_JWT_SECRET` | Secret key used to sign JWT tokens |
| `METALWAF_ADMIN_PASSWORD` | Initial `admin` user password |
| `METALWAF_LOG_LEVEL` | Log level |
| `METALWAF_LOG_FORMAT` | Log format (`text` or `json`) |

---

## Database backends

MetalWAF ships with **SQLite as the default backend** — no external services required, zero config, single file. This is suitable for most deployments.

For high-traffic production environments you can optionally switch to **PostgreSQL**. Both editions (LITE and PRO) support both backends.

### Switching to PostgreSQL

1. Add the DSN to `configs/metalwaf.yaml` or set the env var:

```bash
export METALWAF_DB_DSN="postgres://user:password@localhost:5432/metalwaf?sslmode=disable"
```

2. Run the migration command to initialise the PostgreSQL schema:

```bash
./metalwaf --db-migrate
```

3. Start the server normally. MetalWAF will use PostgreSQL from that point on.

> **Note:** data is not automatically transferred from SQLite to PostgreSQL during migration. If you need to migrate existing data, export it beforehand.

---

## Available endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check + database ping |

> The full REST API under `/api/v1/` is added in Phase 4.

---

## Project structure

```
MetalWAF/
├── cmd/metalwaf/           ← Main entrypoint
├── internal/
│   ├── auth/               ← JWT, bcrypt, 2FA TOTP
│   ├── config/             ← Structs + YAML/env loader
│   ├── database/
│   │   ├── interface.go    ← Store interface + domain models
│   │   ├── sqlite/         ← SQLite implementation (default)
│   │   └── postgres/       ← PostgreSQL implementation (optional)
│   ├── waf/                ← WAF engine + rules + signatures
│   ├── proxy/              ← Reverse proxy + rate limiter
│   ├── certificates/       ← TLS manager + Let's Encrypt
│   ├── analytics/          ← Traffic collector and aggregator
│   └── api/                ← REST API (router + handlers)
├── web/                    ← React frontend (embedded in binary)
└── configs/                ← Default configuration
```

---

## Development

### Run in development mode

```bash
# Backend hot reload (requires 'air')
air

# Frontend dev server
cd web && npm run dev
```

### Tests

```bash
go test ./...
```

### Lint

```bash
golangci-lint run ./...
```

---

## Security

- All passwords are stored with **bcrypt** (cost 10)
- JWT tokens signed with HMAC-SHA256
- SQLite with **WAL mode** + `foreign_keys=ON` + `busy_timeout=5000`
- HTTP security headers on all dashboard responses
- `/healthz` does not expose sensitive information

**Default credentials**: `admin` / `changeme123!` — change immediately in production by setting `METALWAF_ADMIN_PASSWORD` before the first run.

---

## License

**MetalWAF LITE** is open source software released under the [MIT License](LICENSE).
You are free to use, modify and distribute it without restrictions.

**MetalWAF PRO** is proprietary commercial software. A valid license is required for production use.
See [metalwaf.io](https://metalwaf.io) for details or contact **sales@metalwaf.io**.
