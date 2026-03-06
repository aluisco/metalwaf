-- MetalWAF — initial schema (migration 001)
-- Applied automatically by the SQLite store on first run.

-- ── Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            TEXT    PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'viewer',  -- admin | viewer
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── Sessions (refresh tokens) ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT     PRIMARY KEY,
    user_id       TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token TEXT     NOT NULL UNIQUE,
    expires_at    DATETIME NOT NULL,
    ip_address    TEXT,
    user_agent    TEXT,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── Sites (virtual proxy hosts) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sites (
    id         TEXT     PRIMARY KEY,
    name       TEXT     NOT NULL,
    domain     TEXT     NOT NULL UNIQUE,
    waf_mode   TEXT     NOT NULL DEFAULT 'detect',  -- detect | block | off
    https_only INTEGER  NOT NULL DEFAULT 0,
    enabled    INTEGER  NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── Upstreams (backend servers per site) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS upstreams (
    id         TEXT     PRIMARY KEY,
    site_id    TEXT     NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    url        TEXT     NOT NULL,
    weight     INTEGER  NOT NULL DEFAULT 1,
    enabled    INTEGER  NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── WAF Rules ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS waf_rules (
    id          TEXT     PRIMARY KEY,
    site_id     TEXT     REFERENCES sites(id) ON DELETE CASCADE,  -- NULL = global
    name        TEXT     NOT NULL,
    description TEXT,
    field       TEXT     NOT NULL,    -- header | body | uri | query | method | ip | user_agent
    operator    TEXT     NOT NULL,    -- contains | regex | equals | startswith | endswith | cidr
    value       TEXT     NOT NULL,
    action      TEXT     NOT NULL DEFAULT 'block',   -- block | detect | allow
    score       INTEGER  NOT NULL DEFAULT 5,
    enabled     INTEGER  NOT NULL DEFAULT 1,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── Certificates ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS certificates (
    id          TEXT     PRIMARY KEY,
    site_id     TEXT     NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    domain      TEXT     NOT NULL,
    source      TEXT     NOT NULL DEFAULT 'manual',  -- manual | letsencrypt
    cert_pem    TEXT     NOT NULL,
    key_pem     TEXT     NOT NULL,
    expires_at  DATETIME,
    auto_renew  INTEGER  NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── Request Logs (traffic analysis) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS request_logs (
    id           TEXT     PRIMARY KEY,
    site_id      TEXT     REFERENCES sites(id) ON DELETE SET NULL,
    timestamp    DATETIME NOT NULL DEFAULT (datetime('now')),
    client_ip    TEXT     NOT NULL,
    method       TEXT     NOT NULL,
    host         TEXT     NOT NULL,
    path         TEXT     NOT NULL,
    query        TEXT,
    status_code  INTEGER  NOT NULL,
    bytes_sent   INTEGER  NOT NULL DEFAULT 0,
    duration_ms  INTEGER  NOT NULL DEFAULT 0,
    blocked      INTEGER  NOT NULL DEFAULT 0,
    threat_score INTEGER  NOT NULL DEFAULT 0,
    rule_id      TEXT     REFERENCES waf_rules(id) ON DELETE SET NULL,
    user_agent   TEXT
);

-- ── Settings (key-value store) ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT     PRIMARY KEY,
    value      TEXT     NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_sessions_user_id   ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token     ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_upstreams_site_id  ON upstreams(site_id);
CREATE INDEX IF NOT EXISTS idx_waf_rules_site_id  ON waf_rules(site_id);
CREATE INDEX IF NOT EXISTS idx_certs_site_id      ON certificates(site_id);
CREATE INDEX IF NOT EXISTS idx_logs_site_id       ON request_logs(site_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp     ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_client_ip     ON request_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_logs_blocked       ON request_logs(blocked);
