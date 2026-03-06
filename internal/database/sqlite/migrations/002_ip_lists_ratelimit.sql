-- MetalWAF — migration 002
-- Adds IP allow/block lists and per-site rate-limit overrides.

-- ── IP Lists ──────────────────────────────────────────────────────────────────
-- Each row represents one IP address or CIDR range that is either globally
-- allowed (never blocked, skips WAF) or globally/per-site blocked (always 403).
-- site_id = NULL means the rule applies to all sites.
CREATE TABLE IF NOT EXISTS ip_lists (
    id         TEXT     PRIMARY KEY,
    site_id    TEXT     REFERENCES sites(id) ON DELETE CASCADE,
    type       TEXT     NOT NULL CHECK (type IN ('allow', 'block')),
    cidr       TEXT     NOT NULL,  -- single IP or CIDR, e.g. "1.2.3.4" or "10.0.0.0/8"
    comment    TEXT     NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ip_lists_site_id ON ip_lists (site_id);
CREATE INDEX IF NOT EXISTS idx_ip_lists_type    ON ip_lists (type);

-- ── Per-site rate-limit overrides ─────────────────────────────────────────────
-- 0 in either column means "inherit the global default".
ALTER TABLE sites ADD COLUMN rate_limit_rps   REAL    NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN rate_limit_burst INTEGER NOT NULL DEFAULT 0;
