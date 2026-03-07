-- MetalWAF — migration 003
-- Makes certificates.site_id nullable to support global (non-site-specific) certs.
-- SQLite does not support ALTER COLUMN, so we recreate the table.
-- No other table has a FK pointing to certificates, so no PRAGMA needed.

CREATE TABLE certificates_new (
    id          TEXT     PRIMARY KEY,
    site_id     TEXT     REFERENCES sites(id) ON DELETE CASCADE,
    domain      TEXT     NOT NULL,
    source      TEXT     NOT NULL DEFAULT 'manual',
    cert_pem    TEXT     NOT NULL,
    key_pem     TEXT     NOT NULL,
    expires_at  DATETIME,
    auto_renew  INTEGER  NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO certificates_new SELECT * FROM certificates;

DROP TABLE certificates;

ALTER TABLE certificates_new RENAME TO certificates;

CREATE INDEX IF NOT EXISTS idx_certs_site_id ON certificates(site_id);
