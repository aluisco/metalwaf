-- MetalWAF — migration 004
-- Removes site_id from certificates table.
-- Certificates are standalone entities; TLS matching is done by SNI domain name,
-- not by site association. Sites do not need a cert_id either — the TLS manager
-- picks the right cert by matching the certificate's own domain/SAN list.

CREATE TABLE certificates_v2 (
    id          TEXT     PRIMARY KEY,
    domain      TEXT     NOT NULL,
    source      TEXT     NOT NULL DEFAULT 'manual',
    cert_pem    TEXT     NOT NULL,
    key_pem     TEXT     NOT NULL,
    expires_at  DATETIME,
    auto_renew  INTEGER  NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO certificates_v2 (id, domain, source, cert_pem, key_pem, expires_at, auto_renew, created_at, updated_at)
SELECT id, domain, source, cert_pem, key_pem, expires_at, auto_renew, created_at, updated_at FROM certificates;

DROP TABLE certificates;

ALTER TABLE certificates_v2 RENAME TO certificates;
