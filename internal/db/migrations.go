package db

import "database/sql"

// migrate runs ALTER TABLE statements to add columns to existing tables.
// Each statement is executed independently — errors from "duplicate column name"
// are expected and ignored so migrations are idempotent.
func migrate(db *sql.DB) error {
	alterations := []string{
		`ALTER TABLE issuers ADD COLUMN access_token_ttl TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE issuers ADD COLUMN refresh_token_ttl TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE issuers ADD COLUMN auth_code_ttl TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range alterations {
		db.Exec(stmt) // ignore "duplicate column" errors
	}
	return nil
}

const schema = `
CREATE TABLE IF NOT EXISTS issuers (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    private_key       TEXT NOT NULL,
    public_key        TEXT NOT NULL,
    key_id            TEXT NOT NULL,
    scopes            TEXT NOT NULL DEFAULT 'openid profile email',
    access_token_ttl  TEXT NOT NULL DEFAULT '',
    refresh_token_ttl TEXT NOT NULL DEFAULT '',
    auth_code_ttl     TEXT NOT NULL DEFAULT '',
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    id            TEXT PRIMARY KEY,
    issuer_id     TEXT NOT NULL REFERENCES issuers(id) ON DELETE CASCADE,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(issuer_id, client_id)
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT PRIMARY KEY,
    issuer_id             TEXT NOT NULL REFERENCES issuers(id) ON DELETE CASCADE,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    username              TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    nonce                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    expires_at            DATETIME NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tokens (
    id         TEXT PRIMARY KEY,
    issuer_id  TEXT NOT NULL REFERENCES issuers(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    username   TEXT NOT NULL,
    scope      TEXT NOT NULL,
    token_type TEXT NOT NULL DEFAULT 'access_token',
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_clients_issuer ON clients(issuer_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_issuer ON auth_codes(issuer_id);
CREATE INDEX IF NOT EXISTS idx_tokens_issuer ON tokens(issuer_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);

CREATE TABLE IF NOT EXISTS custom_claims (
    id          TEXT PRIMARY KEY,
    issuer_id   TEXT NOT NULL REFERENCES issuers(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    claim_key   TEXT NOT NULL,
    claim_value TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_custom_claims_lookup ON custom_claims(issuer_id, client_id, username);
`
