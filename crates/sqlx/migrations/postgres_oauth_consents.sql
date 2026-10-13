CREATE TABLE oauth_consent (id TEXT PRIMARY KEY NOT NULL, client_id TEXT NOT NULL, user_id TEXT, metadata TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE INDEX idx_oauth_consent_user ON oauth_consent(user_id);
CREATE INDEX idx_oauth_consent_client ON oauth_consent(client_id);
