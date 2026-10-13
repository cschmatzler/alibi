CREATE TABLE oauth_client (
 id TEXT PRIMARY KEY NOT NULL,client_id TEXT NOT NULL UNIQUE,user_id TEXT,client_secret TEXT,metadata TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_oauth_client_user ON oauth_client(user_id);
