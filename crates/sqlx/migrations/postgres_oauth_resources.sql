CREATE TABLE oauth_resource (id TEXT PRIMARY KEY NOT NULL, identifier TEXT NOT NULL UNIQUE, metadata TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE oauth_client_resource (id TEXT PRIMARY KEY NOT NULL,client_id TEXT NOT NULL REFERENCES oauth_client(client_id) ON DELETE CASCADE,resource_id TEXT NOT NULL REFERENCES oauth_resource(identifier) ON DELETE CASCADE,metadata TEXT,created_at TIMESTAMPTZ);
CREATE UNIQUE INDEX idx_oauth_client_resource_pair ON oauth_client_resource(client_id,resource_id);
CREATE INDEX idx_oauth_client_resource_resource ON oauth_client_resource(resource_id);
