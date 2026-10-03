-- Better Auth schema for PostgreSQL. Column types match the SeaORM migration.

CREATE TABLE users (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    username TEXT UNIQUE,
    display_username TEXT,
    two_factor_enabled BOOLEAN,
    role TEXT,
    banned BOOLEAN,
    ban_reason TEXT,
    ban_expires TIMESTAMPTZ,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    is_anonymous BOOLEAN,
    phone_number TEXT,
    phone_number_verified BOOLEAN,
    last_login_method TEXT
);
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_username ON users (username);
CREATE UNIQUE INDEX idx_users_phone_number_unique ON users (phone_number);

CREATE TABLE sessions (
    id TEXT NOT NULL PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    token TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    impersonated_by TEXT,
    active_organization_id TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    active_team_id TEXT
);
CREATE INDEX idx_sessions_token ON sessions (token);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE accounts (
    id TEXT NOT NULL PRIMARY KEY,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    scope TEXT,
    password TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_accounts_user_id ON accounts (user_id);
CREATE INDEX idx_accounts_provider_account_lookup ON accounts (provider_id, account_id);

CREATE TABLE verifications (
    id TEXT NOT NULL PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_verifications_identifier ON verifications (identifier);

CREATE TABLE organization (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    logo TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_organization_slug ON organization (slug);

CREATE TABLE member (
    id TEXT NOT NULL PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_member_organization_id ON member (organization_id);
CREATE INDEX idx_member_user_id ON member (user_id);

CREATE TABLE invitation (
    id TEXT NOT NULL PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    inviter_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    team_id TEXT
);
CREATE INDEX idx_invitation_organization_id ON invitation (organization_id);
CREATE INDEX idx_invitation_email ON invitation (email);
CREATE INDEX idx_invitation_status ON invitation (status);

CREATE TABLE two_factor (
    id TEXT NOT NULL PRIMARY KEY,
    secret TEXT NOT NULL,
    backup_codes TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    verified BOOLEAN DEFAULT TRUE,
    failed_verification_count DOUBLE PRECISION DEFAULT 0,
    locked_until TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_two_factor_user_id ON two_factor (user_id);

CREATE TABLE api_keys (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    start TEXT,
    prefix TEXT,
    key TEXT NOT NULL UNIQUE,
    reference_id TEXT NOT NULL,
    config_id TEXT NOT NULL DEFAULT 'default',
    refill_interval DOUBLE PRECISION,
    refill_amount DOUBLE PRECISION,
    last_refill_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window DOUBLE PRECISION,
    rate_limit_max DOUBLE PRECISION,
    request_count DOUBLE PRECISION,
    remaining DOUBLE PRECISION,
    last_request TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    permissions TEXT,
    metadata TEXT
);
CREATE INDEX idx_api_keys_reference_id ON api_keys (reference_id);
CREATE INDEX idx_api_keys_config_id ON api_keys (config_id);

CREATE TABLE passkeys (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    public_key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    counter BIGINT NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT,
    credential TEXT NOT NULL,
    aaguid TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_passkeys_user_id ON passkeys (user_id);
CREATE INDEX idx_passkeys_credential_id ON passkeys (credential_id);

CREATE TABLE device_code (
    id TEXT NOT NULL PRIMARY KEY,
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    user_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    last_polled_at TIMESTAMPTZ,
    polling_interval BIGINT,
    client_id TEXT,
    scope TEXT
);
CREATE INDEX idx_device_code_device_code ON device_code (device_code);
CREATE INDEX idx_device_code_user_code ON device_code (user_code);
CREATE INDEX idx_device_code_user_id ON device_code (user_id);
CREATE INDEX idx_device_code_expires_at ON device_code (expires_at);

CREATE TABLE team (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    member_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ
);
CREATE INDEX idx_team_organization ON team (organization_id);

CREATE TABLE team_member (
    id TEXT NOT NULL PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES team (id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    membership_key TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_team_member_team ON team_member (team_id);
CREATE INDEX idx_team_member_user ON team_member (user_id);

CREATE TABLE organization_role (
    id TEXT NOT NULL PRIMARY KEY,
    organization_id TEXT NOT NULL,
    role TEXT NOT NULL,
    permission TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ
);
CREATE INDEX idx_organization_role_org ON organization_role (organization_id);
CREATE INDEX idx_organization_role_role ON organization_role (role);

CREATE TABLE jwks (
    id TEXT NOT NULL PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    alg TEXT,
    crv TEXT
);

CREATE TABLE wallet_address (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    address TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_wallet_address_user ON wallet_address (user_id);
