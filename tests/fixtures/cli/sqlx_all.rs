use alibi::AuthSchema;
use alibi::sqlx::{Engine, SqlxPool};
pub mod user {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "user", table = "user")]
    pub struct Model {
        pub id: String,
        pub name: String,
        pub email: String,
        #[sqlx(rename = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "isAnonymous")]
        pub is_anonymous: Option<bool>,
        #[sqlx(rename = "phoneNumber")]
        pub phone_number: Option<String>,
        #[sqlx(rename = "phoneNumberVerified")]
        pub phone_number_verified: Option<bool>,
        #[sqlx(rename = "lastLoginMethod")]
        pub last_login_method: Option<String>,
        pub username: Option<String>,
        #[sqlx(rename = "displayUsername")]
        pub display_username: Option<String>,
        #[sqlx(rename = "twoFactorEnabled")]
        pub two_factor_enabled: Option<bool>,
        pub role: Option<String>,
        pub banned: Option<bool>,
        #[sqlx(rename = "banReason")]
        pub ban_reason: Option<String>,
        #[sqlx(rename = "banExpires")]
        pub ban_expires: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod session {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "session", table = "session")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub token: String,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "ipAddress")]
        pub ip_address: Option<String>,
        #[sqlx(rename = "userAgent")]
        pub user_agent: Option<String>,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        #[sqlx(rename = "activeTeamId")]
        pub active_team_id: Option<String>,
        #[sqlx(rename = "impersonatedBy")]
        pub impersonated_by: Option<String>,
        #[sqlx(rename = "activeOrganizationId")]
        pub active_organization_id: Option<String>,
    }
}
pub mod account {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "account", table = "account")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "accountId")]
        pub account_id: String,
        #[sqlx(rename = "providerId")]
        pub provider_id: String,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        #[sqlx(rename = "accessToken")]
        pub access_token: Option<String>,
        #[sqlx(rename = "refreshToken")]
        pub refresh_token: Option<String>,
        #[sqlx(rename = "idToken")]
        pub id_token: Option<String>,
        #[sqlx(rename = "accessTokenExpiresAt")]
        pub access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "refreshTokenExpiresAt")]
        pub refresh_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub scope: Option<String>,
        pub password: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod verification {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "verification", table = "verification")]
    pub struct Model {
        pub id: String,
        pub identifier: String,
        pub value: String,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod wallet_address {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "walletAddress")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        pub address: String,
        #[sqlx(rename = "chainId")]
        pub chain_id: alibi::sqlx::Number,
        #[sqlx(rename = "isPrimary")]
        pub is_primary: bool,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod jwk {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "jwks")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "publicKey")]
        pub public_key: String,
        #[sqlx(rename = "privateKey")]
        pub private_key: String,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub alg: Option<String>,
        pub crv: Option<String>,
    }
}
pub mod team {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "team")]
    pub struct Model {
        pub id: String,
        pub name: String,
        #[sqlx(rename = "organizationId")]
        pub organization_id: String,
        #[sqlx(rename = "memberCount")]
        pub member_count: alibi::sqlx::Integer,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod team_member {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "teamMember")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "teamId")]
        pub team_id: String,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        #[sqlx(rename = "membershipKey")]
        pub membership_key: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod organization_role {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "organizationRole")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "organizationId")]
        pub organization_id: String,
        pub role: String,
        pub permission: String,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod two_factor {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "twoFactor")]
    pub struct Model {
        pub id: String,
        pub secret: String,
        #[sqlx(rename = "backupCodes")]
        pub backup_codes: String,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        pub verified: Option<bool>,
        #[sqlx(rename = "failedVerificationCount")]
        pub failed_verification_count: Option<alibi::sqlx::Number>,
        #[sqlx(rename = "lockedUntil")]
        pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod device_code {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "deviceCode")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "deviceCode")]
        pub device_code: String,
        #[sqlx(rename = "userCode")]
        pub user_code: String,
        #[sqlx(rename = "userId")]
        pub user_id: Option<String>,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub status: String,
        #[sqlx(rename = "lastPolledAt")]
        pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "pollingInterval")]
        pub polling_interval: Option<alibi::sqlx::Integer>,
        #[sqlx(rename = "clientId")]
        pub client_id: Option<String>,
        pub scope: Option<String>,
    }
}
pub mod organization {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "organization")]
    pub struct Model {
        pub id: String,
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        #[auth(column_type = "text")]
        pub metadata: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod member {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "member")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "organizationId")]
        pub organization_id: String,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        pub role: String,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod invitation {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "invitation")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "organizationId")]
        pub organization_id: String,
        pub email: String,
        pub role: Option<String>,
        #[sqlx(rename = "teamId")]
        pub team_id: Option<String>,
        pub status: String,
        #[sqlx(rename = "inviterId")]
        pub inviter_id: String,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod api_key {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "apikey")]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        pub start: Option<String>,
        pub prefix: Option<String>,
        #[sqlx(rename = "key")]
        pub key_hash: String,
        #[sqlx(rename = "referenceId")]
        pub reference_id: String,
        #[sqlx(rename = "configId")]
        pub config_id: String,
        #[sqlx(rename = "refillInterval")]
        pub refill_interval: Option<alibi::sqlx::Number>,
        #[sqlx(rename = "refillAmount")]
        pub refill_amount: Option<alibi::sqlx::Number>,
        #[sqlx(rename = "lastRefillAt")]
        pub last_refill_at: Option<chrono::DateTime<chrono::Utc>>,
        pub enabled: Option<bool>,
        #[sqlx(rename = "rateLimitEnabled")]
        pub rate_limit_enabled: Option<bool>,
        #[sqlx(rename = "rateLimitTimeWindow")]
        pub rate_limit_time_window: Option<alibi::sqlx::Number>,
        #[sqlx(rename = "rateLimitMax")]
        pub rate_limit_max: Option<alibi::sqlx::Number>,
        #[sqlx(rename = "requestCount")]
        pub request_count: Option<alibi::sqlx::Number>,
        pub remaining: Option<alibi::sqlx::Number>,
        #[sqlx(rename = "lastRequest")]
        pub last_request: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub permissions: Option<String>,
        pub metadata: Option<String>,
    }
}
pub mod passkey {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "passkey")]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        #[sqlx(rename = "publicKey")]
        pub public_key: String,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        #[sqlx(rename = "credentialID")]
        pub credential_id: String,
        pub counter: alibi::sqlx::Integer,
        #[sqlx(rename = "deviceType")]
        pub device_type: String,
        #[sqlx(rename = "backedUp")]
        pub backed_up: bool,
        pub transports: Option<String>,
        pub aaguid: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod oauth_client {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthClient")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "clientId")]
        pub client_id: String,
        #[sqlx(rename = "clientSecret")]
        pub client_secret: Option<String>,
        #[sqlx(rename = "clientDiscoveryId")]
        pub client_discovery_id: Option<String>,
        #[sqlx(rename = "disabled")]
        pub disabled: Option<bool>,
        #[sqlx(rename = "skipConsent")]
        pub skip_consent: Option<bool>,
        #[sqlx(rename = "enableEndSession")]
        pub enable_end_session: Option<bool>,
        #[sqlx(rename = "subjectType")]
        pub subject_type: Option<String>,
        #[sqlx(rename = "scopes")]
        pub scopes: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "clientCredentialsScopes")]
        pub client_credentials_scopes: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "userId")]
        pub user_id: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "name")]
        pub name: Option<String>,
        #[sqlx(rename = "uri")]
        pub uri: Option<String>,
        #[sqlx(rename = "icon")]
        pub icon: Option<String>,
        #[sqlx(rename = "contacts")]
        pub contacts: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "tos")]
        pub tos: Option<String>,
        #[sqlx(rename = "policy")]
        pub policy: Option<String>,
        #[sqlx(rename = "softwareId")]
        pub software_id: Option<String>,
        #[sqlx(rename = "softwareVersion")]
        pub software_version: Option<String>,
        #[sqlx(rename = "softwareStatement")]
        pub software_statement: Option<String>,
        #[sqlx(rename = "redirectUris")]
        pub redirect_uris: alibi::sqlx::JsonMetadata,
        #[sqlx(rename = "postLogoutRedirectUris")]
        pub post_logout_redirect_uris: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "backchannelLogoutUri")]
        pub backchannel_logout_uri: Option<String>,
        #[sqlx(rename = "backchannelLogoutSessionRequired")]
        pub backchannel_logout_session_required: Option<bool>,
        #[sqlx(rename = "tokenEndpointAuthMethod")]
        pub token_endpoint_auth_method: Option<String>,
        #[sqlx(rename = "applicationType")]
        pub application_type: Option<String>,
        #[sqlx(rename = "jwks")]
        pub jwks: Option<String>,
        #[sqlx(rename = "jwksUri")]
        pub jwks_uri: Option<String>,
        #[sqlx(rename = "grantTypes")]
        pub grant_types: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "responseTypes")]
        pub response_types: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "requirePKCE")]
        pub require_pkce: Option<bool>,
        #[sqlx(rename = "dpopBoundAccessTokens")]
        pub dpop_bound_access_tokens: Option<bool>,
        #[sqlx(rename = "referenceId")]
        pub reference_id: Option<String>,
        #[sqlx(rename = "metadata")]
        pub metadata: Option<alibi::sqlx::JsonMetadata>,
    }
}
pub mod oauth_resource {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthResource")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "identifier")]
        pub identifier: String,
        #[sqlx(rename = "name")]
        pub name: String,
        #[sqlx(rename = "accessTokenTtl")]
        pub access_token_ttl: Option<alibi::sqlx::Integer>,
        #[sqlx(rename = "refreshTokenTtl")]
        pub refresh_token_ttl: Option<alibi::sqlx::Integer>,
        #[sqlx(rename = "signingAlgorithm")]
        pub signing_algorithm: Option<String>,
        #[sqlx(rename = "signingKeyId")]
        pub signing_key_id: Option<String>,
        #[sqlx(rename = "allowedScopes")]
        pub allowed_scopes: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "customClaims")]
        pub custom_claims: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "dpopBoundAccessTokensRequired")]
        pub dpop_bound_access_tokens_required: Option<bool>,
        #[sqlx(rename = "disabled")]
        pub disabled: Option<bool>,
        #[sqlx(rename = "createdAt")]
        pub created_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "policyVersion")]
        pub policy_version: Option<alibi::sqlx::Integer>,
        #[sqlx(rename = "metadata")]
        pub metadata: Option<alibi::sqlx::JsonMetadata>,
    }
}
pub mod oauth_client_resource {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthClientResource")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "clientId")]
        pub client_id: String,
        #[sqlx(rename = "resourceId")]
        pub resource_id: String,
        #[sqlx(rename = "metadata")]
        pub metadata: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "createdAt")]
        pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod oauth_refresh_token {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthRefreshToken")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "token")]
        pub token: String,
        #[sqlx(rename = "clientId")]
        pub client_id: String,
        #[sqlx(rename = "sessionId")]
        pub session_id: Option<String>,
        #[sqlx(rename = "userId")]
        pub user_id: String,
        #[sqlx(rename = "referenceId")]
        pub reference_id: Option<String>,
        #[sqlx(rename = "authorizationCodeId")]
        pub authorization_code_id: Option<String>,
        #[sqlx(rename = "resources")]
        pub resources: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "requestedUserInfoClaims")]
        pub requested_user_info_claims: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "revoked")]
        pub revoked: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "rotatedAt")]
        pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "rotationReplayResponse")]
        pub rotation_replay_response: Option<String>,
        #[sqlx(rename = "rotationReplayExpiresAt")]
        pub rotation_replay_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "authTime")]
        pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "confirmation")]
        pub confirmation: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "scopes")]
        pub scopes: alibi::sqlx::JsonMetadata,
    }
}
pub mod oauth_access_token {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthAccessToken")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "token")]
        pub token: String,
        #[sqlx(rename = "clientId")]
        pub client_id: String,
        #[sqlx(rename = "sessionId")]
        pub session_id: Option<String>,
        #[sqlx(rename = "userId")]
        pub user_id: Option<String>,
        #[sqlx(rename = "referenceId")]
        pub reference_id: Option<String>,
        #[sqlx(rename = "authorizationCodeId")]
        pub authorization_code_id: Option<String>,
        #[sqlx(rename = "resources")]
        pub resources: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "requestedUserInfoClaims")]
        pub requested_user_info_claims: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "refreshId")]
        pub refresh_id: Option<String>,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "revoked")]
        pub revoked: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "confirmation")]
        pub confirmation: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "scopes")]
        pub scopes: alibi::sqlx::JsonMetadata,
    }
}
pub mod oauth_consent {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthConsent")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "clientId")]
        pub client_id: String,
        #[sqlx(rename = "userId")]
        pub user_id: Option<String>,
        #[sqlx(rename = "referenceId")]
        pub reference_id: Option<String>,
        #[sqlx(rename = "resources")]
        pub resources: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "requestedUserInfoClaims")]
        pub requested_user_info_claims: Option<alibi::sqlx::JsonMetadata>,
        #[sqlx(rename = "scopes")]
        pub scopes: alibi::sqlx::JsonMetadata,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod oauth_client_assertion {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "oauthClientAssertion")]
    pub struct Model {
        pub id: String,
        #[sqlx(rename = "expiresAt")]
        pub expires_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod rate_limit {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "rateLimit")]
    pub struct Model {
        pub id: String,
        pub key: String,
        pub count: i32,
        #[sqlx(rename = "lastRequest")]
        pub last_request: i64,
    }
}
pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
const SQLITE_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" integer not null, \"image\" text, \"createdAt\" date not null, \"updatedAt\" date not null, \"role\" text, \"banned\" integer, \"banReason\" text, \"banExpires\" date, \"isAnonymous\" integer, \"phoneNumber\" text unique, \"phoneNumberVerified\" integer, \"lastLoginMethod\" text, \"username\" text unique, \"displayUsername\" text, \"twoFactorEnabled\" integer)",
    "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" date not null, \"token\" text not null unique, \"createdAt\" date not null, \"updatedAt\" date not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"impersonatedBy\" text, \"activeOrganizationId\" text, \"activeTeamId\" text)",
    "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" date, \"refreshTokenExpiresAt\" date, \"scope\" text, \"password\" text, \"createdAt\" date not null, \"updatedAt\" date not null)",
    "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" date not null, \"createdAt\" date not null, \"updatedAt\" date not null)",
    "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
    "CREATE TABLE IF NOT EXISTS \"organization\" (\"id\" text not null primary key, \"name\" text not null, \"slug\" text not null unique, \"logo\" text, \"createdAt\" date not null, \"metadata\" text)",
    "CREATE TABLE IF NOT EXISTS \"organizationRole\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"role\" text not null, \"permission\" text not null, \"createdAt\" date not null, \"updatedAt\" date)",
    "create index IF NOT EXISTS \"organizationRole_organizationId_idx\" on \"organizationRole\" (\"organizationId\")",
    "create index IF NOT EXISTS \"organizationRole_role_idx\" on \"organizationRole\" (\"role\")",
    "CREATE TABLE IF NOT EXISTS \"team\" (\"id\" text not null primary key, \"name\" text not null, \"memberCount\" integer not null, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"createdAt\" date not null, \"updatedAt\" date)",
    "create index IF NOT EXISTS \"team_organizationId_idx\" on \"team\" (\"organizationId\")",
    "CREATE TABLE IF NOT EXISTS \"teamMember\" (\"id\" text not null primary key, \"teamId\" text not null references \"team\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"membershipKey\" text unique, \"createdAt\" date)",
    "create index IF NOT EXISTS \"teamMember_teamId_idx\" on \"teamMember\" (\"teamId\")",
    "create index IF NOT EXISTS \"teamMember_userId_idx\" on \"teamMember\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"member\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"role\" text not null, \"createdAt\" date not null)",
    "create index IF NOT EXISTS \"member_organizationId_idx\" on \"member\" (\"organizationId\")",
    "create index IF NOT EXISTS \"member_userId_idx\" on \"member\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"invitation\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"email\" text not null, \"role\" text, \"teamId\" text, \"status\" text not null, \"expiresAt\" date not null, \"createdAt\" date not null, \"inviterId\" text not null references \"user\" (\"id\") on delete cascade)",
    "create index IF NOT EXISTS \"invitation_organizationId_idx\" on \"invitation\" (\"organizationId\")",
    "create index IF NOT EXISTS \"invitation_email_idx\" on \"invitation\" (\"email\")",
    "CREATE TABLE IF NOT EXISTS \"twoFactor\" (\"id\" text not null primary key, \"secret\" text not null, \"backupCodes\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"verified\" integer, \"failedVerificationCount\" integer, \"lockedUntil\" date)",
    "create index IF NOT EXISTS \"twoFactor_secret_idx\" on \"twoFactor\" (\"secret\")",
    "create index IF NOT EXISTS \"twoFactor_userId_idx\" on \"twoFactor\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"deviceCode\" (\"id\" text not null primary key, \"deviceCode\" text not null, \"userCode\" text not null, \"userId\" text, \"expiresAt\" date not null, \"status\" text not null, \"lastPolledAt\" date, \"pollingInterval\" integer, \"clientId\" text, \"scope\" text)",
    "create unique index IF NOT EXISTS \"deviceCode_deviceCode_uidx\" on \"deviceCode\" (\"deviceCode\")",
    "create unique index IF NOT EXISTS \"deviceCode_userCode_uidx\" on \"deviceCode\" (\"userCode\")",
    "CREATE TABLE IF NOT EXISTS \"jwks\" (\"id\" text not null primary key, \"publicKey\" text not null, \"privateKey\" text not null, \"createdAt\" date not null, \"expiresAt\" date, \"alg\" text, \"crv\" text)",
    "CREATE TABLE IF NOT EXISTS \"walletAddress\" (\"id\" text not null primary key, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"address\" text not null, \"chainId\" integer not null, \"isPrimary\" integer not null, \"createdAt\" date not null)",
    "create index IF NOT EXISTS \"walletAddress_userId_idx\" on \"walletAddress\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"apikey\" (\"id\" text not null primary key, \"configId\" text not null, \"name\" text, \"start\" text, \"referenceId\" text not null, \"prefix\" text, \"key\" text not null, \"refillInterval\" integer, \"refillAmount\" integer, \"lastRefillAt\" date, \"enabled\" integer, \"rateLimitEnabled\" integer, \"rateLimitTimeWindow\" integer, \"rateLimitMax\" integer, \"requestCount\" integer, \"remaining\" integer, \"lastRequest\" date, \"expiresAt\" date, \"createdAt\" date not null, \"updatedAt\" date not null, \"permissions\" text, \"metadata\" text)",
    "create index IF NOT EXISTS \"apikey_configId_idx\" on \"apikey\" (\"configId\")",
    "create index IF NOT EXISTS \"apikey_referenceId_idx\" on \"apikey\" (\"referenceId\")",
    "create index IF NOT EXISTS \"apikey_key_idx\" on \"apikey\" (\"key\")",
    "CREATE TABLE IF NOT EXISTS \"passkey\" (\"id\" text not null primary key, \"name\" text, \"publicKey\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"credentialID\" text not null, \"counter\" integer not null, \"deviceType\" text not null, \"backedUp\" integer not null, \"transports\" text, \"createdAt\" date, \"aaguid\" text)",
    "create index IF NOT EXISTS \"passkey_userId_idx\" on \"passkey\" (\"userId\")",
    "create index IF NOT EXISTS \"passkey_credentialID_idx\" on \"passkey\" (\"credentialID\")",
    "CREATE TABLE IF NOT EXISTS \"oauthClient\" (\"id\" text not null primary key, \"clientId\" text not null unique, \"clientSecret\" text, \"clientDiscoveryId\" text, \"disabled\" integer, \"skipConsent\" integer, \"enableEndSession\" integer, \"subjectType\" text, \"scopes\" text, \"clientCredentialsScopes\" text, \"userId\" text references \"user\" (\"id\") on delete cascade, \"createdAt\" date, \"updatedAt\" date, \"name\" text, \"uri\" text, \"icon\" text, \"contacts\" text, \"tos\" text, \"policy\" text, \"softwareId\" text, \"softwareVersion\" text, \"softwareStatement\" text, \"redirectUris\" text not null, \"postLogoutRedirectUris\" text, \"backchannelLogoutUri\" text, \"backchannelLogoutSessionRequired\" integer, \"tokenEndpointAuthMethod\" text, \"applicationType\" text, \"jwks\" text, \"jwksUri\" text, \"grantTypes\" text, \"responseTypes\" text, \"requirePKCE\" integer, \"dpopBoundAccessTokens\" integer, \"referenceId\" text, \"metadata\" text)",
    "create index IF NOT EXISTS \"oauthClient_userId_idx\" on \"oauthClient\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthResource\" (\"id\" text not null primary key, \"identifier\" text not null unique, \"name\" text not null, \"accessTokenTtl\" integer, \"refreshTokenTtl\" integer, \"signingAlgorithm\" text, \"signingKeyId\" text, \"allowedScopes\" text, \"customClaims\" text, \"dpopBoundAccessTokensRequired\" integer, \"disabled\" integer, \"createdAt\" date, \"updatedAt\" date, \"policyVersion\" integer, \"metadata\" text)",
    "CREATE TABLE IF NOT EXISTS \"oauthClientResource\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"resourceId\" text not null references \"oauthResource\" (\"identifier\") on delete cascade, \"metadata\" text, \"createdAt\" date)",
    "create index IF NOT EXISTS \"oauthClientResource_clientId_idx\" on \"oauthClientResource\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthClientResource_resourceId_idx\" on \"oauthClientResource\" (\"resourceId\")",
    "create unique index IF NOT EXISTS \"oauthClientResource_clientId_resourceId_uidx\" on \"oauthClientResource\" (\"clientId\", \"resourceId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthRefreshToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" text, \"requestedUserInfoClaims\" text, \"expiresAt\" date not null, \"createdAt\" date not null, \"revoked\" date, \"rotatedAt\" date, \"rotationReplayResponse\" text, \"rotationReplayExpiresAt\" date, \"authTime\" date, \"confirmation\" text, \"scopes\" text not null)",
    "create index IF NOT EXISTS \"oauthRefreshToken_clientId_idx\" on \"oauthRefreshToken\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthRefreshToken_sessionId_idx\" on \"oauthRefreshToken\" (\"sessionId\")",
    "create index IF NOT EXISTS \"oauthRefreshToken_userId_idx\" on \"oauthRefreshToken\" (\"userId\")",
    "create index IF NOT EXISTS \"oauthRefreshToken_authorizationCodeId_idx\" on \"oauthRefreshToken\" (\"authorizationCodeId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthAccessToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" text, \"requestedUserInfoClaims\" text, \"refreshId\" text references \"oauthRefreshToken\" (\"id\") on delete cascade, \"expiresAt\" date not null, \"createdAt\" date not null, \"revoked\" date, \"confirmation\" text, \"scopes\" text not null)",
    "create index IF NOT EXISTS \"oauthAccessToken_clientId_idx\" on \"oauthAccessToken\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_sessionId_idx\" on \"oauthAccessToken\" (\"sessionId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_userId_idx\" on \"oauthAccessToken\" (\"userId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_authorizationCodeId_idx\" on \"oauthAccessToken\" (\"authorizationCodeId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_refreshId_idx\" on \"oauthAccessToken\" (\"refreshId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthConsent\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"resources\" text, \"requestedUserInfoClaims\" text, \"scopes\" text not null, \"createdAt\" date not null, \"updatedAt\" date not null)",
    "create index IF NOT EXISTS \"oauthConsent_clientId_idx\" on \"oauthConsent\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthConsent_userId_idx\" on \"oauthConsent\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthClientAssertion\" (\"id\" text not null primary key, \"expiresAt\" date not null)",
    "CREATE TABLE IF NOT EXISTS \"rateLimit\" (\"id\" text not null primary key, \"key\" text not null unique, \"count\" integer not null, \"lastRequest\" bigint not null)",
];
const POSTGRES_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" boolean not null, \"image\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null, \"role\" text, \"banned\" boolean, \"banReason\" text, \"banExpires\" timestamptz, \"isAnonymous\" boolean, \"phoneNumber\" text unique, \"phoneNumberVerified\" boolean, \"lastLoginMethod\" text, \"username\" text unique, \"displayUsername\" text, \"twoFactorEnabled\" boolean)",
    "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" timestamptz not null, \"token\" text not null unique, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"impersonatedBy\" text, \"activeOrganizationId\" text, \"activeTeamId\" text)",
    "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" timestamptz, \"refreshTokenExpiresAt\" timestamptz, \"scope\" text, \"password\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null)",
    "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null)",
    "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
    "CREATE TABLE IF NOT EXISTS \"organization\" (\"id\" text not null primary key, \"name\" text not null, \"slug\" text not null unique, \"logo\" text, \"createdAt\" timestamptz not null, \"metadata\" text)",
    "CREATE TABLE IF NOT EXISTS \"organizationRole\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"role\" text not null, \"permission\" text not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz)",
    "create index IF NOT EXISTS \"organizationRole_organizationId_idx\" on \"organizationRole\" (\"organizationId\")",
    "create index IF NOT EXISTS \"organizationRole_role_idx\" on \"organizationRole\" (\"role\")",
    "CREATE TABLE IF NOT EXISTS \"team\" (\"id\" text not null primary key, \"name\" text not null, \"memberCount\" integer not null, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz)",
    "create index IF NOT EXISTS \"team_organizationId_idx\" on \"team\" (\"organizationId\")",
    "CREATE TABLE IF NOT EXISTS \"teamMember\" (\"id\" text not null primary key, \"teamId\" text not null references \"team\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"membershipKey\" text unique, \"createdAt\" timestamptz)",
    "create index IF NOT EXISTS \"teamMember_teamId_idx\" on \"teamMember\" (\"teamId\")",
    "create index IF NOT EXISTS \"teamMember_userId_idx\" on \"teamMember\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"member\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"role\" text not null, \"createdAt\" timestamptz not null)",
    "create index IF NOT EXISTS \"member_organizationId_idx\" on \"member\" (\"organizationId\")",
    "create index IF NOT EXISTS \"member_userId_idx\" on \"member\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"invitation\" (\"id\" text not null primary key, \"organizationId\" text not null references \"organization\" (\"id\") on delete cascade, \"email\" text not null, \"role\" text, \"teamId\" text, \"status\" text not null, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"inviterId\" text not null references \"user\" (\"id\") on delete cascade)",
    "create index IF NOT EXISTS \"invitation_organizationId_idx\" on \"invitation\" (\"organizationId\")",
    "create index IF NOT EXISTS \"invitation_email_idx\" on \"invitation\" (\"email\")",
    "CREATE TABLE IF NOT EXISTS \"twoFactor\" (\"id\" text not null primary key, \"secret\" text not null, \"backupCodes\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"verified\" boolean, \"failedVerificationCount\" integer, \"lockedUntil\" timestamptz)",
    "create index IF NOT EXISTS \"twoFactor_secret_idx\" on \"twoFactor\" (\"secret\")",
    "create index IF NOT EXISTS \"twoFactor_userId_idx\" on \"twoFactor\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"deviceCode\" (\"id\" text not null primary key, \"deviceCode\" text not null, \"userCode\" text not null, \"userId\" text, \"expiresAt\" timestamptz not null, \"status\" text not null, \"lastPolledAt\" timestamptz, \"pollingInterval\" integer, \"clientId\" text, \"scope\" text)",
    "create unique index IF NOT EXISTS \"deviceCode_deviceCode_uidx\" on \"deviceCode\" (\"deviceCode\")",
    "create unique index IF NOT EXISTS \"deviceCode_userCode_uidx\" on \"deviceCode\" (\"userCode\")",
    "CREATE TABLE IF NOT EXISTS \"jwks\" (\"id\" text not null primary key, \"publicKey\" text not null, \"privateKey\" text not null, \"createdAt\" timestamptz not null, \"expiresAt\" timestamptz, \"alg\" text, \"crv\" text)",
    "CREATE TABLE IF NOT EXISTS \"walletAddress\" (\"id\" text not null primary key, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"address\" text not null, \"chainId\" integer not null, \"isPrimary\" boolean not null, \"createdAt\" timestamptz not null)",
    "create index IF NOT EXISTS \"walletAddress_userId_idx\" on \"walletAddress\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"apikey\" (\"id\" text not null primary key, \"configId\" text not null, \"name\" text, \"start\" text, \"referenceId\" text not null, \"prefix\" text, \"key\" text not null, \"refillInterval\" integer, \"refillAmount\" integer, \"lastRefillAt\" timestamptz, \"enabled\" boolean, \"rateLimitEnabled\" boolean, \"rateLimitTimeWindow\" integer, \"rateLimitMax\" integer, \"requestCount\" integer, \"remaining\" integer, \"lastRequest\" timestamptz, \"expiresAt\" timestamptz, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz not null, \"permissions\" text, \"metadata\" text)",
    "create index IF NOT EXISTS \"apikey_configId_idx\" on \"apikey\" (\"configId\")",
    "create index IF NOT EXISTS \"apikey_referenceId_idx\" on \"apikey\" (\"referenceId\")",
    "create index IF NOT EXISTS \"apikey_key_idx\" on \"apikey\" (\"key\")",
    "CREATE TABLE IF NOT EXISTS \"passkey\" (\"id\" text not null primary key, \"name\" text, \"publicKey\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"credentialID\" text not null, \"counter\" integer not null, \"deviceType\" text not null, \"backedUp\" boolean not null, \"transports\" text, \"createdAt\" timestamptz, \"aaguid\" text)",
    "create index IF NOT EXISTS \"passkey_userId_idx\" on \"passkey\" (\"userId\")",
    "create index IF NOT EXISTS \"passkey_credentialID_idx\" on \"passkey\" (\"credentialID\")",
    "CREATE TABLE IF NOT EXISTS \"oauthClient\" (\"id\" text not null primary key, \"clientId\" text not null unique, \"clientSecret\" text, \"clientDiscoveryId\" text, \"disabled\" boolean, \"skipConsent\" boolean, \"enableEndSession\" boolean, \"subjectType\" text, \"scopes\" jsonb, \"clientCredentialsScopes\" jsonb, \"userId\" text references \"user\" (\"id\") on delete cascade, \"createdAt\" timestamptz, \"updatedAt\" timestamptz, \"name\" text, \"uri\" text, \"icon\" text, \"contacts\" jsonb, \"tos\" text, \"policy\" text, \"softwareId\" text, \"softwareVersion\" text, \"softwareStatement\" text, \"redirectUris\" jsonb not null, \"postLogoutRedirectUris\" jsonb, \"backchannelLogoutUri\" text, \"backchannelLogoutSessionRequired\" boolean, \"tokenEndpointAuthMethod\" text, \"applicationType\" text, \"jwks\" text, \"jwksUri\" text, \"grantTypes\" jsonb, \"responseTypes\" jsonb, \"requirePKCE\" boolean, \"dpopBoundAccessTokens\" boolean, \"referenceId\" text, \"metadata\" jsonb)",
    "create index IF NOT EXISTS \"oauthClient_userId_idx\" on \"oauthClient\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthResource\" (\"id\" text not null primary key, \"identifier\" text not null unique, \"name\" text not null, \"accessTokenTtl\" integer, \"refreshTokenTtl\" integer, \"signingAlgorithm\" text, \"signingKeyId\" text, \"allowedScopes\" jsonb, \"customClaims\" jsonb, \"dpopBoundAccessTokensRequired\" boolean, \"disabled\" boolean, \"createdAt\" timestamptz, \"updatedAt\" timestamptz, \"policyVersion\" integer, \"metadata\" jsonb)",
    "CREATE TABLE IF NOT EXISTS \"oauthClientResource\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"resourceId\" text not null references \"oauthResource\" (\"identifier\") on delete cascade, \"metadata\" jsonb, \"createdAt\" timestamptz)",
    "create index IF NOT EXISTS \"oauthClientResource_clientId_idx\" on \"oauthClientResource\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthClientResource_resourceId_idx\" on \"oauthClientResource\" (\"resourceId\")",
    "create unique index IF NOT EXISTS \"oauthClientResource_clientId_resourceId_uidx\" on \"oauthClientResource\" (\"clientId\", \"resourceId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthRefreshToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" jsonb, \"requestedUserInfoClaims\" jsonb, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz not null, \"revoked\" timestamptz, \"rotatedAt\" timestamptz, \"rotationReplayResponse\" text, \"rotationReplayExpiresAt\" timestamptz, \"authTime\" timestamptz, \"confirmation\" jsonb, \"scopes\" jsonb not null)",
    "create index IF NOT EXISTS \"oauthRefreshToken_clientId_idx\" on \"oauthRefreshToken\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthRefreshToken_sessionId_idx\" on \"oauthRefreshToken\" (\"sessionId\")",
    "create index IF NOT EXISTS \"oauthRefreshToken_userId_idx\" on \"oauthRefreshToken\" (\"userId\")",
    "create index IF NOT EXISTS \"oauthRefreshToken_authorizationCodeId_idx\" on \"oauthRefreshToken\" (\"authorizationCodeId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthAccessToken\" (\"id\" text not null primary key, \"token\" text not null unique, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"sessionId\" text references \"session\" (\"id\") on delete set null, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"authorizationCodeId\" text, \"resources\" jsonb, \"requestedUserInfoClaims\" jsonb, \"refreshId\" text references \"oauthRefreshToken\" (\"id\") on delete cascade, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz not null, \"revoked\" timestamptz, \"confirmation\" jsonb, \"scopes\" jsonb not null)",
    "create index IF NOT EXISTS \"oauthAccessToken_clientId_idx\" on \"oauthAccessToken\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_sessionId_idx\" on \"oauthAccessToken\" (\"sessionId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_userId_idx\" on \"oauthAccessToken\" (\"userId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_authorizationCodeId_idx\" on \"oauthAccessToken\" (\"authorizationCodeId\")",
    "create index IF NOT EXISTS \"oauthAccessToken_refreshId_idx\" on \"oauthAccessToken\" (\"refreshId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthConsent\" (\"id\" text not null primary key, \"clientId\" text not null references \"oauthClient\" (\"clientId\") on delete cascade, \"userId\" text references \"user\" (\"id\") on delete cascade, \"referenceId\" text, \"resources\" jsonb, \"requestedUserInfoClaims\" jsonb, \"scopes\" jsonb not null, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz not null)",
    "create index IF NOT EXISTS \"oauthConsent_clientId_idx\" on \"oauthConsent\" (\"clientId\")",
    "create index IF NOT EXISTS \"oauthConsent_userId_idx\" on \"oauthConsent\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"oauthClientAssertion\" (\"id\" text not null primary key, \"expiresAt\" timestamptz not null)",
    "CREATE TABLE IF NOT EXISTS \"rateLimit\" (\"id\" text not null primary key, \"key\" text not null unique, \"count\" integer not null, \"lastRequest\" bigint not null)",
];
pub async fn run_app_migrations(
    pool: &SqlxPool,
) -> Result<(), alibi::sqlx::sqlx::Error> {
    let statements = match pool.engine() {
        Engine::Sqlite => SQLITE_TABLES,
        Engine::Postgres => POSTGRES_TABLES,
    };
    pool.execute_batch(statements).await
}
