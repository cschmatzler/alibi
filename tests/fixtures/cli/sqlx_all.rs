use better_auth::AuthSchema;
use better_auth::sqlx::{Engine, SqlxPool};
pub mod user {
    #[derive(
        Clone,
        Debug,
        serde::Serialize,
        sqlx::FromRow,
        better_auth::sqlx::AuthEntity
    )]
    #[auth(role = "user", table = "users")]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub is_anonymous: Option<bool>,
        pub phone_number: Option<String>,
        pub phone_number_verified: Option<bool>,
        pub last_login_method: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: Option<bool>,
        pub role: Option<String>,
        pub banned: Option<bool>,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<chrono::DateTime<chrono::Utc>>,
        pub metadata: better_auth::sqlx::JsonMetadata,
    }
}
pub mod session {
    #[derive(
        Clone,
        Debug,
        serde::Serialize,
        sqlx::FromRow,
        better_auth::sqlx::AuthEntity
    )]
    #[auth(role = "session", table = "sessions")]
    pub struct Model {
        pub id: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub token: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub active: bool,
        pub active_team_id: Option<String>,
        pub impersonated_by: Option<String>,
        pub active_organization_id: Option<String>,
    }
}
pub mod account {
    #[derive(
        Clone,
        Debug,
        serde::Serialize,
        sqlx::FromRow,
        better_auth::sqlx::AuthEntity
    )]
    #[auth(role = "account", table = "accounts")]
    pub struct Model {
        pub id: String,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: String,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub refresh_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod verification {
    #[derive(
        Clone,
        Debug,
        serde::Serialize,
        sqlx::FromRow,
        better_auth::sqlx::AuthEntity
    )]
    #[auth(role = "verification", table = "verifications")]
    pub struct Model {
        pub id: String,
        pub identifier: String,
        pub value: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod wallet_address {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub user_id: String,
        pub address: String,
        pub chain_id: f64,
        pub is_primary: bool,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod jwk {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub public_key: String,
        pub private_key: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub alg: Option<String>,
        pub crv: Option<String>,
    }
}
pub mod team {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub name: String,
        pub organization_id: String,
        pub member_count: i64,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod team_member {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub team_id: String,
        pub user_id: String,
        pub membership_key: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod organization_role {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub organization_id: String,
        pub role: String,
        pub permission: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    }
}
pub mod two_factor {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub secret: String,
        pub backup_codes: String,
        pub user_id: String,
        pub verified: Option<bool>,
        pub failed_verification_count: Option<f64>,
        pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod device_code {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub device_code: String,
        pub user_code: String,
        pub user_id: Option<String>,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub status: String,
        pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
        pub polling_interval: Option<i64>,
        pub client_id: Option<String>,
        pub scope: Option<String>,
    }
}
pub mod organization {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        pub metadata: Option<better_auth::sqlx::JsonMetadata>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod member {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub organization_id: String,
        pub user_id: String,
        pub role: String,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod invitation {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub organization_id: String,
        pub email: String,
        pub role: String,
        pub team_id: Option<String>,
        pub status: String,
        pub inviter_id: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod api_key {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        pub start: Option<String>,
        pub prefix: Option<String>,
        #[sqlx(rename = "key")]
        pub key_hash: String,
        pub user_id: String,
        pub refill_interval: Option<f64>,
        pub refill_amount: Option<f64>,
        pub last_refill_at: Option<chrono::DateTime<chrono::Utc>>,
        pub enabled: bool,
        pub rate_limit_enabled: bool,
        pub rate_limit_time_window: Option<f64>,
        pub rate_limit_max: Option<f64>,
        pub request_count: Option<f64>,
        pub remaining: Option<f64>,
        pub last_request: Option<chrono::DateTime<chrono::Utc>>,
        pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub permissions: Option<String>,
        pub metadata: Option<String>,
    }
}
pub mod passkey {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        pub public_key: String,
        pub user_id: String,
        pub credential_id: String,
        pub counter: i64,
        pub device_type: String,
        pub backed_up: bool,
        pub transports: Option<String>,
        pub credential: String,
        pub aaguid: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
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
    "CREATE TABLE IF NOT EXISTS \"users\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"email\" TEXT, \"email_verified\" BOOLEAN NOT NULL, \"image\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL, \"is_anonymous\" BOOLEAN, \"phone_number\" TEXT, \"phone_number_verified\" BOOLEAN, \"last_login_method\" TEXT, \"username\" TEXT, \"display_username\" TEXT, \"two_factor_enabled\" BOOLEAN, \"role\" TEXT, \"banned\" BOOLEAN, \"ban_reason\" TEXT, \"ban_expires\" TEXT, \"metadata\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"sessions\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"expires_at\" TEXT NOT NULL, \"token\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL, \"ip_address\" TEXT, \"user_agent\" TEXT, \"user_id\" TEXT NOT NULL, \"active\" BOOLEAN NOT NULL, \"active_team_id\" TEXT, \"impersonated_by\" TEXT, \"active_organization_id\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"accounts\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"account_id\" TEXT NOT NULL, \"provider_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"access_token\" TEXT, \"refresh_token\" TEXT, \"id_token\" TEXT, \"access_token_expires_at\" TEXT, \"refresh_token_expires_at\" TEXT, \"scope\" TEXT, \"password\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"verifications\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"identifier\" TEXT NOT NULL, \"value\" TEXT NOT NULL, \"expires_at\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"wallet_address\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"user_id\" TEXT NOT NULL, \"address\" TEXT NOT NULL, \"chain_id\" REAL NOT NULL, \"is_primary\" BOOLEAN NOT NULL, \"created_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"jwks\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"public_key\" TEXT NOT NULL, \"private_key\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL, \"expires_at\" TEXT, \"alg\" TEXT, \"crv\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"team\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT NOT NULL, \"organization_id\" TEXT NOT NULL, \"member_count\" INTEGER NOT NULL, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"team_member\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"team_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"membership_key\" TEXT, \"created_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"organization_role\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"organization_id\" TEXT NOT NULL, \"role\" TEXT NOT NULL, \"permission\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"two_factor\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"secret\" TEXT NOT NULL, \"backup_codes\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"verified\" BOOLEAN, \"failed_verification_count\" REAL, \"locked_until\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"device_code\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"device_code\" TEXT NOT NULL, \"user_code\" TEXT NOT NULL, \"user_id\" TEXT, \"expires_at\" TEXT NOT NULL, \"status\" TEXT NOT NULL, \"last_polled_at\" TEXT, \"polling_interval\" INTEGER, \"client_id\" TEXT, \"scope\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"organization\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT NOT NULL, \"slug\" TEXT NOT NULL, \"logo\" TEXT, \"metadata\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"member\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"organization_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"role\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"invitation\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"organization_id\" TEXT NOT NULL, \"email\" TEXT NOT NULL, \"role\" TEXT NOT NULL, \"team_id\" TEXT, \"status\" TEXT NOT NULL, \"inviter_id\" TEXT NOT NULL, \"expires_at\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"api_keys\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"start\" TEXT, \"prefix\" TEXT, \"key\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"refill_interval\" REAL, \"refill_amount\" REAL, \"last_refill_at\" TEXT, \"enabled\" BOOLEAN NOT NULL, \"rate_limit_enabled\" BOOLEAN NOT NULL, \"rate_limit_time_window\" REAL, \"rate_limit_max\" REAL, \"request_count\" REAL, \"remaining\" REAL, \"last_request\" TEXT, \"expires_at\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL, \"permissions\" TEXT, \"metadata\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"passkeys\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"public_key\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"credential_id\" TEXT NOT NULL, \"counter\" INTEGER NOT NULL, \"device_type\" TEXT NOT NULL, \"backed_up\" BOOLEAN NOT NULL, \"transports\" TEXT, \"credential\" TEXT NOT NULL, \"aaguid\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
];
const POSTGRES_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"users\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"email\" TEXT, \"email_verified\" BOOLEAN NOT NULL, \"image\" TEXT, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL, \"is_anonymous\" BOOLEAN, \"phone_number\" TEXT, \"phone_number_verified\" BOOLEAN, \"last_login_method\" TEXT, \"username\" TEXT, \"display_username\" TEXT, \"two_factor_enabled\" BOOLEAN, \"role\" TEXT, \"banned\" BOOLEAN, \"ban_reason\" TEXT, \"ban_expires\" TIMESTAMPTZ, \"metadata\" JSONB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"sessions\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"expires_at\" TIMESTAMPTZ NOT NULL, \"token\" TEXT NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL, \"ip_address\" TEXT, \"user_agent\" TEXT, \"user_id\" TEXT NOT NULL, \"active\" BOOLEAN NOT NULL, \"active_team_id\" TEXT, \"impersonated_by\" TEXT, \"active_organization_id\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"accounts\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"account_id\" TEXT NOT NULL, \"provider_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"access_token\" TEXT, \"refresh_token\" TEXT, \"id_token\" TEXT, \"access_token_expires_at\" TIMESTAMPTZ, \"refresh_token_expires_at\" TIMESTAMPTZ, \"scope\" TEXT, \"password\" TEXT, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"verifications\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"identifier\" TEXT NOT NULL, \"value\" TEXT NOT NULL, \"expires_at\" TIMESTAMPTZ NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"wallet_address\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"user_id\" TEXT NOT NULL, \"address\" TEXT NOT NULL, \"chain_id\" DOUBLE PRECISION NOT NULL, \"is_primary\" BOOLEAN NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"jwks\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"public_key\" TEXT NOT NULL, \"private_key\" TEXT NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"expires_at\" TIMESTAMPTZ, \"alg\" TEXT, \"crv\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"team\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT NOT NULL, \"organization_id\" TEXT NOT NULL, \"member_count\" BIGINT NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ)",
    "CREATE TABLE IF NOT EXISTS \"team_member\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"team_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"membership_key\" TEXT, \"created_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"organization_role\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"organization_id\" TEXT NOT NULL, \"role\" TEXT NOT NULL, \"permission\" TEXT NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ)",
    "CREATE TABLE IF NOT EXISTS \"two_factor\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"secret\" TEXT NOT NULL, \"backup_codes\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"verified\" BOOLEAN, \"failed_verification_count\" DOUBLE PRECISION, \"locked_until\" TIMESTAMPTZ, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"device_code\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"device_code\" TEXT NOT NULL, \"user_code\" TEXT NOT NULL, \"user_id\" TEXT, \"expires_at\" TIMESTAMPTZ NOT NULL, \"status\" TEXT NOT NULL, \"last_polled_at\" TIMESTAMPTZ, \"polling_interval\" BIGINT, \"client_id\" TEXT, \"scope\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"organization\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT NOT NULL, \"slug\" TEXT NOT NULL, \"logo\" TEXT, \"metadata\" JSONB, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"member\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"organization_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"role\" TEXT NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"invitation\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"organization_id\" TEXT NOT NULL, \"email\" TEXT NOT NULL, \"role\" TEXT NOT NULL, \"team_id\" TEXT, \"status\" TEXT NOT NULL, \"inviter_id\" TEXT NOT NULL, \"expires_at\" TIMESTAMPTZ NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"api_keys\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"start\" TEXT, \"prefix\" TEXT, \"key\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"refill_interval\" DOUBLE PRECISION, \"refill_amount\" DOUBLE PRECISION, \"last_refill_at\" TIMESTAMPTZ, \"enabled\" BOOLEAN NOT NULL, \"rate_limit_enabled\" BOOLEAN NOT NULL, \"rate_limit_time_window\" DOUBLE PRECISION, \"rate_limit_max\" DOUBLE PRECISION, \"request_count\" DOUBLE PRECISION, \"remaining\" DOUBLE PRECISION, \"last_request\" TIMESTAMPTZ, \"expires_at\" TIMESTAMPTZ, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL, \"permissions\" TEXT, \"metadata\" TEXT)",
    "CREATE TABLE IF NOT EXISTS \"passkeys\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"public_key\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"credential_id\" TEXT NOT NULL, \"counter\" BIGINT NOT NULL, \"device_type\" TEXT NOT NULL, \"backed_up\" BOOLEAN NOT NULL, \"transports\" TEXT, \"credential\" TEXT NOT NULL, \"aaguid\" TEXT, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
];
pub async fn run_app_migrations(
    pool: &SqlxPool,
) -> Result<(), better_auth::sqlx::sqlx::Error> {
    let statements = match pool.engine() {
        Engine::Sqlite => SQLITE_TABLES,
        Engine::Postgres => POSTGRES_TABLES,
    };
    pool.execute_batch(statements).await
}
