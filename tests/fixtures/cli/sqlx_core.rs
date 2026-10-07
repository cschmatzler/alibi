use alibi::AuthSchema;
use alibi::sqlx::{Engine, SqlxPool};
pub mod user {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "user", table = "users")]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
pub mod session {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
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
    }
}
pub mod account {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
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
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
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
pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
const SQLITE_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"users\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"email\" TEXT, \"email_verified\" BOOLEAN NOT NULL, \"image\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"sessions\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"expires_at\" TEXT NOT NULL, \"token\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL, \"ip_address\" TEXT, \"user_agent\" TEXT, \"user_id\" TEXT NOT NULL, \"active\" BOOLEAN NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"accounts\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"account_id\" TEXT NOT NULL, \"provider_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"access_token\" TEXT, \"refresh_token\" TEXT, \"id_token\" TEXT, \"access_token_expires_at\" TEXT, \"refresh_token_expires_at\" TEXT, \"scope\" TEXT, \"password\" TEXT, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"verifications\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"identifier\" TEXT NOT NULL, \"value\" TEXT NOT NULL, \"expires_at\" TEXT NOT NULL, \"created_at\" TEXT NOT NULL, \"updated_at\" TEXT NOT NULL)",
];
const POSTGRES_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"users\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"email\" TEXT, \"email_verified\" BOOLEAN NOT NULL, \"image\" TEXT, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"sessions\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"expires_at\" TIMESTAMPTZ NOT NULL, \"token\" TEXT NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL, \"ip_address\" TEXT, \"user_agent\" TEXT, \"user_id\" TEXT NOT NULL, \"active\" BOOLEAN NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"accounts\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"account_id\" TEXT NOT NULL, \"provider_id\" TEXT NOT NULL, \"user_id\" TEXT NOT NULL, \"access_token\" TEXT, \"refresh_token\" TEXT, \"id_token\" TEXT, \"access_token_expires_at\" TIMESTAMPTZ, \"refresh_token_expires_at\" TIMESTAMPTZ, \"scope\" TEXT, \"password\" TEXT, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE IF NOT EXISTS \"verifications\" (\"id\" TEXT NOT NULL PRIMARY KEY, \"identifier\" TEXT NOT NULL, \"value\" TEXT NOT NULL, \"expires_at\" TIMESTAMPTZ NOT NULL, \"created_at\" TIMESTAMPTZ NOT NULL, \"updated_at\" TIMESTAMPTZ NOT NULL)",
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
