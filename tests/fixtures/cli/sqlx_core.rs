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
pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
const SQLITE_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" integer not null, \"image\" text, \"createdAt\" date not null, \"updatedAt\" date not null)",
    "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" date not null, \"token\" text not null unique, \"createdAt\" date not null, \"updatedAt\" date not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade)",
    "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" date, \"refreshTokenExpiresAt\" date, \"scope\" text, \"password\" text, \"createdAt\" date not null, \"updatedAt\" date not null)",
    "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" date not null, \"createdAt\" date not null, \"updatedAt\" date not null)",
    "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
];
const POSTGRES_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" boolean not null, \"image\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null)",
    "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" timestamptz not null, \"token\" text not null unique, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade)",
    "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" timestamptz, \"refreshTokenExpiresAt\" timestamptz, \"scope\" text, \"password\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null)",
    "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
    "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null)",
    "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
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
