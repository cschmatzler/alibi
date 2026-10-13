use alibi::AuthSchema;
use alibi::seaorm::sea_orm;
use alibi::seaorm::sea_orm::entity::prelude::*;
use alibi::seaorm::sea_orm::ConnectionTrait;
use alibi::seaorm::{AuthEntity, DatabaseConnection};
mod user {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub email: String,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod session {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "session")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        pub token: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_name = "ipAddress")]
        pub ip_address: Option<String>,
        #[sea_orm(column_name = "userAgent")]
        pub user_agent: Option<String>,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod account {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "account")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "accountId")]
        pub account_id: String,
        #[sea_orm(column_name = "providerId")]
        pub provider_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        #[sea_orm(column_name = "accessToken")]
        pub access_token: Option<String>,
        #[sea_orm(column_name = "refreshToken")]
        pub refresh_token: Option<String>,
        #[sea_orm(column_name = "idToken")]
        pub id_token: Option<String>,
        #[sea_orm(column_name = "accessTokenExpiresAt")]
        pub access_token_expires_at: Option<DateTimeUtc>,
        #[sea_orm(column_name = "refreshTokenExpiresAt")]
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
mod verification {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "verification")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        pub value: String,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
pub async fn run_app_migrations(
    database: &DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    let statements: &[&str] = match database.get_database_backend() {
        sea_orm::DbBackend::Sqlite => {
            &[
                "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" integer not null, \"image\" text, \"createdAt\" date not null, \"updatedAt\" date not null)",
                "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" date not null, \"token\" text not null unique, \"createdAt\" date not null, \"updatedAt\" date not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade)",
                "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" date, \"refreshTokenExpiresAt\" date, \"scope\" text, \"password\" text, \"createdAt\" date not null, \"updatedAt\" date not null)",
                "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" date not null, \"createdAt\" date not null, \"updatedAt\" date not null)",
                "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
            ]
        }
        sea_orm::DbBackend::Postgres => {
            &[
                "CREATE TABLE IF NOT EXISTS \"user\" (\"id\" text not null primary key, \"name\" text not null, \"email\" text not null unique, \"emailVerified\" boolean not null, \"image\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null)",
                "CREATE TABLE IF NOT EXISTS \"session\" (\"id\" text not null primary key, \"expiresAt\" timestamptz not null, \"token\" text not null unique, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null, \"ipAddress\" text, \"userAgent\" text, \"userId\" text not null references \"user\" (\"id\") on delete cascade)",
                "create index IF NOT EXISTS \"session_userId_idx\" on \"session\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"account\" (\"id\" text not null primary key, \"accountId\" text not null, \"providerId\" text not null, \"userId\" text not null references \"user\" (\"id\") on delete cascade, \"accessToken\" text, \"refreshToken\" text, \"idToken\" text, \"accessTokenExpiresAt\" timestamptz, \"refreshTokenExpiresAt\" timestamptz, \"scope\" text, \"password\" text, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz not null)",
                "create index IF NOT EXISTS \"account_userId_idx\" on \"account\" (\"userId\")",
                "CREATE TABLE IF NOT EXISTS \"verification\" (\"id\" text not null primary key, \"identifier\" text not null, \"value\" text not null, \"expiresAt\" timestamptz not null, \"createdAt\" timestamptz default CURRENT_TIMESTAMP not null, \"updatedAt\" timestamptz default CURRENT_TIMESTAMP not null)",
                "create index IF NOT EXISTS \"verification_identifier_idx\" on \"verification\" (\"identifier\")",
            ]
        }
        _ => {
            return Err(
                sea_orm::DbErr::Custom(
                    "Generated migrations support SQLite and PostgreSQL".into(),
                ),
            );
        }
    };
    for statement in statements {
        let _ = database.execute_unprepared(statement).await?;
    }
    Ok(())
}
