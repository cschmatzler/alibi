//! Actual user, session and account columns with canonical accessor names.
//!
//! Each model derives the selected backend's `AuthEntity`; both read the same
//! physical tables, created by `additional_fields_fixture`.
pub(super) mod application_user {
    #[cfg(feature = "seaorm")]
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm",
        derive(alibi::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "app_user")
    )]
    #[cfg_attr(
        not(feature = "seaorm"),
        derive(alibi::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "app_user")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "user")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "display_name"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "display_name"))]
        pub name: Option<String>,
        pub email: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "emailVerified"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "emailVerified"))]
        pub email_verified: bool,
        pub image: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "createdAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "createdAt"))]
        pub created_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "updatedAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "updatedAt"))]
        pub updated_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "user_label"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "user_label"))]
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
        pub readonly: Option<String>,
        pub role: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(default_value = "physical-private"))]
        #[serde(rename = "private_column")]
        pub private_column: String,
    }
    #[cfg(feature = "seaorm")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[cfg(feature = "seaorm")]
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) mod application_session {
    #[cfg(feature = "seaorm")]
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm",
        derive(alibi::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "app_session")
    )]
    #[cfg_attr(
        not(feature = "seaorm"),
        derive(alibi::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "app_session")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "session")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "expiresAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "expiresAt"))]
        pub expires_at: DateTime<Utc>,
        pub token: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "createdAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "createdAt"))]
        pub created_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "updatedAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "updatedAt"))]
        pub updated_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "ipAddress"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "ipAddress"))]
        pub ip_address: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "userAgent"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "userAgent"))]
        pub user_agent: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "userId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "userId"))]
        pub user_id: String,
        #[serde(skip)]
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
    }
    #[cfg(feature = "seaorm")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[cfg(feature = "seaorm")]
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) mod application_account {
    #[cfg(feature = "seaorm")]
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm",
        derive(alibi::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "app_account")
    )]
    #[cfg_attr(
        not(feature = "seaorm"),
        derive(alibi::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "app_account")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "account")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "accountId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "accountId"))]
        pub account_id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "providerId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "providerId"))]
        pub provider_id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "userId"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "userId"))]
        pub user_id: String,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "accessToken"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "accessToken"))]
        pub access_token: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "refreshToken"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "refreshToken"))]
        pub refresh_token: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "idToken"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "idToken"))]
        pub id_token: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "accessTokenExpiresAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "accessTokenExpiresAt"))]
        pub access_token_expires_at: Option<DateTime<Utc>>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "refreshTokenExpiresAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "refreshTokenExpiresAt"))]
        pub refresh_token_expires_at: Option<DateTime<Utc>>,
        pub scope: Option<String>,
        pub password: Option<String>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "createdAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "createdAt"))]
        pub created_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm", sea_orm(column_name = "updatedAt"))]
        #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "updatedAt"))]
        pub updated_at: DateTime<Utc>,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
    }
    #[cfg(feature = "seaorm")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[cfg(feature = "seaorm")]
    impl ActiveModelBehavior for ActiveModel {}
}

/// The physical tables behind these models.
pub(super) const TABLES: [&str; 4] = [
    r#"CREATE TABLE "app_user" ( "id" varchar NOT NULL PRIMARY KEY, "display_name" varchar, "email" varchar, "emailVerified" boolean NOT NULL, "image" varchar, "createdAt" timestamp_with_timezone_text NOT NULL, "updatedAt" timestamp_with_timezone_text NOT NULL, "user_label" varchar, "hidden" varchar, "omitted" varchar, "readonly" varchar, "role" varchar, "private_column" varchar NOT NULL DEFAULT 'physical-private' )"#,
    r#"CREATE TABLE "app_session" ( "id" varchar NOT NULL PRIMARY KEY, "expiresAt" timestamp_with_timezone_text NOT NULL, "token" varchar NOT NULL, "createdAt" timestamp_with_timezone_text NOT NULL, "updatedAt" timestamp_with_timezone_text NOT NULL, "ipAddress" varchar, "userAgent" varchar, "userId" varchar NOT NULL, "label" varchar, "hidden" varchar, "omitted" varchar )"#,
    r#"CREATE TABLE "app_account" ( "id" varchar NOT NULL PRIMARY KEY, "accountId" varchar NOT NULL, "providerId" varchar NOT NULL, "userId" varchar NOT NULL, "accessToken" varchar, "refreshToken" varchar, "idToken" varchar, "accessTokenExpiresAt" timestamp_with_timezone_text, "refreshTokenExpiresAt" timestamp_with_timezone_text, "scope" varchar, "password" varchar, "createdAt" timestamp_with_timezone_text NOT NULL, "updatedAt" timestamp_with_timezone_text NOT NULL, "label" varchar, "hidden" varchar, "omitted" varchar )"#,
    r#"CREATE TABLE "verification" ( "id" varchar NOT NULL PRIMARY KEY, "identifier" varchar NOT NULL, "value" varchar NOT NULL, "expiresAt" timestamp_with_timezone_text NOT NULL, "createdAt" timestamp_with_timezone_text NOT NULL, "updatedAt" timestamp_with_timezone_text NOT NULL )"#,
];

pub(super) struct ApplicationSchema;
impl alibi::AuthSchema for ApplicationSchema {
    type User = application_user::Model;
    type Session = application_session::Model;
    type Account = application_account::Model;
    type Verification = crate::backend::entities::verification::Model;
}
