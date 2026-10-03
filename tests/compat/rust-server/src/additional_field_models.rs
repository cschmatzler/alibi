//! Actual user, session and account columns with canonical accessor names.
//!
//! Each model derives the selected backend's `AuthEntity`; both read the same
//! physical tables, created by `additional_fields_fixture`.
pub(super) mod application_user {
    #[cfg(feature = "seaorm2")]
    use better_auth::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm2",
        derive(better_auth::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "app_user")
    )]
    #[cfg_attr(
        not(feature = "seaorm2"),
        derive(better_auth::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "app_user")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "user")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[cfg_attr(feature = "seaorm2", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        #[cfg_attr(feature = "seaorm2", sea_orm(column_name = "display_name"))]
        #[cfg_attr(not(feature = "seaorm2"), sqlx(rename = "display_name"))]
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        #[cfg_attr(feature = "seaorm2", sea_orm(column_name = "user_label"))]
        #[cfg_attr(not(feature = "seaorm2"), sqlx(rename = "user_label"))]
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
        pub readonly: Option<String>,
        pub role: Option<String>,
        #[cfg_attr(feature = "seaorm2", sea_orm(default_value = "physical-private"))]
        #[serde(rename = "private_column")]
        pub private_column: String,
    }
    #[cfg(feature = "seaorm2")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[cfg(feature = "seaorm2")]
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) mod application_session {
    #[cfg(feature = "seaorm2")]
    use better_auth::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm2",
        derive(better_auth::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "app_session")
    )]
    #[cfg_attr(
        not(feature = "seaorm2"),
        derive(better_auth::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "app_session")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "session")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[cfg_attr(feature = "seaorm2", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        pub expires_at: DateTime<Utc>,
        pub token: String,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        #[serde(skip)]
        pub active: bool,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
    }
    #[cfg(feature = "seaorm2")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[cfg(feature = "seaorm2")]
    impl ActiveModelBehavior for ActiveModel {}
}
pub(super) mod application_account {
    #[cfg(feature = "seaorm2")]
    use better_auth::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    #[cfg_attr(
        feature = "seaorm2",
        derive(better_auth::seaorm::AuthEntity, DeriveEntityModel),
        sea_orm(table_name = "app_account")
    )]
    #[cfg_attr(
        not(feature = "seaorm2"),
        derive(better_auth::sqlx::AuthEntity, sqlx::FromRow),
        auth(table = "app_account")
    )]
    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[auth(role = "account")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[cfg_attr(feature = "seaorm2", sea_orm(primary_key, auto_increment = false))]
        pub id: String,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: String,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTime<Utc>>,
        pub refresh_token_expires_at: Option<DateTime<Utc>>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub omitted: Option<String>,
    }
    #[cfg(feature = "seaorm2")]
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    #[cfg(feature = "seaorm2")]
    impl ActiveModelBehavior for ActiveModel {}
}

/// The physical tables behind these models.
pub(super) const TABLES: [&str; 4] = [
    r#"CREATE TABLE "app_user" ( "id" varchar NOT NULL PRIMARY KEY, "display_name" varchar, "email" varchar, "email_verified" boolean NOT NULL, "image" varchar, "created_at" timestamp_with_timezone_text NOT NULL, "updated_at" timestamp_with_timezone_text NOT NULL, "user_label" varchar, "hidden" varchar, "omitted" varchar, "readonly" varchar, "role" varchar, "private_column" varchar NOT NULL DEFAULT 'physical-private' )"#,
    r#"CREATE TABLE "app_session" ( "id" varchar NOT NULL PRIMARY KEY, "expires_at" timestamp_with_timezone_text NOT NULL, "token" varchar NOT NULL, "created_at" timestamp_with_timezone_text NOT NULL, "updated_at" timestamp_with_timezone_text NOT NULL, "ip_address" varchar, "user_agent" varchar, "user_id" varchar NOT NULL, "active" boolean NOT NULL, "label" varchar, "hidden" varchar, "omitted" varchar )"#,
    r#"CREATE TABLE "app_account" ( "id" varchar NOT NULL PRIMARY KEY, "account_id" varchar NOT NULL, "provider_id" varchar NOT NULL, "user_id" varchar NOT NULL, "access_token" varchar, "refresh_token" varchar, "id_token" varchar, "access_token_expires_at" timestamp_with_timezone_text, "refresh_token_expires_at" timestamp_with_timezone_text, "scope" varchar, "password" varchar, "created_at" timestamp_with_timezone_text NOT NULL, "updated_at" timestamp_with_timezone_text NOT NULL, "label" varchar, "hidden" varchar, "omitted" varchar )"#,
    r#"CREATE TABLE "verifications" ( "id" varchar NOT NULL PRIMARY KEY, "identifier" varchar NOT NULL, "value" varchar NOT NULL, "expires_at" timestamp_with_timezone_text NOT NULL, "created_at" timestamp_with_timezone_text NOT NULL, "updated_at" timestamp_with_timezone_text NOT NULL )"#,
];

pub(super) struct ApplicationSchema;
impl better_auth::AuthSchema for ApplicationSchema {
    type User = application_user::Model;
    type Session = application_session::Model;
    type Account = application_account::Model;
    type Verification = crate::backend::entities::verification::Model;
}
