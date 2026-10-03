//! Real application user columns for anonymous callback contracts.
#[cfg(feature = "seaorm")]
use better_auth::seaorm::JsonMetadata;
#[cfg(feature = "seaorm")]
use better_auth::seaorm::sea_orm::{self, entity::prelude::*};
#[cfg(not(feature = "seaorm"))]
use better_auth::sqlx::JsonMetadata;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[cfg_attr(
    feature = "seaorm",
    derive(better_auth::seaorm::AuthEntity, DeriveEntityModel),
    sea_orm(table_name = "users")
)]
#[cfg_attr(
    not(feature = "seaorm"),
    derive(better_auth::sqlx::AuthEntity, sqlx::FromRow),
    auth(table = "users")
)]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[auth(role = "user", secondary_storage)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_type = "JsonBinary"))]
    pub metadata: JsonMetadata,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub last_login_method: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "cargo_label"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "cargo_label"))]
    pub cargo_label: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "cargo_hidden"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "cargo_hidden"))]
    pub cargo_hidden: Option<String>,
}

#[cfg(feature = "seaorm")]
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
#[cfg(feature = "seaorm")]
impl ActiveModelBehavior for ActiveModel {}
pub(crate) struct ApplicationSchema;
impl better_auth::AuthSchema for ApplicationSchema {
    type User = Model;
    type Session = crate::backend::entities::session::Model;
    type Account = crate::backend::entities::account::Model;
    type Verification = crate::backend::entities::verification::Model;
}
