//! Real application user columns for anonymous callback contracts.
#[cfg(feature = "seaorm")]
use alibi::seaorm::JsonMetadata;
#[cfg(feature = "seaorm")]
use alibi::seaorm::sea_orm::{self, entity::prelude::*};
#[cfg(not(feature = "seaorm"))]
use alibi::sqlx::JsonMetadata;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[cfg_attr(
    feature = "seaorm",
    derive(alibi::seaorm::AuthEntity, DeriveEntityModel),
    sea_orm(table_name = "user")
)]
#[cfg_attr(
    not(feature = "seaorm"),
    derive(alibi::sqlx::AuthEntity, sqlx::FromRow),
    auth(table = "user")
)]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[auth(role = "user", secondary_storage)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[cfg_attr(feature = "seaorm", sea_orm(primary_key, auto_increment = false))]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "emailVerified"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "emailVerified"))]
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "displayUsername"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "displayUsername"))]
    pub display_username: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "twoFactorEnabled"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "twoFactorEnabled"))]
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "banReason"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "banReason"))]
    pub ban_reason: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "banExpires"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "banExpires"))]
    pub ban_expires: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_type = "JsonBinary"))]
    pub metadata: JsonMetadata,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "isAnonymous"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "isAnonymous"))]
    pub is_anonymous: Option<bool>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "phoneNumber"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "phoneNumber"))]
    pub phone_number: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "phoneNumberVerified"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "phoneNumberVerified"))]
    pub phone_number_verified: Option<bool>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "lastLoginMethod"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "lastLoginMethod"))]
    pub last_login_method: Option<String>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "createdAt"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "createdAt"))]
    pub created_at: DateTime<Utc>,
    #[cfg_attr(feature = "seaorm", sea_orm(column_name = "updatedAt"))]
    #[cfg_attr(not(feature = "seaorm"), sqlx(rename = "updatedAt"))]
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
impl alibi::AuthSchema for ApplicationSchema {
    type User = Model;
    type Session = crate::backend::entities::session::Model;
    type Account = crate::backend::entities::account::Model;
    type Verification = crate::backend::entities::verification::Model;
}
