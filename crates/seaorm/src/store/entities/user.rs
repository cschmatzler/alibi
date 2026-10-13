use crate::AuthEntity;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Serialize, DeriveEntityModel)]
#[auth(role = "user", secondary_storage)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub email: String,
    #[sea_orm(column_name = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    #[sea_orm(column_name = "displayUsername")]
    pub display_username: Option<String>,
    #[sea_orm(column_name = "twoFactorEnabled")]
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    #[sea_orm(column_name = "banReason")]
    pub ban_reason: Option<String>,
    #[sea_orm(column_name = "banExpires")]
    pub ban_expires: Option<DateTimeUtc>,
    #[sea_orm(column_name = "isAnonymous")]
    pub is_anonymous: Option<bool>,
    #[sea_orm(column_name = "phoneNumber")]
    pub phone_number: Option<String>,
    #[sea_orm(column_name = "phoneNumberVerified")]
    pub phone_number_verified: Option<bool>,
    #[sea_orm(column_name = "lastLoginMethod")]
    pub last_login_method: Option<String>,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
