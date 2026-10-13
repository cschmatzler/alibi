use crate::AuthEntity;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Serialize, sqlx::FromRow)]
#[auth(role = "user", table = "user", secondary_storage)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub email: String,
    #[sqlx(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
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
    pub ban_expires: Option<DateTime<Utc>>,
    #[sqlx(rename = "isAnonymous")]
    pub is_anonymous: Option<bool>,
    #[sqlx(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    #[sqlx(rename = "phoneNumberVerified")]
    pub phone_number_verified: Option<bool>,
    #[sqlx(rename = "lastLoginMethod")]
    pub last_login_method: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
