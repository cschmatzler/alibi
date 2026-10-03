use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(crate::AuthEntity, Clone, Debug, PartialEq, Serialize, sqlx::FromRow)]
#[auth(role = "user", table = "users", secondary_storage)]
pub struct Model {
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
    pub metadata: crate::JsonMetadata,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub last_login_method: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
