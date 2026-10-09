use crate::AuthEntity;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
#[auth(role = "account", table = "accounts")]
pub struct Model {
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
}
