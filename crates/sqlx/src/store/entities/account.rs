use crate::AuthEntity;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
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
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
