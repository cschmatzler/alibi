use crate::AuthEntity;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
#[auth(role = "verification", table = "verification")]
pub struct Model {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
