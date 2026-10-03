use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(crate::AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
#[auth(role = "verification", table = "verifications")]
pub struct Model {
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
