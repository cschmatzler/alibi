use crate::AuthEntity;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
#[auth(role = "session", table = "sessions", secondary_storage)]
pub struct Model {
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
    pub active: bool,
}
