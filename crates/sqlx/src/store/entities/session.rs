use crate::AuthEntity;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, sqlx::FromRow)]
#[auth(role = "session", table = "session", secondary_storage)]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[sqlx(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[sqlx(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "impersonatedBy")]
    pub impersonated_by: Option<String>,
    #[sqlx(rename = "activeOrganizationId")]
    pub active_organization_id: Option<String>,
    #[sqlx(rename = "activeTeamId")]
    pub active_team_id: Option<String>,
}
