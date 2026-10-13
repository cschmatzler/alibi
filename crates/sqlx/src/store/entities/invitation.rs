use crate::SqlxModel;
use alibi_core::Invitation;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "invitation")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "organizationId")]
    pub organization_id: String,
    pub email: String,
    pub role: Option<String>,
    #[sqlx(rename = "teamId")]
    pub team_id: Option<String>,
    pub status: String,
    #[sqlx(rename = "inviterId")]
    pub inviter_id: String,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl From<&Model> for Invitation {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            email: model.email.clone(),
            role: model.role.clone(),
            team_id: model.team_id.clone(),
            status: alibi_core::InvitationStatus::from(model.status.clone()),
            inviter_id: model.inviter_id.clone(),
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}
