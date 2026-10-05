use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "invitation")]
pub struct Model {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub team_id: Option<String>,
    pub status: String,
    pub inviter_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<&Model> for better_auth_core::Invitation {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            email: model.email.clone(),
            role: Some(model.role.clone()),
            team_id: model.team_id.clone(),
            status: better_auth_core::InvitationStatus::from(model.status.clone()),
            inviter_id: model.inviter_id.clone(),
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}
