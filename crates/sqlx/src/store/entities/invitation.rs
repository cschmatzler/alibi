use chrono::{DateTime, Utc};

bundled_model! {
    table = "invitation", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub organization_id: String = "organization_id",
        pub email: String = "email",
        pub role: String = "role",
        pub team_id: Option<String> = "team_id",
        pub status: String = "status",
        pub inviter_id: String = "inviter_id",
        pub expires_at: DateTime<Utc> = "expires_at",
        pub created_at: DateTime<Utc> = "created_at",
    }
}

impl From<&Model> for better_auth_core::Invitation {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            email: model.email.clone(),
            role: model.role.clone(),
            team_id: model.team_id.clone(),
            status: better_auth_core::InvitationStatus::from(model.status.clone()),
            inviter_id: model.inviter_id.clone(),
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}
