use chrono::{DateTime, Utc};

bundled_model! {
    table = "organization_role", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub organization_id: String = "organization_id",
        pub role: String = "role",
        pub permission: String = "permission",
        pub created_at: DateTime<Utc> = "created_at",
        pub updated_at: Option<DateTime<Utc>> = "updated_at",
    }
}

impl TryFrom<Model> for better_auth_core::types::OrganizationRole {
    type Error = better_auth_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            organization_id: model.organization_id,
            role: model.role,
            permission: serde_json::from_str(&model.permission)?,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
