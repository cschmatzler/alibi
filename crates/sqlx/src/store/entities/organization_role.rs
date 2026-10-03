use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "organization_role")]
pub struct Model {
    pub id: String,
    pub organization_id: String,
    pub role: String,
    pub permission: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl TryFrom<Model> for better_auth_core::types::OrganizationRole {
    type Error = better_auth_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            organization_id: model.organization_id,
            role: model.role,
            permission: model.permission.into(),
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
