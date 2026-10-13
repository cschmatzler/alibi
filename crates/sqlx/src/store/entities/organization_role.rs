use crate::SqlxModel;
use alibi_core::AuthError;
use alibi_core::types::OrganizationRole;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "organizationRole")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "organizationId")]
    pub organization_id: String,
    pub role: String,
    pub permission: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl TryFrom<Model> for OrganizationRole {
    type Error = AuthError;
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
