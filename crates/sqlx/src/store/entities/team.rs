use crate::SqlxModel;
use alibi_core::types::Team;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "team")]
pub struct Model {
    pub id: String,
    pub name: String,
    #[sqlx(rename = "organizationId")]
    pub organization_id: String,
    #[sqlx(rename = "memberCount")]
    pub member_count: i64,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl From<Model> for Team {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            organization_id: model.organization_id,
            member_count: model.member_count,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}
