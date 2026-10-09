use crate::SqlxModel;
use alibi_core::types::Team;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "team")]
pub struct Model {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
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
