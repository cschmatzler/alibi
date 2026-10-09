use crate::SqlxModel;
use alibi_core::Member;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "member")]
pub struct Model {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl From<&Model> for Member {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            user_id: model.user_id.clone(),
            role: model.role.clone(),
            created_at: model.created_at,
        }
    }
}
