use crate::SqlxModel;
use alibi_core::types::TeamMember;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "team_member")]
pub struct Model {
    pub id: String,
    pub team_id: String,
    pub user_id: String,
    pub membership_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<Model> for TeamMember {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            team_id: model.team_id,
            user_id: model.user_id,
            membership_key: model.membership_key,
            created_at: model.created_at,
        }
    }
}
