use crate::SqlxModel;
use alibi_core::types::TeamMember;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "teamMember")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "teamId")]
    pub team_id: String,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "membershipKey")]
    pub membership_key: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
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
