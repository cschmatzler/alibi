use chrono::{DateTime, Utc};

bundled_model! {
    table = "team_member", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub team_id: String = "team_id",
        pub user_id: String = "user_id",
        pub membership_key: Option<String> = "membership_key",
        pub created_at: DateTime<Utc> = "created_at",
    }
}

impl From<Model> for better_auth_core::types::TeamMember {
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
