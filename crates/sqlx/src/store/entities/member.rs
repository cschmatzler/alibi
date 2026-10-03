use chrono::{DateTime, Utc};

bundled_model! {
    table = "member", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub organization_id: String = "organization_id",
        pub user_id: String = "user_id",
        pub role: String = "role",
        pub created_at: DateTime<Utc> = "created_at",
    }
}

impl From<&Model> for better_auth_core::Member {
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
