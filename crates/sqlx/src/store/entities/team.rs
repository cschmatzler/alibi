use chrono::{DateTime, Utc};

bundled_model! {
    table = "team", primary_key = "id";
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Model {
        pub id: String = "id",
        pub name: String = "name",
        pub organization_id: String = "organization_id",
        pub member_count: i64 = "member_count",
        pub created_at: DateTime<Utc> = "created_at",
        pub updated_at: Option<DateTime<Utc>> = "updated_at",
    }
}

impl From<Model> for better_auth_core::types::Team {
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
