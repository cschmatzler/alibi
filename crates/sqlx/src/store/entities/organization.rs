pub use crate::json_metadata::JsonMetadata;
use chrono::{DateTime, Utc};

bundled_model! {
    table = "organization", primary_key = "id";
    #[derive(Clone, Debug, PartialEq)]
    pub struct Model {
        pub id: String = "id",
        pub name: String = "name",
        pub slug: String = "slug",
        pub logo: Option<String> = "logo",
        pub metadata: Option<JsonMetadata> = "metadata",
        pub created_at: DateTime<Utc> = "created_at",
        pub updated_at: DateTime<Utc> = "updated_at",
    }
}

impl From<&Model> for better_auth_core::Organization {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            slug: model.slug.clone(),
            logo: model.logo.clone(),
            metadata: model.metadata.as_ref().map(|metadata| (**metadata).clone()),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}
