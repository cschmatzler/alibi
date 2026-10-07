pub use crate::json_metadata::JsonMetadata;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "organization")]
pub struct Model {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<JsonMetadata>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Model> for alibi_core::Organization {
    fn from(model: &Model) -> Self {
        Self {
            additional_fields: Default::default(),
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
