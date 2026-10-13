use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "oauth_resource")]
pub struct Model {
    pub id: String,
    pub identifier: String,
    pub metadata: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl TryFrom<Model> for alibi_core::store::OAuthResource {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            identifier: model.identifier,
            metadata: serde_json::from_str(&model.metadata)?,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
