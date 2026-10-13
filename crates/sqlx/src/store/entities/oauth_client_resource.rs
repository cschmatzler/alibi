use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "oauth_client_resource")]
pub struct Model {
    pub id: String,
    pub client_id: String,
    pub resource_id: String,
    pub metadata: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}
impl TryFrom<Model> for alibi_core::store::OAuthClientResource {
    type Error = alibi_core::AuthError;
    fn try_from(row: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            client_id: row.client_id,
            resource_id: row.resource_id,
            metadata: row
                .metadata
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
            created_at: row.created_at,
        })
    }
}
