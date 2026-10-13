use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "oauthClientResource")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sqlx(rename = "resourceId")]
    #[serde(rename = "resourceId")]
    pub resource_id: String,
    #[serde(rename = "metadata")]
    pub metadata: Option<JsonMetadata>,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
}

impl TryFrom<Model> for alibi_core::store::OAuthClientResource {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            client_id: model.client_id,
            resource_id: model.resource_id,
            metadata: model
                .metadata
                .map_or(serde_json::Value::Null, |value| (*value).clone()),
            created_at: model.created_at,
        })
    }
}
