use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow, SqlxModel)]
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
