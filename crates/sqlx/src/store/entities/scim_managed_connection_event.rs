use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "scimManagedConnectionEvent")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionRecordId")]
    #[serde(rename = "connectionRecordId")]
    pub connection_record_id: String,
    #[sqlx(rename = "eventKey")]
    #[serde(rename = "eventKey")]
    pub event_key: String,
    pub sequence: i64,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub kind: String,
    #[sqlx(rename = "actorId")]
    #[serde(rename = "actorId")]
    pub actor_id: String,
    #[sqlx(rename = "credentialId")]
    #[serde(rename = "credentialId")]
    pub credential_id: Option<String>,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}
