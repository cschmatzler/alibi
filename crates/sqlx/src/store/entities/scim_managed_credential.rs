use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "scimManagedCredential")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionRecordId")]
    #[serde(rename = "connectionRecordId")]
    pub connection_record_id: String,
    #[sqlx(rename = "credentialId")]
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[sqlx(rename = "tokenDigest")]
    #[serde(rename = "tokenDigest")]
    pub token_digest: String,
    #[sqlx(rename = "hashVersion")]
    #[serde(rename = "hashVersion")]
    pub hash_version: String,
    #[sqlx(rename = "activeSlotKey")]
    #[serde(rename = "activeSlotKey")]
    pub active_slot_key: String,
    pub status: String,
    #[sqlx(rename = "serializedScopes")]
    #[serde(rename = "serializedScopes")]
    pub serialized_scopes: String,
    #[sqlx(rename = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "createdBy")]
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[sqlx(rename = "lastUsedAt")]
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "revokedAt")]
    #[serde(rename = "revokedAt")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "revokedBy")]
    #[serde(rename = "revokedBy")]
    pub revoked_by: Option<String>,
    #[sqlx(rename = "decommissionedAt")]
    #[serde(rename = "decommissionedAt")]
    pub decommissioned_at: Option<DateTime<Utc>>,
}

impl From<Model> for alibi_core::store::ScimManagedCredential {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            connection_record_id: row.connection_record_id,
            credential_id: row.credential_id,
            token_digest: row.token_digest,
            hash_version: row.hash_version,
            active_slot_key: row.active_slot_key,
            status: row.status,
            serialized_scopes: row.serialized_scopes,
            expires_at: row.expires_at,
            created_at: row.created_at,
            created_by: row.created_by,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
            revoked_by: row.revoked_by,
            decommissioned_at: row.decommissioned_at,
        }
    }
}
