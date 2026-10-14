use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimManagedCredential")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionRecordId")]
    #[serde(rename = "connectionRecordId")]
    pub connection_record_id: String,
    #[sea_orm(column_name = "credentialId")]
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[sea_orm(column_name = "tokenDigest")]
    #[serde(rename = "tokenDigest")]
    pub token_digest: String,
    #[sea_orm(column_name = "hashVersion")]
    #[serde(rename = "hashVersion")]
    pub hash_version: String,
    #[sea_orm(column_name = "activeSlotKey")]
    #[serde(rename = "activeSlotKey")]
    pub active_slot_key: String,
    pub status: String,
    #[sea_orm(column_name = "serializedScopes")]
    #[serde(rename = "serializedScopes")]
    pub serialized_scopes: String,
    #[sea_orm(column_name = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sea_orm(column_name = "createdBy")]
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[sea_orm(column_name = "lastUsedAt")]
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[sea_orm(column_name = "revokedAt")]
    #[serde(rename = "revokedAt")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[sea_orm(column_name = "revokedBy")]
    #[serde(rename = "revokedBy")]
    pub revoked_by: Option<String>,
    #[sea_orm(column_name = "decommissionedAt")]
    #[serde(rename = "decommissionedAt")]
    pub decommissioned_at: Option<DateTime<Utc>>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}

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
