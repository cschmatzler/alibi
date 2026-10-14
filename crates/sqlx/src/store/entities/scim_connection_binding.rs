use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "scimConnectionBinding")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sqlx(rename = "connectionKey")]
    #[serde(rename = "connectionKey")]
    pub connection_key: String,
    #[sqlx(rename = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "decommissionStatus")]
    #[serde(rename = "decommissionStatus")]
    pub decommission_status: String,
    #[sqlx(rename = "decommissionCursorUserId")]
    #[serde(rename = "decommissionCursorUserId")]
    pub decommission_cursor_user_id: Option<String>,
    #[sqlx(rename = "decommissionReconciledUserCount")]
    #[serde(rename = "decommissionReconciledUserCount")]
    pub decommission_reconciled_user_count: i64,
    #[sqlx(rename = "decommissionBatchCount")]
    #[serde(rename = "decommissionBatchCount")]
    pub decommission_batch_count: i64,
    #[sqlx(rename = "decommissionRevision")]
    #[serde(rename = "decommissionRevision")]
    pub decommission_revision: i64,
    #[sqlx(rename = "decommissionedAt")]
    #[serde(rename = "decommissionedAt")]
    pub decommissioned_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "decommissionCompletedAt")]
    #[serde(rename = "decommissionCompletedAt")]
    pub decommission_completed_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "decommissionLeaseId")]
    #[serde(rename = "decommissionLeaseId")]
    pub decommission_lease_id: Option<String>,
    #[sqlx(rename = "decommissionLeaseExpiresAt")]
    #[serde(rename = "decommissionLeaseExpiresAt")]
    pub decommission_lease_expires_at: Option<DateTime<Utc>>,
}
impl From<Model> for alibi_core::store::ScimConnectionBinding {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            connection_id: row.connection_id,
            connection_key: row.connection_key,
            provisioning_domain_id: row.provisioning_domain_id,
            created_at: row.created_at,
            decommission_status: row.decommission_status,
            decommission_cursor_user_id: row.decommission_cursor_user_id,
            decommission_reconciled_user_count: row.decommission_reconciled_user_count,
            decommission_batch_count: row.decommission_batch_count,
            decommission_revision: row.decommission_revision,
            decommissioned_at: row.decommissioned_at,
            decommission_completed_at: row.decommission_completed_at,
            decommission_lease_id: row.decommission_lease_id,
            decommission_lease_expires_at: row.decommission_lease_expires_at,
        }
    }
}
