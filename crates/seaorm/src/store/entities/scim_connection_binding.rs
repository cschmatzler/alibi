use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimConnectionBinding")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "connectionKey")]
    #[serde(rename = "connectionKey")]
    pub connection_key: String,
    #[sea_orm(column_name = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sea_orm(column_name = "decommissionStatus")]
    #[serde(rename = "decommissionStatus")]
    pub decommission_status: String,
    #[sea_orm(column_name = "decommissionCursorUserId")]
    #[serde(rename = "decommissionCursorUserId")]
    pub decommission_cursor_user_id: Option<String>,
    #[sea_orm(column_name = "decommissionReconciledUserCount")]
    #[serde(rename = "decommissionReconciledUserCount")]
    pub decommission_reconciled_user_count: i32,
    #[sea_orm(column_name = "decommissionBatchCount")]
    #[serde(rename = "decommissionBatchCount")]
    pub decommission_batch_count: i32,
    #[sea_orm(column_name = "decommissionRevision")]
    #[serde(rename = "decommissionRevision")]
    pub decommission_revision: i32,
    #[sea_orm(column_name = "decommissionedAt")]
    #[serde(rename = "decommissionedAt")]
    pub decommissioned_at: Option<DateTime<Utc>>,
    #[sea_orm(column_name = "decommissionCompletedAt")]
    #[serde(rename = "decommissionCompletedAt")]
    pub decommission_completed_at: Option<DateTime<Utc>>,
    #[sea_orm(column_name = "decommissionLeaseId")]
    #[serde(rename = "decommissionLeaseId")]
    pub decommission_lease_id: Option<String>,
    #[sea_orm(column_name = "decommissionLeaseExpiresAt")]
    #[serde(rename = "decommissionLeaseExpiresAt")]
    pub decommission_lease_expires_at: Option<DateTime<Utc>>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}
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
            decommission_reconciled_user_count: i64::from(row.decommission_reconciled_user_count),
            decommission_batch_count: i64::from(row.decommission_batch_count),
            decommission_revision: i64::from(row.decommission_revision),
            decommissioned_at: row.decommissioned_at,
            decommission_completed_at: row.decommission_completed_at,
            decommission_lease_id: row.decommission_lease_id,
            decommission_lease_expires_at: row.decommission_lease_expires_at,
        }
    }
}
