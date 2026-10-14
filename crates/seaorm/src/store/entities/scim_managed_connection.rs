use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimManagedConnection")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "creationRequestId")]
    #[serde(rename = "creationRequestId")]
    pub creation_request_id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    pub status: String,
    pub revision: i32,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sea_orm(column_name = "createdBy")]
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[sea_orm(column_name = "decommissionStartedAt")]
    #[serde(rename = "decommissionStartedAt")]
    pub decommission_started_at: Option<DateTime<Utc>>,
    #[sea_orm(column_name = "decommissionStartedBy")]
    #[serde(rename = "decommissionStartedBy")]
    pub decommission_started_by: Option<String>,
    #[sea_orm(column_name = "decommissionedAt")]
    #[serde(rename = "decommissionedAt")]
    pub decommissioned_at: Option<DateTime<Utc>>,
    #[sea_orm(column_name = "decommissionedBy")]
    #[serde(rename = "decommissionedBy")]
    pub decommissioned_by: Option<String>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}

impl From<Model> for alibi_core::store::ScimManagedConnection {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            creation_request_id: row.creation_request_id,
            connection_id: row.connection_id,
            provisioning_domain_id: row.provisioning_domain_id,
            status: row.status,
            revision: i64::from(row.revision),
            created_at: row.created_at,
            created_by: row.created_by,
            decommission_started_at: row.decommission_started_at,
            decommission_started_by: row.decommission_started_by,
            decommissioned_at: row.decommissioned_at,
            decommissioned_by: row.decommissioned_by,
        }
    }
}
