use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "scimManagedConnection")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "creationRequestId")]
    #[serde(rename = "creationRequestId")]
    pub creation_request_id: String,
    #[sqlx(rename = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sqlx(rename = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    pub status: String,
    pub revision: i64,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "createdBy")]
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[sqlx(rename = "decommissionStartedAt")]
    #[serde(rename = "decommissionStartedAt")]
    pub decommission_started_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "decommissionStartedBy")]
    #[serde(rename = "decommissionStartedBy")]
    pub decommission_started_by: Option<String>,
    #[sqlx(rename = "decommissionedAt")]
    #[serde(rename = "decommissionedAt")]
    pub decommissioned_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "decommissionedBy")]
    #[serde(rename = "decommissionedBy")]
    pub decommissioned_by: Option<String>,
}

impl From<Model> for alibi_core::store::ScimManagedConnection {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            creation_request_id: row.creation_request_id,
            connection_id: row.connection_id,
            provisioning_domain_id: row.provisioning_domain_id,
            status: row.status,
            revision: row.revision,
            created_at: row.created_at,
            created_by: row.created_by,
            decommission_started_at: row.decommission_started_at,
            decommission_started_by: row.decommission_started_by,
            decommissioned_at: row.decommissioned_at,
            decommissioned_by: row.decommissioned_by,
        }
    }
}
