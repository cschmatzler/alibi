use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "scimIdentityTombstone")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sqlx(rename = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sqlx(rename = "externalId")]
    #[serde(rename = "externalId")]
    pub external_id: String,
    #[sqlx(rename = "externalIdKey")]
    #[serde(rename = "externalIdKey")]
    pub external_id_key: String,
    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    pub profile: String,
    #[sqlx(rename = "deletedAt")]
    #[serde(rename = "deletedAt")]
    pub deleted_at: DateTime<Utc>,
}
