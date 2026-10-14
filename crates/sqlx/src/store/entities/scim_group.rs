use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "scimGroup")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sqlx(rename = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    pub revision: i64,
    #[sqlx(rename = "displayName")]
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[sqlx(rename = "displayNameKey")]
    #[serde(rename = "displayNameKey")]
    pub display_name_key: String,
    #[sqlx(rename = "externalId")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[sqlx(rename = "externalIdKey")]
    #[serde(rename = "externalIdKey")]
    pub external_id_key: Option<String>,
    #[sqlx(rename = "orderKey")]
    #[serde(rename = "orderKey")]
    pub order_key: String,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
