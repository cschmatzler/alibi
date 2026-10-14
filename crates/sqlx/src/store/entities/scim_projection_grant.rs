use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "scimProjectionGrant")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sqlx(rename = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sqlx(rename = "scimUserId")]
    #[serde(rename = "scimUserId")]
    pub scim_user_id: String,
    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "sourceKind")]
    #[serde(rename = "sourceKind")]
    pub source_kind: String,
    #[sqlx(rename = "sourceId")]
    #[serde(rename = "sourceId")]
    pub source_id: String,
    #[sqlx(rename = "sourceValue")]
    #[serde(rename = "sourceValue")]
    pub source_value: Option<String>,
    pub role: String,
    #[sqlx(rename = "grantKey")]
    #[serde(rename = "grantKey")]
    pub grant_key: String,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
