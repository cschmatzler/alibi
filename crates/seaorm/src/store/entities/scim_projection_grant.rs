use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimProjectionGrant")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sea_orm(column_name = "scimUserId")]
    #[serde(rename = "scimUserId")]
    pub scim_user_id: String,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "sourceKind")]
    #[serde(rename = "sourceKind")]
    pub source_kind: String,
    #[sea_orm(column_name = "sourceId")]
    #[serde(rename = "sourceId")]
    pub source_id: String,
    #[sea_orm(column_name = "sourceValue")]
    #[serde(rename = "sourceValue")]
    pub source_value: Option<String>,
    pub role: String,
    #[sea_orm(column_name = "grantKey")]
    #[serde(rename = "grantKey")]
    pub grant_key: String,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sea_orm(column_name = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}
