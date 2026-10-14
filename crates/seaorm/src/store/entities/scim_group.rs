use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimGroup")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    pub revision: i32,
    #[sea_orm(column_name = "displayName")]
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[sea_orm(column_name = "displayNameKey")]
    #[serde(rename = "displayNameKey")]
    pub display_name_key: String,
    #[sea_orm(column_name = "externalId")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[sea_orm(column_name = "externalIdKey")]
    #[serde(rename = "externalIdKey")]
    pub external_id_key: Option<String>,
    #[sea_orm(column_name = "orderKey")]
    #[serde(rename = "orderKey")]
    pub order_key: String,
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
