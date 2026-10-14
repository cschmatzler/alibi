use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimIdentityTombstone")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sea_orm(column_name = "externalId")]
    #[serde(rename = "externalId")]
    pub external_id: String,
    #[sea_orm(column_name = "externalIdKey")]
    #[serde(rename = "externalIdKey")]
    pub external_id_key: String,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    pub profile: String,
    #[sea_orm(column_name = "deletedAt")]
    #[serde(rename = "deletedAt")]
    pub deleted_at: DateTime<Utc>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}
