use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimGroupMember")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "groupId")]
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[sea_orm(column_name = "scimUserId")]
    #[serde(rename = "scimUserId")]
    pub scim_user_id: String,
    #[sea_orm(column_name = "membershipKey")]
    #[serde(rename = "membershipKey")]
    pub membership_key: String,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}
