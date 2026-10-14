use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimManagedConnectionEvent")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionRecordId")]
    #[serde(rename = "connectionRecordId")]
    pub connection_record_id: String,
    #[sea_orm(column_name = "eventKey")]
    #[serde(rename = "eventKey")]
    pub event_key: String,
    pub sequence: i32,
    #[sea_orm(column_name = "type")]
    #[serde(rename = "type")]
    pub kind: String,
    #[sea_orm(column_name = "actorId")]
    #[serde(rename = "actorId")]
    pub actor_id: String,
    #[sea_orm(column_name = "credentialId")]
    #[serde(rename = "credentialId")]
    pub credential_id: Option<String>,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}
