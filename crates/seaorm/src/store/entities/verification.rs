use crate::AuthEntity;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, DeriveEntityModel)]
#[auth(role = "verification")]
#[sea_orm(table_name = "verification")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[sea_orm(column_name = "expiresAt")]
    pub expires_at: DateTimeUtc,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
