pub use crate::json_metadata::JsonMetadata;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "organization")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[sea_orm(column_type = "Text", save_as = "text")]
    pub metadata: Option<JsonMetadata>,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
