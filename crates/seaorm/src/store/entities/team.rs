use alibi_core::types::Team;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "team")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub organization_id: String,
    #[sea_orm(default_value = 0)]
    pub member_count: i64,
    pub created_at: DateTimeUtc,
    pub updated_at: Option<DateTimeUtc>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for Team {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            organization_id: model.organization_id,
            member_count: model.member_count,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}
