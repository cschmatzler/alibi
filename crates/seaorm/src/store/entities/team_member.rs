use alibi_core::types::TeamMember;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "teamMember")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "teamId")]
    pub team_id: String,
    #[sea_orm(column_name = "userId")]
    pub user_id: String,
    #[sea_orm(unique)]
    #[sea_orm(column_name = "membershipKey")]
    pub membership_key: Option<String>,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: Option<DateTimeUtc>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for TeamMember {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            team_id: model.team_id,
            user_id: model.user_id,
            membership_key: model.membership_key,
            created_at: model.created_at,
        }
    }
}
