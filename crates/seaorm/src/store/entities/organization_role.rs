use alibi_core::AuthError;
use alibi_core::types::OrganizationRole;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "organizationRole")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "organizationId")]
    pub organization_id: String,
    pub role: String,
    pub permission: String,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    pub updated_at: Option<DateTimeUtc>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

impl TryFrom<Model> for OrganizationRole {
    type Error = AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            organization_id: model.organization_id,
            role: model.role,
            permission: model.permission.into(),
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
