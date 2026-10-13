use crate::AuthEntity;
use sea_orm::entity::prelude::*;
use serde::Serialize;

#[derive(AuthEntity, Clone, Debug, PartialEq, Eq, Serialize, DeriveEntityModel)]
#[auth(role = "session", secondary_storage)]
#[sea_orm(table_name = "session")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "expiresAt")]
    pub expires_at: DateTimeUtc,
    pub token: String,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    pub updated_at: DateTimeUtc,
    #[sea_orm(column_name = "ipAddress")]
    pub ip_address: Option<String>,
    #[sea_orm(column_name = "userAgent")]
    pub user_agent: Option<String>,
    #[sea_orm(column_name = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "impersonatedBy")]
    pub impersonated_by: Option<String>,
    #[sea_orm(column_name = "activeOrganizationId")]
    pub active_organization_id: Option<String>,
    #[sea_orm(column_name = "activeTeamId")]
    pub active_team_id: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
