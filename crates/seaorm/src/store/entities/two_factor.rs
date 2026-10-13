use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "twoFactor")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub secret: String,
    #[sea_orm(column_name = "backupCodes")]
    pub backup_codes: String,
    #[sea_orm(column_name = "userId")]
    pub user_id: String,
    pub verified: Option<bool>,
    #[sea_orm(column_name = "failedVerificationCount")]
    pub failed_verification_count: Option<crate::Number>,
    #[sea_orm(column_name = "lockedUntil")]
    pub locked_until: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
