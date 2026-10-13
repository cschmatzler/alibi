use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "passkey")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    #[sea_orm(column_name = "publicKey")]
    pub public_key: String,
    #[sea_orm(column_name = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "credentialID")]
    pub credential_id: String,
    pub counter: crate::Integer,
    #[sea_orm(column_name = "deviceType")]
    pub device_type: String,
    #[sea_orm(column_name = "backedUp")]
    pub backed_up: bool,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
