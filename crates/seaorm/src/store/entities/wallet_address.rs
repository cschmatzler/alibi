pub use crate::Number as WalletChainId;
use alibi_core::WalletAddress;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "walletAddress")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "userId")]
    pub user_id: String,
    pub address: String,
    #[sea_orm(column_name = "chainId")]
    pub chain_id: WalletChainId,
    #[sea_orm(column_name = "isPrimary")]
    pub is_primary: bool,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for WalletAddress {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            address: row.address,
            chain_id: row.chain_id.0,
            is_primary: row.is_primary,
            created_at: row.created_at,
        }
    }
}
