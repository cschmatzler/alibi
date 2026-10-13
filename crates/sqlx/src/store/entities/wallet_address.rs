pub use crate::Number as WalletChainId;
use crate::SqlxModel;
use alibi_core::WalletAddress;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, sqlx::FromRow, SqlxModel)]
#[auth(table = "walletAddress")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    pub address: String,
    #[sqlx(rename = "chainId")]
    pub chain_id: WalletChainId,
    #[sqlx(rename = "isPrimary")]
    pub is_primary: bool,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

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
