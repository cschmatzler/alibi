use super::ScopedTransaction;
use super::entities::wallet_address;
use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::WalletAddressStore;
use alibi_core::{AuthUser, CreateWalletAddress, WalletAddress};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set,
    SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use uuid::Uuid;

#[async_trait]
impl<S> WalletAddressStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
{
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<f64>,
    ) -> AuthResult<Option<WalletAddress>> {
        let mut query =
            wallet_address::Entity::find().filter(wallet_address::Column::Address.eq(address));
        if let Some(chain_id) = chain_id {
            query = query.filter(wallet_address::Column::ChainId.eq(chain_id));
        }
        // The upstream adapter uses findOne without ordering. In SQLite this
        // preserves insertion order for an address-only scan; a chain/address
        // index or creation-time sort would change the selected owner.
        Ok(query
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(Into::into))
    }

    async fn create_wallet_address(&self, data: CreateWalletAddress) -> AuthResult<WalletAddress> {
        if !data.chain_id.is_finite() {
            return Err(AuthError::bad_request("Wallet chain ID must be finite"));
        }
        let transaction = self
            .scoped_connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let owner_id = S::User::parse_id(&data.user_id)?;
        let owner = super::users::user_query::<S::User>(
            sea_orm::ConnectionTrait::get_database_backend(&transaction),
        )
        .filter(S::User::id_column().eq(owner_id))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(map_db_err)?
        .ok_or(AuthError::UserNotFound)?;
        let created = wallet_address::ActiveModel {
            id: Set(self
                .generated_id(&self.db, "walletAddress", "wallet_address", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            user_id: Set(owner.id().into_owned()),
            address: Set(data.address),
            chain_id: Set(data.chain_id.into()),
            is_primary: Set(data.is_primary),
            created_at: Set(Utc::now()),
        }
        .insert(&transaction)
        .await
        .map_err(map_db_err)?;
        transaction.commit().await.map_err(map_db_err)?;
        Ok(created.into())
    }
}

pub(super) async fn remove_owned_wallets(
    transaction: &ScopedTransaction,
    user_id: &str,
) -> AuthResult<()> {
    if !transaction
        .has_table("wallet_address")
        .await
        .map_err(map_db_err)?
    {
        return Ok(());
    }
    let _ignored_map_err = wallet_address::Entity::delete_many()
        .filter(wallet_address::Column::UserId.eq(user_id))
        .exec(transaction)
        .await
        .map_err(map_db_err)?;
    Ok(())
}
