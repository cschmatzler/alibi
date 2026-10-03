use super::entities::wallet_address;
use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::WalletAddressStore;
use better_auth_core::{AuthUser, CreateWalletAddress, WalletAddress};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QuerySelect, Set,
    SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use sea_orm_migration::SchemaManager;
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
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(Into::into))
    }

    async fn create_wallet_address(&self, data: CreateWalletAddress) -> AuthResult<WalletAddress> {
        if !data.chain_id.is_finite() {
            return Err(AuthError::bad_request("Wallet chain ID must be finite"));
        }
        let transaction = self
            .connection()
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
            id: Set(Uuid::new_v4().to_string()),
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
    transaction: &DatabaseTransaction,
    user_id: &str,
) -> AuthResult<()> {
    if !SchemaManager::new(transaction)
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
