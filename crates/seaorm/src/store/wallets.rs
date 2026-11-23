use super::entities::wallet_address;
use super::{ScopedTransaction, SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::WalletAddressStore;
use alibi_core::{AuthUser, CreateWalletAddress, WalletAddress};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};
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
        let transaction = self.scoped_connection().begin_immediate().await?;
        let created = self
            .insert_wallet_address(&transaction, &self.db, data)
            .await?;
        transaction.commit().await.map_err(map_db_err)?;
        Ok(created)
    }
}

impl<S> SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
{
    /// Validate the owner under a shared lock and insert the wallet on
    /// `connection`. `ids` generates the row ID, so a caller's transaction can
    /// supply its own connection instead of waiting for a second one.
    pub(super) async fn insert_wallet_address<C, I>(
        &self,
        connection: &C,
        ids: &I,
        data: CreateWalletAddress,
    ) -> AuthResult<WalletAddress>
    where
        C: sea_orm::ConnectionTrait,
        I: sea_orm::ConnectionTrait,
    {
        if !data.chain_id.is_finite() {
            return Err(AuthError::bad_request("Wallet chain ID must be finite"));
        }
        let owner_id = S::User::parse_id(&data.user_id)?;
        let owner = super::users::user_query::<S::User>(connection.get_database_backend())
            .filter(S::User::id_column().eq(owner_id))
            .lock_shared()
            .one(connection)
            .await
            .map_err(map_db_err)?
            .ok_or(AuthError::UserNotFound)?;
        let created = wallet_address::ActiveModel {
            id: Set(self
                .generated_id(ids, "walletAddress", "walletAddress", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            user_id: Set(owner.id().into_owned()),
            address: Set(data.address),
            chain_id: Set(data.chain_id.into()),
            is_primary: Set(data.is_primary),
            created_at: Set(Utc::now()),
        }
        .insert(connection)
        .await
        .map_err(map_db_err)?;
        Ok(created.into())
    }
}

pub(super) async fn remove_owned_wallets(
    transaction: &ScopedTransaction,
    user_id: &str,
) -> AuthResult<()> {
    if !transaction
        .has_table("walletAddress")
        .await
        .map_err(map_db_err)?
    {
        return Ok(());
    }
    _ = wallet_address::Entity::delete_many()
        .filter(wallet_address::Column::UserId.eq(user_id))
        .exec(transaction)
        .await
        .map_err(map_db_err)?;
    Ok(())
}
