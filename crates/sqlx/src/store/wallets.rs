use super::SqlxStore;
use super::entities::wallet_address::{self, WalletChainId};
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxUserModel};
use crate::sql::Sql;
use crate::value::SqlxValue;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::WalletAddressStore;
use better_auth_core::{AuthUser, CreateWalletAddress, WalletAddress};
use chrono::Utc;
use uuid::Uuid;

#[async_trait]
impl<S> WalletAddressStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SqlxUserModel,
{
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<f64>,
    ) -> AuthResult<Option<WalletAddress>> {
        let mut sql = model::select_model::<wallet_address::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(wallet_address::Model::TABLE, "address", " = ", address);
        if let Some(chain_id) = chain_id {
            sql.push(" AND ");
            sql.compare(wallet_address::Model::TABLE, "chain_id", " = ", chain_id);
        }
        model::limit_one(&mut sql);
        // The upstream adapter uses findOne without ordering. In SQLite this
        // preserves insertion order for an address-only scan; a chain/address
        // index or creation-time sort would change the selected owner.
        Ok(self
            .exec()
            .fetch_optional::<wallet_address::Model>(sql)
            .await?
            .map(Into::into))
    }

    async fn create_wallet_address(&self, data: CreateWalletAddress) -> AuthResult<WalletAddress> {
        if !data.chain_id.is_finite() {
            return Err(AuthError::bad_request("Wallet chain ID must be finite"));
        }
        self.in_transaction(true, async move |tx| {
            let exec = Exec::Tx(tx);
            let owner = super::users::find_user_by_id::<S::User>(
                exec,
                &data.user_id,
                super::users::Lock::Shared,
            )
            .await?
            .ok_or(AuthError::UserNotFound)?;
            let mut active = ActiveRow::new();
            active.set("id", Uuid::new_v4().to_string());
            active.set("user_id", owner.id().into_owned());
            active.set("address", data.address);
            active.set(
                "chain_id",
                WalletChainId::from(data.chain_id).into_sql_value(),
            );
            active.set("is_primary", data.is_primary);
            active.set("created_at", Utc::now());
            let created = model::insert::<wallet_address::Model>(exec, &active).await?;
            Ok(created.into())
        })
        .await
    }
}

pub(super) async fn remove_owned_wallets(tx: &SqlxTransaction, user_id: &str) -> AuthResult<()> {
    let exec = Exec::Tx(tx);
    if !super::migrator::has_table(exec, "wallet_address").await? {
        return Ok(());
    }
    let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
    sql.ident(wallet_address::Model::TABLE);
    sql.push(" WHERE ");
    sql.compare(wallet_address::Model::TABLE, "user_id", " = ", user_id);
    _ = exec.execute(sql).await?;
    Ok(())
}
