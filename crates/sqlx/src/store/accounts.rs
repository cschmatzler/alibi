use super::SqlxStore;
use crate::error::{cancelled_by_hook, record_not_updated};
use crate::model::{self, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxAccountModel};
use crate::sql::Sql;
use async_trait::async_trait;
use better_auth_core::error::AuthResult;
use better_auth_core::store::AccountStore;
use better_auth_core::types::{CreateAccount, UpdateAccount};
use chrono::Utc;

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::Account: SqlxAccountModel,
{
    async fn create_account_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        mut create_account: CreateAccount,
    ) -> AuthResult<S::Account> {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_account(&mut create_account, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account creation"));
            }
        }
        let now = Utc::now();
        let mut fields = std::mem::take(&mut create_account.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        let mut active = S::Account::new_active(None, create_account, now);
        let backend = exec.backend();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value = crate::session_fields::prepare_value(
                exec,
                <S::Account as SqlxModel>::column_kind(column),
                value,
            )
            .await?;
            S::Account::set_additional_field(&mut active, column, value, backend)?;
        }
        let account = model::insert::<S::Account>(exec, &active).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_account(&account, &hook_context).await?;
            }
        }
        Ok(account)
    }

    pub(crate) async fn create_account_in_tx(
        &self,
        tx: &SqlxTransaction,
        create_account: CreateAccount,
    ) -> AuthResult<S::Account> {
        self.create_account_with_connection(Exec::Tx(tx), Some(tx), create_account)
            .await
    }

    async fn find_account_by_id(&self, id: &str) -> AuthResult<Option<S::Account>> {
        let account_id = <S::Account as SqlxAccountModel>::parse_id(id)?;
        let mut sql = model::select_model::<S::Account>(self.exec());
        sql.push(" WHERE ")
            .column(<S::Account as SqlxModel>::TABLE, S::Account::id_column())
            .push(" = ")
            .bind(account_id)
            .push(" LIMIT 1");
        self.exec().fetch_optional(sql).await
    }
}

#[async_trait]
impl<S> AccountStore<S> for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Account: SqlxAccountModel,
{
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        self.create_account_with_connection(self.exec(), None, create_account)
            .await
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        let table = <S::Account as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::Account>(self.exec());
        sql.push(" WHERE ")
            .column(table, S::Account::provider_id_column())
            .push(" = ")
            .bind(provider)
            .push(" AND ")
            .column(table, S::Account::account_id_column())
            .push(" = ")
            .bind(provider_account_id)
            .push(" LIMIT ")
            .bind(2_i64);
        let mut accounts: Vec<S::Account> = self.exec().fetch_all(sql).await?;
        if accounts.len() > 1 {
            return Err(better_auth_core::AuthError::Database(
                better_auth_core::DatabaseError::AmbiguousAccount {
                    provider: provider.to_owned(),
                },
            ));
        }
        Ok(accounts.pop())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        let user_id = <S::Account as SqlxAccountModel>::parse_user_id(user_id)?;
        let mut sql = model::select_model::<S::Account>(self.exec());
        sql.push(" WHERE ")
            .column(
                <S::Account as SqlxModel>::TABLE,
                S::Account::user_id_column(),
            )
            .push(" = ")
            .bind(user_id);
        self.exec().fetch_all(sql).await
    }

    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<S::Account> {
        drop(<S::Account as SqlxAccountModel>::parse_id(id)?);
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_account(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account update"));
            }
        }
        let Some(model) = self.find_account_by_id(id).await? else {
            return Err(better_auth_core::error::AuthError::not_found(
                "Account not found",
            ));
        };

        let mut active = model.into_active();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        S::Account::apply_update(&mut active, update, Utc::now());
        let backend = self.exec().backend();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value = crate::session_fields::prepare_value(
                self.exec(),
                <S::Account as SqlxModel>::column_kind(column),
                value,
            )
            .await?;
            S::Account::set_additional_field(&mut active, column, value, backend)?;
        }

        let account = model::update::<S::Account>(self.exec(), &active)
            .await?
            .ok_or_else(record_not_updated)?;
        for hook in self.hooks() {
            hook.after_update_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let account_id = <S::Account as SqlxAccountModel>::parse_id(id)?;
        let Some(account_model) = self.find_account_by_id(id).await? else {
            return Err(better_auth_core::error::AuthError::not_found(
                "Account not found",
            ));
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_account(&account_model, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("account deletion"));
            }
        }
        let table = <S::Account as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().backend(), "DELETE FROM ");
        sql.ident(table)
            .push(" WHERE ")
            .column(table, S::Account::id_column())
            .push(" = ")
            .bind(account_id);
        self.exec().execute(sql).await?;
        for hook in self.hooks() {
            hook.after_delete_account(&account_model, &hook_context)
                .await?;
        }
        Ok(())
    }
}
