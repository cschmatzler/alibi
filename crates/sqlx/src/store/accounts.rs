use super::SqlxStore;
use crate::error::record_not_updated;
use crate::model::{self, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxAccountModel};
use crate::sql::Sql;
use alibi_core::AuthError;
use alibi_core::DatabaseError;
use alibi_core::error::AuthResult;
use alibi_core::store::AccountStore;
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::types::{CreateAccount, UpdateAccount};
use async_trait::async_trait;
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
        let generated_id = self
            .generated_id(
                exec,
                "account",
                <S::Account as SqlxModel>::TABLE,
                S::Account::id_column(),
            )
            .await?;
        let id = generated_id
            .as_deref()
            .map(S::Account::parse_id)
            .transpose()?;
        let mut active = S::Account::new_active(id, create_account, now);
        let backend = exec.engine();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(
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
        self.create_account_with_connection(Exec::tx(tx), Some(tx), create_account)
            .await
    }

    async fn find_account_by_id(&self, id: &str) -> AuthResult<Option<S::Account>> {
        let account_id = <S::Account as SqlxAccountModel>::parse_id(id)?;
        let mut sql = model::select_model::<S::Account>(self.exec());
        sql.push(" WHERE ");
        sql.compare_model::<S::Account>(
            <S::Account as SqlxModel>::TABLE,
            S::Account::id_column(),
            " = ",
            account_id,
        );
        sql.push(" LIMIT 1");
        self.exec().fetch_optional(sql).await
    }
}

#[async_trait]
impl<S> AccountStore<S> for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Account: SqlxAccountModel,
{
    async fn provider_token_text(&self, value: &serde_json::Value) -> AuthResult<Option<String>> {
        if value.is_object() || value.is_array() {
            return Err(alibi_core::AuthError::internal(
                "Unsupported provider token SQL parameter",
            ));
        }
        let value = crate::additional_fields::raw_value(&alibi_core::utils::json::JsValue::from(
            value.clone(),
        ))?;
        crate::additional_fields::prepare_string_value(self.exec(), value).await
    }

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
        sql.push(" WHERE ");
        sql.compare_model::<S::Account>(table, S::Account::provider_id_column(), " = ", provider);
        sql.push(" AND ");
        sql.compare_model::<S::Account>(
            table,
            S::Account::account_id_column(),
            " = ",
            provider_account_id,
        );
        sql.push(" LIMIT ");
        sql.bind(2_i64);
        let mut accounts: Vec<S::Account> = self.exec().fetch_all(sql).await?;
        if accounts.len() > 1 {
            return Err(AuthError::Database(DatabaseError::AmbiguousAccount {
                provider: provider.to_owned(),
            }));
        }
        Ok(accounts.pop())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        let user_id = <S::Account as SqlxAccountModel>::parse_user_id(user_id)?;
        let mut sql = model::select_model::<S::Account>(self.exec());
        sql.push(" WHERE ");
        sql.compare_model::<S::Account>(
            <S::Account as SqlxModel>::TABLE,
            S::Account::user_id_column(),
            " = ",
            user_id,
        );
        self.exec().fetch_all(sql).await
    }

    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<S::Account> {
        _ = <S::Account as SqlxAccountModel>::parse_id(id)?;
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
            return Err(alibi_core::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        S::Account::apply_update(&mut active, update, Utc::now());
        let backend = self.exec().engine();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(
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
            return Err(alibi_core::error::AuthError::not_found("Account not found"));
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_account(&account_model, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(());
            }
        }
        let table = <S::Account as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(table);
        sql.push(" WHERE ");
        sql.compare_model::<S::Account>(table, S::Account::id_column(), " = ", account_id);
        _ = self.exec().execute(sql).await?;
        for hook in self.hooks() {
            hook.after_delete_account(&account_model, &hook_context)
                .await?;
        }
        Ok(())
    }
}
