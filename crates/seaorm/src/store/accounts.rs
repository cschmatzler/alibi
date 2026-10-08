use super::ScopedTransaction;
use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmAccountModel};
use alibi_core::error::AuthResult;
use alibi_core::store::AccountStore;
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::types::{CreateAccount, UpdateAccount};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect,
};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Account: SeaOrmAccountModel,
{
    async fn create_account_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&ScopedTransaction>,
        mut create_account: CreateAccount,
    ) -> AuthResult<S::Account>
    where
        C: ConnectionTrait,
    {
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
                db,
                "account",
                <<S::Account as SeaOrmAccountModel>::Entity as sea_orm::EntityName>::table_name(
                    &Default::default(),
                ),
                &sea_orm::Iden::to_string(&S::Account::id_column()),
            )
            .await?;
        let id = generated_id
            .as_deref()
            .map(S::Account::parse_id)
            .transpose()?;
        let mut active = S::Account::new_active(id, create_account, now);
        let backend = db.get_database_backend();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(db, &column, value).await?;
            S::Account::set_additional_field(&mut active, column, value, backend)?;
        }
        let account = active.insert(db).await.map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_account(&account, &hook_context).await?;
            }
        }
        Ok(account)
    }

    pub(crate) async fn create_account_in_tx(
        &self,
        tx: &ScopedTransaction,
        create_account: CreateAccount,
    ) -> AuthResult<S::Account> {
        self.create_account_with_connection(tx, Some(tx), create_account)
            .await
    }
}

#[async_trait]
impl<S> AccountStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Account: SeaOrmAccountModel,
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
        crate::additional_fields::prepare_string_value(self.scoped_connection(), value).await
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        self.create_account_with_connection(self.scoped_connection(), None, create_account)
            .await
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        let mut accounts = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::provider_id_column().eq(provider))
            .filter(<S::Account as SeaOrmAccountModel>::account_id_column().eq(provider_account_id))
            .limit(2)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        if accounts.len() > 1 {
            return Err(alibi_core::AuthError::Database(
                alibi_core::DatabaseError::AmbiguousAccount {
                    provider: provider.to_owned(),
                },
            ));
        }
        Ok(accounts.pop())
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        let user_id = <S::Account as SeaOrmAccountModel>::parse_user_id(user_id)?;
        <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::user_id_column().eq(user_id))
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<S::Account> {
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
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
        let Some(model) = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(alibi_core::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active_model();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        S::Account::apply_update(&mut active, update, Utc::now());
        let backend = self.scoped_connection().get_database_backend();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value =
                crate::additional_fields::prepare_value(self.scoped_connection(), &column, value)
                    .await?;
            S::Account::set_additional_field(&mut active, column, value, backend)?;
        }

        let account = active
            .update(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_account(&account, &hook_context).await?;
        }
        Ok(account)
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
        let Some(account_model) = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id.clone()))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
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
        let _ignored_map_err = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_account(&account_model, &hook_context)
                .await?;
        }
        Ok(())
    }
}
