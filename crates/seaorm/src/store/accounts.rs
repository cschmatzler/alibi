use super::{ScopedTransaction, SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmAccountModel};
use alibi_core::error::AuthResult;
use alibi_core::store::AccountStore;
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::types::{CreateAccount, UpdateAccount};
use alibi_core::{AuthError, DatabaseError};
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
            .generated_entity_id::<<S::Account as SeaOrmAccountModel>::Entity, _>(
                db,
                "account",
                S::Account::id_column(),
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
        provider_account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        self.get_account_with_connection(self.scoped_connection(), provider, provider_account_id)
            .await
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        let user_id = <S::Account as SeaOrmAccountModel>::parse_user_id(user_id)?;
        <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::user_id_column().eq(user_id))
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account> {
        self.update_account_with_connection(self.scoped_connection(), None, id, update)
            .await
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
        _ = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
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

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Account: crate::schema::SeaOrmAccountModel,
{
    pub(super) async fn update_account_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<&ScopedTransaction>,
        id: &str,
        mut update: UpdateAccount,
    ) -> AuthResult<S::Account> {
        let account_id = <S::Account as SeaOrmAccountModel>::parse_id(id)?;
        let hook_context = self.hook_context(tx);
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
            .one(connection)
            .await
            .map_err(map_db_err)?
        else {
            return Err(alibi_core::error::AuthError::not_found("Account not found"));
        };

        let mut active = model.into_active_model();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        S::Account::apply_update(&mut active, update, Utc::now());
        let backend = connection.get_database_backend();
        for (column, value) in S::Account::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(connection, &column, value).await?;
            S::Account::set_additional_field(&mut active, column, value, backend)?;
        }

        let account = active.update(connection).await.map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_update_account(&account, &hook_context).await?;
            }
        }
        Ok(account)
    }
}

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Account: crate::schema::SeaOrmAccountModel,
{
    pub(super) async fn get_account_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        provider: &str,
        provider_account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        let mut accounts = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::provider_id_column().eq(provider))
            .filter(
                <S::Account as SeaOrmAccountModel>::account_id_column()
                    .eq(provider_account_id.to_utf8_binding()),
            )
            .limit(2)
            .all(connection)
            .await
            .map_err(map_db_err)?;
        if accounts.len() > 1 {
            return Err(AuthError::Database(DatabaseError::AmbiguousAccount {
                provider: provider.to_owned(),
            }));
        }
        Ok(accounts.pop())
    }
}

#[cfg(test)]
mod utf16_tests {
    use super::super::bundled_schema::BundledSchema;
    use super::*;
    use crate::hooks::{DatabaseHooks, HookControl};
    use alibi_core::store::{AccountStore, SchemaMigrator, UserStore};
    use alibi_core::utils::json::JsString;
    use alibi_core::{AuthAccount, AuthConfig, AuthUser, CreateAccount, CreateUser};
    use std::sync::{Arc, Mutex};
    type Account = <BundledSchema as alibi_core::AuthSchema>::Account;

    #[derive(Clone)]
    struct RawHooks(Arc<Mutex<Vec<(&'static str, JsString)>>>);
    #[async_trait]
    impl DatabaseHooks<BundledSchema, crate::hooks::SeaOrmBackend> for RawHooks {
        async fn before_create_account(
            &self,
            input: &mut CreateAccount,
            _: &crate::hooks::SeaOrmHookContext<'_>,
        ) -> alibi_core::AuthResult<HookControl> {
            self.0
                .lock()
                .unwrap()
                .push(("before", input.account_id.clone()));
            Ok(HookControl::Continue)
        }
        async fn after_create_account(
            &self,
            account: &Account,
            _: &crate::hooks::SeaOrmHookContext<'_>,
        ) -> alibi_core::AuthResult<()> {
            self.0.lock().unwrap().push(("after", account.account_id()));
            Ok(())
        }
    }
    fn input(user: &str, key: JsString) -> CreateAccount {
        CreateAccount {
            additional_fields: Default::default(),
            user_id: user.into(),
            account_id: key,
            provider_id: "fixture".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        }
    }
    #[tokio::test]
    async fn account_utf16_hooks_precede_real_sqlite_usv_binding_and_query_collisions() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db)
            .hook(RawHooks(trace.clone()));
        store.migrate().await.unwrap();
        let owner = store
            .create_user(
                CreateUser::new()
                    .with_email("account@fixture.test")
                    .with_name("Owner"),
            )
            .await
            .unwrap();
        let high = JsString::from_code_units(vec![0x61, 0xd800, 0x62]);
        let low = JsString::from_code_units(vec![0x61, 0xdc00, 0x62]);
        let replacement = JsString::from("a\u{fffd}b");
        let first = store
            .create_account(input(&owner.id(), high.clone()))
            .await
            .unwrap();
        assert_eq!(first.account_id(), replacement);
        let raw_hex: String = {
            use sea_orm::ConnectionTrait;
            store
                .connection()
                .query_one_raw(sea_orm::Statement::from_sql_and_values(
                    sea_orm::DatabaseBackend::Sqlite,
                    "SELECT hex(accountId) AS raw FROM account WHERE id = ?",
                    [first.id().into_owned().into()],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get("", "raw")
                .unwrap()
        };
        assert_eq!(raw_hex, "61EFBFBD62");
        for query in [&high, &replacement] {
            let found = store.get_account("fixture", query).await.unwrap().unwrap();
            assert_eq!(found.id(), first.id());
        }
        let second = store
            .create_account(input(&owner.id(), low.clone()))
            .await
            .unwrap();
        assert_ne!(first.id(), second.id());
        assert_eq!(second.account_id(), replacement);
        assert!(matches!(
            store.get_account("fixture", &high).await,
            Err(alibi_core::AuthError::Database(
                alibi_core::DatabaseError::AmbiguousAccount { .. }
            ))
        ));
        assert_eq!(
            trace.lock().unwrap().as_slice(),
            [
                ("before", high),
                ("after", replacement.clone()),
                ("before", low),
                ("after", replacement),
            ]
        );
    }
}
