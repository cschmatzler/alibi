use super::SqlxStore;
use crate::model::{self, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxAccountModel};
use crate::sql::Sql;
use alibi_core::error::AuthResult;
use alibi_core::store::AccountStore;
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::types::{CreateAccount, UpdateAccount};
use alibi_core::{AuthError, DatabaseError};
use async_trait::async_trait;
use chrono::{SubsecRound, Utc};

async fn stage_account_fields<M: SqlxAccountModel>(
    exec: Exec<'_>,
    active: &mut crate::model::ActiveRow,
    fields: &alibi_core::field_policy::FieldValues,
) -> AuthResult<()> {
    let backend = exec.engine();
    let prepared = M::additional_field_bindings(&fields.prepared_text_inputs(), backend)?
        .into_iter()
        .map(|(column, _)| column)
        .collect::<std::collections::BTreeSet<_>>();
    for (column, value) in M::additional_field_bindings(fields, backend)? {
        let kind = M::column_kind(column);
        if prepared.contains(column)
            && matches!(
                kind,
                crate::value::ColumnKind::Timestamp | crate::value::ColumnKind::NaiveTimestamp
            )
            && matches!(&value, alibi_core::store::adapter::RawFieldValue::Text(_))
        {
            active.set(column, crate::additional_fields::bind_scalar(value)?);
        } else {
            let value = crate::additional_fields::prepare_value(exec, kind, value).await?;
            M::set_additional_field(active, column, value, backend)?;
        }
    }
    Ok(())
}

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
        let now = Utc::now().trunc_subsecs(3);
        let mut fields = std::mem::take(&mut create_account.additional_fields);
        fields.take_timestamp_input(
            "accessTokenExpiresAt",
            &mut create_account.access_token_expires_at,
        );
        fields.take_timestamp_input(
            "refreshTokenExpiresAt",
            &mut create_account.refresh_token_expires_at,
        );
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
        stage_account_fields::<S::Account>(exec, &mut active, &fields).await?;
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

    async fn find_account_by_id_with(
        &self,
        exec: Exec<'_>,
        id: &str,
    ) -> AuthResult<Option<S::Account>> {
        let account_id = <S::Account as SqlxAccountModel>::parse_id(id)?;
        let mut sql = model::select_model::<S::Account>(exec);
        sql.push(" WHERE ");
        sql.compare_model::<S::Account>(
            <S::Account as SqlxModel>::TABLE,
            S::Account::id_column(),
            " = ",
            account_id,
        );
        sql.push(" LIMIT 1");
        exec.fetch_optional(sql).await
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
        provider_account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        self.get_account_with_connection(self.exec(), provider, provider_account_id)
            .await
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

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account> {
        self.update_account_with_connection(self.exec(), None, id, update)
            .await?
            .ok_or_else(|| AuthError::not_found("Account not found"))
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        let account_id = <S::Account as SqlxAccountModel>::parse_id(id)?;
        let Some(account_model) = self.find_account_by_id_with(self.exec(), id).await? else {
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

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::Account: crate::schema::SqlxAccountModel,
{
    pub(super) async fn update_account_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        id: &str,
        mut update: UpdateAccount,
    ) -> AuthResult<Option<S::Account>> {
        let locator = <S::Account as SqlxAccountModel>::parse_id(id)?;
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
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.take_timestamp_input("accessTokenExpiresAt", &mut update.access_token_expires_at);
        fields.take_timestamp_input(
            "refreshTokenExpiresAt",
            &mut update.refresh_token_expires_at,
        );
        fields.apply_adapter_transforms_async().await?;
        let mut active = self
            .find_account_by_id_with(exec, id)
            .await?
            .map(SqlxModel::into_active)
            .unwrap_or_default();
        S::Account::apply_update(&mut active, update, Utc::now().trunc_subsecs(3));
        stage_account_fields::<S::Account>(exec, &mut active, &fields).await?;

        let account = model::update_where::<S::Account>(exec, &active, locator).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                if let Some(account) = &account {
                    hook.after_update_account(account, &hook_context).await?;
                } else {
                    hook.after_update_account_missing(id, &hook_context)
                        .await
                        .map_err(alibi_core::store::adapter::callback_error)?;
                }
            }
        }
        Ok(account)
    }
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::Account: crate::schema::SqlxAccountModel,
{
    pub(super) async fn get_account_with_connection(
        &self,
        exec: Exec<'_>,
        provider: &str,
        provider_account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        let table = <S::Account as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::Account>(exec);
        sql.push(" WHERE ");
        sql.compare_model::<S::Account>(table, S::Account::provider_id_column(), " = ", provider);
        sql.push(" AND ");
        sql.compare_model::<S::Account>(
            table,
            S::Account::account_id_column(),
            " = ",
            provider_account_id.to_utf8_binding(),
        );
        sql.push(" LIMIT ");
        sql.bind(2_i64);
        let mut accounts: Vec<S::Account> = exec.fetch_all(sql).await?;
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
    impl DatabaseHooks<BundledSchema, crate::hooks::SqlxBackend> for RawHooks {
        async fn before_create_account(
            &self,
            input: &mut CreateAccount,
            _: &crate::hooks::SqlxHookContext<'_>,
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
            _: &crate::hooks::SqlxHookContext<'_>,
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
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let store = SqlxStore::<BundledSchema>::new(AuthConfig::default(), pool.clone())
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
        let raw_hex: String = sqlx::query_scalar("SELECT hex(accountId) FROM account WHERE id = ?")
            .bind(first.id().as_ref())
            .fetch_one(&pool)
            .await
            .unwrap();
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
