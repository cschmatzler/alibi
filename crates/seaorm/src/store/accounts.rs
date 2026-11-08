use super::{ScopedTransaction, SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmAccountModel};
use alibi_core::error::AuthResult;
use alibi_core::store::AccountStore;
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::types::{CreateAccount, UpdateAccount};
use alibi_core::{AuthError, DatabaseError};
use async_trait::async_trait;
use chrono::{SubsecRound, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect,
};

async fn stage_account_fields<M: SeaOrmAccountModel, C: ConnectionTrait>(
    db: &C,
    active: &mut M::ActiveModel,
    fields: &alibi_core::field_policy::FieldValues,
) -> AuthResult<Vec<(M::Column, sea_orm::Value)>> {
    use sea_orm::Iden;
    let backend = db.get_database_backend();
    let prepared = M::additional_field_bindings(&fields.prepared_text_inputs(), backend)?
        .into_iter()
        .map(|(column, _)| column.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    let mut native = Vec::new();
    for (column, value) in M::additional_field_bindings(fields, backend)? {
        if prepared.contains(&column.to_string())
            && matches!(
                column.def().get_column_type(),
                sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                    | sea_orm::sea_query::ColumnType::Timestamp
                    | sea_orm::sea_query::ColumnType::DateTime
            )
            && matches!(&value, alibi_core::store::adapter::RawFieldValue::Text(_))
        {
            native.push((column, crate::additional_fields::bind_scalar(value)?));
        } else {
            let value = crate::additional_fields::prepare_value(db, &column, value).await?;
            M::set_additional_field(active, column, value, backend)?;
        }
    }
    Ok(native)
}

async fn save_account<M: SeaOrmAccountModel, C: ConnectionTrait>(
    mut active: M::ActiveModel,
    db: &C,
    id: Option<&str>,
    native: Vec<(M::Column, sea_orm::Value)>,
) -> AuthResult<Option<M>> {
    use sea_orm::sea_query::{Alias, Expr, ExprTrait, Query};
    use sea_orm::{ActiveModelBehavior, ActiveValue, DbBackend, EntityName, Iden, Iterable};
    let insert = id.is_none();
    if native.is_empty() && insert {
        return active.insert(db).await.map(Some).map_err(map_db_err);
    }
    active = ActiveModelBehavior::before_save(active, db, insert)
        .await
        .map_err(map_db_err)?;
    let backend = db.get_database_backend();
    let mysql_id = if backend == DbBackend::MySql {
        let column = <M::Entity as EntityTrait>::Column::iter()
            .find(|column| column.to_string() == M::id_column().to_string())
            .ok_or_else(|| {
                AuthError::config("Account entity does not expose its primary key column")
            })?;
        active.get(column).into_value()
    } else {
        None
    };
    let mut columns = Vec::new();
    let mut values = Vec::new();
    for column in <M::Entity as EntityTrait>::Column::iter() {
        let override_value = native
            .iter()
            .find(|(physical, _)| physical.to_string() == column.to_string())
            .map(|(_, value)| value.clone());
        let staged = match active.take(column) {
            ActiveValue::Set(value) => Some(value),
            ActiveValue::Unchanged(value) if insert => Some(value),
            _ => None,
        };
        if let Some(value) = override_value.or(staged) {
            let expression = if backend == DbBackend::Postgres {
                match &value {
                    sea_orm::Value::String(Some(value))
                        if matches!(
                            column.def().get_column_type(),
                            sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                                | sea_orm::sea_query::ColumnType::Timestamp
                                | sea_orm::sea_query::ColumnType::DateTime
                        ) =>
                    {
                        Expr::cust(alibi_core::store::postgres_parameter::quoted_literal(value))
                            .cast_as(Alias::new(
                                if matches!(
                                    column.def().get_column_type(),
                                    sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                                ) {
                                    "timestamptz"
                                } else {
                                    "timestamp"
                                },
                            ))
                    }
                    _ => Expr::val(value).into(),
                }
            } else {
                Expr::val(value).into()
            };
            columns.push(column);
            values.push(column.save_as(expression));
        }
    }
    let statement = if let Some(id) = id {
        let mut query = Query::update()
            .table(M::Entity::default().table_ref())
            .values(columns.into_iter().zip(values))
            .and_where(M::id_column().eq(M::parse_id(id)?))
            .to_owned();
        if backend != DbBackend::MySql {
            _ = query
                .returning(Query::returning().columns(<M::Entity as EntityTrait>::Column::iter()));
        }
        backend.build(&query)
    } else {
        let mut query = Query::insert()
            .into_table(M::Entity::default().table_ref())
            .columns(columns)
            .values(values)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .to_owned();
        if backend != DbBackend::MySql {
            _ = query
                .returning(Query::returning().columns(<M::Entity as EntityTrait>::Column::iter()));
        }
        backend.build(&query)
    };
    let account = if backend == DbBackend::MySql {
        let result = db.execute_raw(statement).await.map_err(map_db_err)?;
        // SQLx enables FOUND_ROWS: zero means no matched account, not an
        // unchanged value. UPDATE must never fall back to an insert identifier.
        if !insert && result.rows_affected() == 0 {
            return Ok(None);
        }
        let lookup = if let Some(id) = id {
            M::id_column().eq(M::parse_id(id)?)
        } else {
            M::id_column().eq(mysql_id.unwrap_or_else(|| result.last_insert_id().into()))
        };
        let Some(account) = M::Entity::find()
            .filter(lookup)
            .one(db)
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        account
    } else {
        let Some(row) = db.query_one_raw(statement).await.map_err(map_db_err)? else {
            return Ok(None);
        };
        M::from_query_result(&row, "").map_err(map_db_err)?
    };
    <M::ActiveModel as ActiveModelBehavior>::after_save(account, db, insert)
        .await
        .map(Some)
        .map_err(map_db_err)
}

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
        let native = stage_account_fields::<S::Account, _>(db, &mut active, &fields).await?;
        let account = save_account::<S::Account, _>(active, db, None, native)
            .await?
            .ok_or_else(|| map_db_err(sea_orm::DbErr::RecordNotInserted))?;
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
            .await?
            .ok_or_else(|| AuthError::not_found("Account not found"))
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
    ) -> AuthResult<Option<S::Account>> {
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
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.take_timestamp_input("accessTokenExpiresAt", &mut update.access_token_expires_at);
        fields.take_timestamp_input(
            "refreshTokenExpiresAt",
            &mut update.refresh_token_expires_at,
        );
        fields.apply_adapter_transforms_async().await?;
        let mut active = <S::Account as SeaOrmAccountModel>::Entity::find()
            .filter(<S::Account as SeaOrmAccountModel>::id_column().eq(account_id))
            .one(connection)
            .await
            .map_err(map_db_err)?
            .map(IntoActiveModel::into_active_model)
            .unwrap_or_else(ActiveModelTrait::default);
        S::Account::apply_update(&mut active, update, Utc::now().trunc_subsecs(3));
        let native =
            stage_account_fields::<S::Account, _>(connection, &mut active, &fields).await?;
        let account = save_account::<S::Account, _>(active, connection, Some(id), native).await?;
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
