//! SeaORM-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_codes;
pub mod entities;
mod invitations;
mod jwks;
mod members;
mod migrator;
mod oauth_token_conversion;
mod organization_roles;
mod organizations;
mod passkeys;
mod scoped_connection;
mod sessions;
mod teams;
mod two_factor;
mod users;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::{AuthMigrator, run_migrations};
    }
}

use crate::hooks::{DatabaseHooks, SeaOrmBackend, SeaOrmHookContext, current_request_hook_context};
use crate::schema::{
    AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
use alibi_core::config::AuthConfig;
use alibi_core::error::{AuthError, AuthResult, DatabaseError};
use alibi_core::field_policy::FieldValues;
use alibi_core::store::SchemaMigrator;
use alibi_core::store::adapter::{AfterHook, AfterHookQueue};
use alibi_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use alibi_core::types::{AddTeamMemberResult, CreateJwk, Jwk, Member, Team};
use alibi_core::user_validation::PreparedUserCreation;
use alibi_core::verification::{
    VerificationCreation, VerificationPublication, VerificationSnapshot,
};
use alibi_core::{
    CreateAccount, CreateMember, CreatePasskey, CreateSession, CreateUser, CreateVerification,
    Passkey,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use scoped_connection::{ScopedConnection, ScopedTransaction};
use sea_orm::{DatabaseConnection, DbErr, EntityTrait, SqlErr, TransactionTrait};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    db: ScopedConnection,
    hooks: Vec<Arc<dyn DatabaseHooks<S, SeaOrmBackend>>>,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> std::fmt::Debug for SeaOrmStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaOrmStore").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    pub(crate) async fn generated_id<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        model: &str,
        table: &str,
        column: &str,
    ) -> AuthResult<Option<String>> {
        let policy = &self.config.advanced.database;
        if !policy.serial_ids() {
            return policy.generated_id(model);
        }
        let backend = db.get_database_backend();
        let [ddl, allocate] = alibi_core::config::serial_id_statements(
            table,
            column,
            backend == sea_orm::DbBackend::Postgres,
        );
        _ = db.execute_unprepared(&ddl).await.map_err(map_db_err)?;
        let row = db
            .query_one_raw(sea_orm::Statement::from_string(backend, allocate))
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::internal("ID allocation returned no value"))?;
        let value: i64 = row.try_get("", "value").map_err(map_db_err)?;
        Ok(Some(value.to_string()))
    }

    /// `generated_id` for a model entity, naming its table and ID column.
    pub(crate) async fn generated_entity_id<E: EntityTrait, C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        model: &str,
        id_column: impl sea_orm::Iden,
    ) -> AuthResult<Option<String>> {
        let table = E::default().table_name().to_owned();
        self.generated_id(db, model, &table, &id_column.to_string())
            .await
    }

    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        let config = config.into();
        let schema = config.advanced.database.schema_name.clone();
        let factor = config.advanced.database.two_factor.clone();
        Self {
            config,
            db: ScopedConnection {
                inner: db,
                schema,
                factor,
            },
            hooks: Vec::new(),
            _schema: PhantomData,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks<S, SeaOrmBackend>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: DatabaseHooks<S, SeaOrmBackend> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub(super) const fn scoped_connection(&self) -> &ScopedConnection {
        &self.db
    }

    pub const fn connection(&self) -> &DatabaseConnection {
        &self.db.inner
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DatabaseHooks<S, SeaOrmBackend>>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a ScopedTransaction>,
    ) -> SeaOrmHookContext<'a> {
        SeaOrmHookContext {
            config: self.config.as_ref(),
            db: &self.db.inner,
            tx: tx.map(|tx| &tx.inner),
            request: current_request_hook_context(),
        }
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    async fn migrate_bundled_schema(&self) -> AuthResult<()> {
        if self.db.get_database_backend() == sea_orm::DbBackend::Postgres
            && let Some(schema) = &self.db.schema
        {
            use sea_orm::{ConnectionTrait, Statement};
            use sea_orm_migration::MigratorTrait;
            let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
            _ = self
                .db
                .inner
                .execute_unprepared(&format!("CREATE SCHEMA IF NOT EXISTS {quoted}"))
                .await
                .map_err(map_db_err)?;
            // Only the migration transaction has a local DDL namespace.
            // Runtime connections and statements retain statement qualification.
            let transaction = self.db.inner.begin().await.map_err(map_db_err)?;
            _ = transaction
                .execute_raw(Statement::from_string(
                    sea_orm::DbBackend::Postgres,
                    format!("SET LOCAL search_path TO {quoted}"),
                ))
                .await
                .map_err(map_db_err)?;
            migrator::AuthMigrator::up(&transaction, None)
                .await
                .map_err(map_db_err)?;
            return transaction.commit().await.map_err(map_db_err);
        }
        migrator::run_migrations(&self.db.inner)
            .await
            .map_err(map_db_err)
    }
}

#[async_trait]
impl<S: AuthSchema> SchemaMigrator for SeaOrmStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        self.migrate_bundled_schema().await?;
        if self.config.advanced.database.serial_ids() {
            use sea_orm::ConnectionTrait;
            let [ddl, _] = alibi_core::config::serial_id_statements("", "", false);
            _ = self.db.execute_unprepared(&ddl).await.map_err(map_db_err)?;
        }
        if let Some(mapping) = &self.config.advanced.database.two_factor {
            use sea_orm::ConnectionTrait;
            let commands = mapping.migration_statements()?;
            let transaction = self.db.begin().await.map_err(map_db_err)?;
            if transaction
                .has_table("two_factor")
                .await
                .map_err(map_db_err)?
            {
                for command in commands {
                    _ = transaction
                        .execute_unprepared(&command)
                        .await
                        .map_err(map_db_err)?;
                }
            }
            transaction.commit().await.map_err(map_db_err)?;
        }
        Ok(())
    }
}

struct SeaOrmStoreTransaction<'a, S: AuthSchema> {
    store: &'a SeaOrmStore<S>,
    tx: &'a ScopedTransaction,
    pending_after: AfterHookQueue<S>,
}

#[async_trait]
impl<S> AuthTransaction<S> for SeaOrmStoreTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.store.list_jwks_with_connection(self.tx).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.store.get_jwk_with_connection(self.tx, id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.store.create_jwk_with_connection(self.tx, data).await
    }

    async fn get_team(&self, organization_id: &str, team_id: &str) -> AuthResult<Option<Team>> {
        self.store
            .get_team_with_connection(self.tx, Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.store
            .create_member_with_connection(self.tx, member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                self.tx,
                token,
                sessions::SessionScope::Team(team_id),
            )
            .await
    }
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                self.tx,
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        users::provider_verification_output::<S::User, _>(self.tx, id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let id = S::User::parse_id(id)?;
        users::user_query::<S::User>(self.tx.get_database_backend())
            .filter(S::User::id_column().eq(id))
            .one(self.tx)
            .await
            .map_err(map_db_err)
    }
    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.store
            .create_passkey_with_connection(self.tx, data)
            .await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        let account = self
            .store
            .create_account_in_tx(self.tx, create_account)
            .await?;
        self.pending_after
            .push(AfterHook::AccountCreated(account.clone()))
            .await;
        Ok(account)
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        self.store
            .prepare_secondary_update_with_connection(
                self.tx,
                Some(self.tx),
                session,
                expires_at,
                fields,
            )
            .await
    }
    async fn complete_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        use alibi_core::AuthSession;
        let token = session.token().to_owned();
        let result = self
            .store
            .complete_secondary_update_with_connection(
                self.tx,
                Some(self.tx),
                session,
                expires_at,
                fields,
                persist,
            )
            .await?;
        let event = result.as_ref().map_or_else(
            || AfterHook::SessionUpdateMissing(token),
            |model| AfterHook::SessionUpdated(model.clone()),
        );
        self.pending_after.push(event).await;
        Ok(result)
    }
    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .prepare_secondary_session_in_tx(self.tx, input, persist)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        let session = self
            .store
            .create_session_in_tx(self.tx, create_session)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let snapshot = self
            .store
            .create_verification_record_with_connection(self.tx, Some(self.tx), data, publication)
            .await?;
        if let Some(snapshot) = &snapshot {
            self.pending_after
                .push(AfterHook::VerificationRecordCreated(snapshot.clone()))
                .await;
        }
        Ok(snapshot)
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .store
            .create_verification_in_tx(self.tx, verification)
            .await?;
        self.pending_after
            .push(AfterHook::VerificationCreated(verification.clone()))
            .await;
        Ok(verification)
    }
}

#[async_trait]
impl<S> TransactionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.db.begin().await.map_err(map_db_err)?;
        let tx_store = SeaOrmStoreTransaction {
            store: self,
            tx: &tx,
            pending_after: AfterHookQueue::new(),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after;
        match outcome {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                // After hooks run only once the auth writes are durable, in
                // operation order; rollback drops them.
                pending_after
                    .run(self.hooks(), &self.hook_context(None))
                    .await?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(err)
            }
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
pub(crate) fn map_db_err(err: DbErr) -> AuthError {
    match err.sql_err() {
        Some(
            SqlErr::UniqueConstraintViolation(message)
            | SqlErr::ForeignKeyConstraintViolation(message),
        ) => AuthError::Database(DatabaseError::Constraint(message)),
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

/// Bind raw numeric `LIMIT`/`OFFSET` values; the database validates them.
pub(crate) fn bind_page(
    mut statement: sea_orm::Statement,
    limit: Option<f64>,
    offset: Option<f64>,
) -> AuthResult<sea_orm::Statement> {
    use sea_orm::{DbBackend, Value, Values};
    use std::fmt::Write;
    for (clause, number) in [("LIMIT", limit), ("OFFSET", offset)] {
        if let Some(number) = number {
            let values = statement.values.get_or_insert_with(|| Values(Vec::new()));
            let placeholder = match statement.db_backend {
                DbBackend::Postgres => format!("${}", values.0.len() + 1),
                DbBackend::Sqlite | DbBackend::MySql => "?".into(),
                _ => {
                    return Err(AuthError::not_implemented(
                        "Raw numeric pages are not supported by this database backend",
                    ));
                }
            };
            _ = write!(statement.sql, " {clause} {placeholder}");
            if statement.db_backend == DbBackend::Postgres {
                // node-postgres sends Number parameters as text. Binding float8
                // instead lets PostgreSQL round fractional pages to bigint.
                statement.sql.push_str("::bigint");
                values.0.push(Value::String(Some(
                    ryu_js::Buffer::new().format(number).to_owned(),
                )));
            } else {
                values.0.push(Value::Double(Some(number)));
            }
        }
    }
    Ok(statement)
}
