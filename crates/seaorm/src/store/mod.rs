//! SeaORM-backed persistence implementation for built-in auth tables.

mod scoped_connection;
use scoped_connection::{ScopedConnection, ScopedTransaction};
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
mod organization_roles;
mod organizations;
mod passkeys;
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

#[async_trait]
impl<S: AuthSchema> alibi_core::store::SchemaMigrator for SeaOrmStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        if self.db.get_database_backend() == sea_orm::DbBackend::Postgres {
            if let Some(schema) = &self.db.schema {
                use sea_orm::{ConnectionTrait, Statement};
                use sea_orm_migration::MigratorTrait;
                let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
                let _ = self
                    .db
                    .inner
                    .execute_unprepared(&format!("CREATE SCHEMA IF NOT EXISTS {quoted}"))
                    .await
                    .map_err(map_db_err)?;
                // Only the migration transaction has a local DDL namespace.
                // Runtime connections and statements retain statement qualification.
                let transaction = self.db.inner.begin().await.map_err(map_db_err)?;
                let _ = transaction
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
        }
        migrator::run_migrations(&self.db.inner)
            .await
            .map_err(map_db_err)
    }
}

use crate::hooks::{DatabaseHooks, SeaOrmBackend, SeaOrmHookContext, current_request_hook_context};
use crate::schema::{
    AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
use alibi_core::config::AuthConfig;
use alibi_core::error::{AuthError, AuthResult, DatabaseError};
use alibi_core::store::adapter::{AfterHook, AfterHookQueue};
use alibi_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DbErr, SqlErr, TransactionTrait};
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
    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        let config = config.into();
        let schema = config.advanced.database.schema_name.clone();
        Self {
            config,
            db: ScopedConnection { inner: db, schema },
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
    async fn list_jwks(&self) -> AuthResult<Vec<alibi_core::types::Jwk>> {
        self.store.list_jwks_with_connection(self.tx).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<alibi_core::types::Jwk>> {
        self.store.get_jwk_with_connection(self.tx, id).await
    }
    async fn create_jwk(
        &self,
        data: alibi_core::types::CreateJwk,
    ) -> AuthResult<alibi_core::types::Jwk> {
        self.store.create_jwk_with_connection(self.tx, data).await
    }

    async fn get_team(
        &self,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<Option<alibi_core::types::Team>> {
        self.store
            .get_team_with_connection(self.tx, Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<alibi_core::types::AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(
        &self,
        member: alibi_core::CreateMember,
    ) -> AuthResult<alibi_core::types::Member> {
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
    async fn create_passkey(
        &self,
        data: alibi_core::CreatePasskey,
    ) -> AuthResult<alibi_core::Passkey> {
        self.store
            .create_passkey_with_connection(self.tx, data)
            .await
    }
    async fn create_user(&self, create_user: alibi_core::CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_user_prepared(
        &self,
        prepared: alibi_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_account(
        &self,
        create_account: alibi_core::CreateAccount,
    ) -> AuthResult<S::Account> {
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
        fields: alibi_core::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, alibi_core::field_policy::FieldValues)>> {
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
        fields: alibi_core::field_policy::FieldValues,
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
        input: alibi_core::CreateSession,
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
    async fn create_session(
        &self,
        create_session: alibi_core::CreateSession,
    ) -> AuthResult<S::Session> {
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
        data: alibi_core::verification::VerificationCreation,
        publication: alibi_core::verification::VerificationPublication,
    ) -> AuthResult<Option<alibi_core::verification::VerificationSnapshot>> {
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
        verification: alibi_core::CreateVerification,
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

mod oauth_token_conversion;
