//! `SQLx`-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_codes;
pub mod entities;
mod invitations;
mod jwks;
mod members;
pub(crate) mod migrator;
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
        pub use super::super::migrator::run_migrations;
    }
}

use crate::hooks::{DatabaseHooks, SqlxBackend, SqlxHookContext, current_request_hook_context};
use crate::pool::{Exec, SqlxPool, SqlxTransaction};
use crate::schema::{
    AuthSchema, SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
use alibi_core::config::AuthConfig;
use alibi_core::error::AuthResult;
use alibi_core::store::SchemaMigrator;
use alibi_core::store::adapter::{AfterHook, AfterHookQueue};
use alibi_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SqlxStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    pool: SqlxPool,
    hooks: Vec<Arc<dyn DatabaseHooks<S, SqlxBackend>>>,
    organization_models: crate::OrganizationModels,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> std::fmt::Debug for SqlxStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlxStore").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> SqlxStore<S> {
    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, pool: impl Into<SqlxPool>) -> Self {
        Self {
            config: config.into(),
            pool: pool.into(),
            hooks: Vec::new(),
            organization_models: crate::OrganizationModels::default(),
            _schema: PhantomData,
        }
    }

    /// Bind the organization plugin to application-owned tables.
    #[must_use]
    pub fn with_organization_models(mut self, models: crate::OrganizationModels) -> Self {
        self.organization_models = models;
        self
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks<S, SqlxBackend>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: DatabaseHooks<S, SqlxBackend> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub const fn pool(&self) -> &SqlxPool {
        &self.pool
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DatabaseHooks<S, SqlxBackend>>] {
        &self.hooks
    }

    pub(crate) async fn generated_id(
        &self,
        exec: Exec<'_>,
        model: &str,
        table: &str,
        column: &str,
    ) -> AuthResult<Option<String>> {
        let policy = &self.config.advanced.database;
        if !policy.serial_ids() {
            return policy.generated_id(model);
        }
        let [ddl, allocate] = alibi_core::config::serial_id_statements(
            table,
            column,
            exec.engine() == crate::pool::Engine::Postgres,
        );
        let mut sql = crate::sql::Sql::new(exec.engine());
        sql.push(&ddl);
        _ = exec.execute(sql).await?;
        let mut sql = crate::sql::Sql::new(exec.engine());
        sql.push(&allocate);
        let value = exec
            .fetch_scalar::<i64>(sql)
            .await?
            .ok_or_else(|| alibi_core::AuthError::internal("ID allocation returned no value"))?;
        Ok(Some(value.to_string()))
    }

    async fn begin(&self, immediate: bool) -> AuthResult<SqlxTransaction> {
        let mut transaction = self.pool.begin(immediate).await?;
        transaction.config = Some(self.config.clone());
        Ok(transaction)
    }

    pub(crate) fn exec(&self) -> Exec<'_> {
        Exec::pool(&self.pool).with_config(self.config.as_ref())
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a SqlxTransaction>,
    ) -> SqlxHookContext<'a> {
        SqlxHookContext {
            config: self.config.as_ref(),
            db: &self.pool,
            tx,
            request: current_request_hook_context(),
        }
    }

    pub(crate) fn find_many_limit(&self) -> i64 {
        // Mirrors the unsigned page binding of the reference adapter.
        i64::try_from(self.config.advanced.database.default_find_many_limit).unwrap_or(i64::MAX)
    }

    /// Run work on a fresh transaction, committing on success. On failure the
    /// transaction is dropped, which rolls it back, and the work's error returns.
    pub(crate) async fn in_transaction<T>(
        &self,
        immediate: bool,
        work: impl AsyncFnOnce(&SqlxTransaction) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let transaction = self.begin(immediate).await?;
        let value = work(&transaction).await?;
        transaction.commit().await?;
        Ok(value)
    }
}

/// Installs the bundled auth schema in `better_auth_migrations`, the ledger
/// the `SeaORM` adapter also records.
#[async_trait]
impl<S: AuthSchema> SchemaMigrator for SqlxStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        migrator::run_migrations_scoped(&self.pool, &self.config).await?;
        if self.config.advanced.database.serial_ids() {
            let [ddl, _] = alibi_core::config::serial_id_statements("", "", false);
            let exec = self.exec();
            _ = exec
                .execute(crate::sql::Sql::with(exec.engine(), &ddl))
                .await?;
        }
        if let Some(mapping) = &self.config.advanced.database.two_factor {
            let commands = mapping.migration_statements()?;
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                if migrator::has_table(exec, "two_factor").await? {
                    for command in commands {
                        _ = exec
                            .execute(crate::sql::Sql::with(exec.engine(), &command))
                            .await?;
                    }
                }
                Ok(())
            })
            .await?;
        }
        Ok(())
    }
}

struct SqlxStoreTransaction<'a, S: AuthSchema> {
    store: &'a SqlxStore<S>,
    tx: &'a SqlxTransaction,
    pending_after: AfterHookQueue<S>,
}

#[async_trait]
impl<S> AuthTransaction<S> for SqlxStoreTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Account: SqlxAccountModel,
    S::Session: SqlxSessionModel,
    S::Verification: SqlxVerificationModel,
{
    async fn list_jwks(&self) -> AuthResult<Vec<alibi_core::types::Jwk>> {
        self.store.list_jwks_with(Exec::tx(self.tx)).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<alibi_core::types::Jwk>> {
        self.store.get_jwk_with(Exec::tx(self.tx), id).await
    }
    async fn create_jwk(
        &self,
        data: alibi_core::types::CreateJwk,
    ) -> AuthResult<alibi_core::types::Jwk> {
        self.store.create_jwk_with(Exec::tx(self.tx), data).await
    }

    async fn get_team(
        &self,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<Option<alibi_core::types::Team>> {
        self.store
            .get_team_with_connection(Exec::tx(self.tx), Some(organization_id), team_id)
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
            .create_member_with_connection(Exec::tx(self.tx), member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                Exec::tx(self.tx),
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
                Exec::tx(self.tx),
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        users::provider_verification_output::<S::User>(Exec::tx(self.tx), id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        users::find_user_by_id::<S::User>(Exec::tx(self.tx), id, users::Lock::None).await
    }
    async fn create_passkey(
        &self,
        data: alibi_core::CreatePasskey,
    ) -> AuthResult<alibi_core::Passkey> {
        self.store
            .create_passkey_with_connection(Exec::tx(self.tx), data)
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
                Exec::tx(self.tx),
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
                Exec::tx(self.tx),
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
            .create_verification_record_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                data,
                publication,
            )
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
impl<S> TransactionStore<S> for SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Account: SqlxAccountModel,
    S::Session: SqlxSessionModel,
    S::Verification: SqlxVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.begin(false).await?;
        let tx_store = SqlxStoreTransaction {
            store: self,
            tx: &tx,
            pending_after: AfterHookQueue::new(),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after;
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                // After hooks run only once the auth writes are durable, in
                // operation order; rollback drops them.
                pending_after
                    .run(self.hooks(), &self.hook_context(None))
                    .await?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await?;
                Err(err)
            }
        }
    }
}

/// `FOR UPDATE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_exclusive(sql: &mut crate::sql::Sql) {
    if sql.engine() == crate::pool::Engine::Postgres {
        sql.push(" FOR UPDATE");
    }
}

/// `FOR SHARE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_shared(sql: &mut crate::sql::Sql) {
    if sql.engine() == crate::pool::Engine::Postgres {
        sql.push(" FOR SHARE");
    }
}

/// Bind raw numeric `LIMIT`/`OFFSET` values; the database validates them.
pub(crate) fn bind_page(sql: &mut crate::sql::Sql, limit: Option<f64>, offset: Option<f64>) {
    for (clause, number) in [(" LIMIT ", limit), (" OFFSET ", offset)] {
        if let Some(number) = number {
            sql.push(clause);
            if sql.engine() == crate::pool::Engine::Postgres {
                // node-postgres sends Number parameters as text. Binding float8
                // instead lets PostgreSQL round fractional pages to bigint.
                sql.bind(ryu_js::Buffer::new().format(number).to_owned());
                sql.push("::bigint");
            } else {
                sql.bind(number);
            }
        }
    }
}

mod oauth_token_conversion;
