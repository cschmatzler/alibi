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
mod numeric_page;
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

use crate::hooks::{SqlxHookContext, SqlxHooks, current_request_hook_context};
use crate::pool::{Exec, SqlxPool, SqlxTransaction};
use crate::schema::{
    AuthSchema, SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
use async_trait::async_trait;
use better_auth_core::config::AuthConfig;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::SchemaMigrator;
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use chrono::{DateTime, Utc};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SqlxStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    pool: SqlxPool,
    hooks: Vec<Arc<dyn SqlxHooks<S>>>,
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
            _schema: PhantomData,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn SqlxHooks<S>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: SqlxHooks<S> + 'static>(mut self, hook: H) -> Self {
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

    pub(crate) fn hooks(&self) -> &[Arc<dyn SqlxHooks<S>>] {
        &self.hooks
    }

    pub(crate) const fn exec(&self) -> Exec<'_> {
        Exec::Pool(&self.pool)
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
    pub(crate) async fn in_transaction<T, F>(&self, immediate: bool, work: F) -> AuthResult<T>
    where
        F: for<'tx> FnOnce(
            &'tx SqlxTransaction,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = AuthResult<T>> + Send + 'tx>,
        >,
    {
        let transaction = self.pool.begin(immediate).await?;
        let value = work(&transaction).await?;
        transaction.commit().await?;
        Ok(value)
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the database connection check fails.
    pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
        match &self.pool {
            SqlxPool::Sqlite(pool) => sqlx::query("SELECT 1").execute(pool).await.map(drop),
            SqlxPool::Postgres(pool) => sqlx::query("SELECT 1").execute(pool).await.map(drop),
        }
    }
}

/// Installs the bundled auth schema in `better_auth_migrations`, the ledger
/// the `SeaORM` adapter also records.
#[async_trait]
impl<S: AuthSchema> SchemaMigrator for SqlxStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        migrator::run_migrations(&self.pool).await
    }
}

struct SqlxStoreTransaction<'a, S: AuthSchema> {
    store: &'a SqlxStore<S>,
    tx: &'a SqlxTransaction,
    pending_after: tokio::sync::Mutex<Vec<AfterCreate<S>>>,
}

enum AfterCreate<S: AuthSchema> {
    User(S::User),
    Account(S::Account),
    Session(S::Session),
    SessionUpdated(S::Session),
    SessionUpdateMissing(String),
    Verification(S::Verification),
    VerificationRecord(better_auth_core::verification::VerificationSnapshot),
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
    async fn list_jwks(&self) -> AuthResult<Vec<better_auth_core::types::Jwk>> {
        self.store.list_jwks_with(Exec::Tx(self.tx)).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<better_auth_core::types::Jwk>> {
        self.store.get_jwk_with(Exec::Tx(self.tx), id).await
    }
    async fn create_jwk(
        &self,
        data: better_auth_core::types::CreateJwk,
    ) -> AuthResult<better_auth_core::types::Jwk> {
        self.store.create_jwk_with(Exec::Tx(self.tx), data).await
    }

    async fn get_team(
        &self,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<Option<better_auth_core::types::Team>> {
        self.store
            .get_team_with_connection(Exec::Tx(self.tx), Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<better_auth_core::types::AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(
        &self,
        member: better_auth_core::CreateMember,
    ) -> AuthResult<better_auth_core::types::Member> {
        self.store
            .create_member_with_connection(Exec::Tx(self.tx), member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                Exec::Tx(self.tx),
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
                Exec::Tx(self.tx),
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        users::find_user_by_id::<S::User>(Exec::Tx(self.tx), id, users::Lock::None).await
    }
    async fn create_passkey(
        &self,
        data: better_auth_core::CreatePasskey,
    ) -> AuthResult<better_auth_core::Passkey> {
        self.store
            .create_passkey_with_connection(Exec::Tx(self.tx), data)
            .await
    }
    async fn create_user(&self, create_user: better_auth_core::CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::User(user.clone()));
        Ok(user)
    }

    async fn create_user_prepared(
        &self,
        prepared: better_auth_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::User(user.clone()));
        Ok(user)
    }

    async fn create_account(
        &self,
        create_account: better_auth_core::CreateAccount,
    ) -> AuthResult<S::Account> {
        let account = self
            .store
            .create_account_in_tx(self.tx, create_account)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Account(account.clone()));
        Ok(account)
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, better_auth_core::field_policy::FieldValues)>> {
        self.store
            .prepare_secondary_update_with_connection(
                Exec::Tx(self.tx),
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
        fields: better_auth_core::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        use better_auth_core::AuthSession;
        let token = session.token().to_owned();
        let result = self
            .store
            .complete_secondary_update_with_connection(
                Exec::Tx(self.tx),
                Some(self.tx),
                session,
                expires_at,
                fields,
                persist,
            )
            .await?;
        let event = result.as_ref().map_or_else(
            || AfterCreate::SessionUpdateMissing(token),
            |model| AfterCreate::SessionUpdated(model.clone()),
        );
        self.pending_after.lock().await.push(event);
        Ok(result)
    }
    async fn prepare_secondary_session_creation(
        &self,
        input: better_auth_core::CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .prepare_secondary_session_in_tx(self.tx, input, persist)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Session(session.clone()));
        Ok(session)
    }
    async fn create_session(
        &self,
        create_session: better_auth_core::CreateSession,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .create_session_in_tx(self.tx, create_session)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Session(session.clone()));
        Ok(session)
    }
    async fn create_verification_record(
        &self,
        data: better_auth_core::verification::VerificationCreation,
        publication: better_auth_core::verification::VerificationPublication,
    ) -> AuthResult<Option<better_auth_core::verification::VerificationSnapshot>> {
        let snapshot = self
            .store
            .create_verification_record_with_connection(
                Exec::Tx(self.tx),
                Some(self.tx),
                data,
                publication,
            )
            .await?;
        if let Some(snapshot) = &snapshot {
            self.pending_after
                .lock()
                .await
                .push(AfterCreate::VerificationRecord(snapshot.clone()));
        }
        Ok(snapshot)
    }

    async fn create_verification(
        &self,
        verification: better_auth_core::CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .store
            .create_verification_in_tx(self.tx, verification)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Verification(verification.clone()));
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
        let tx = self.pool.begin(false).await?;
        let tx_store = SqlxStoreTransaction {
            store: self,
            tx: &tx,
            pending_after: tokio::sync::Mutex::new(Vec::new()),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after.into_inner();
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                // The pinned adapter defers after callbacks until commit and
                // drops them on rollback. Preserve each created snapshot and
                // its operation order, including interleaved model writes.
                let hook_context = self.hook_context(None);
                for created in pending_after {
                    for hook in self.hooks() {
                        match &created {
                            AfterCreate::User(user) => {
                                hook.after_create_user(user, &hook_context).await?;
                            }
                            AfterCreate::Account(account) => {
                                hook.after_create_account(account, &hook_context).await?;
                            }
                            AfterCreate::Session(session) => {
                                hook.after_create_session(session, &hook_context).await?;
                            }
                            AfterCreate::SessionUpdated(session) => {
                                hook.after_update_session(session, &hook_context).await?;
                            }
                            AfterCreate::SessionUpdateMissing(token) => {
                                hook.after_update_session_missing(token, &hook_context)
                                    .await?;
                            }
                            AfterCreate::VerificationRecord(snapshot) => {
                                hook.after_create_verification_record(snapshot, &hook_context)
                                    .await?;
                            }
                            AfterCreate::Verification(verification) => {
                                hook.after_create_verification(verification, &hook_context)
                                    .await?;
                            }
                        }
                    }
                }
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await?;
                Err(err)
            }
        }
    }
}

pub(crate) fn parse_rfc3339(value: &str, field: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_error| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

pub(crate) fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}

/// `FOR UPDATE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_exclusive(sql: &mut crate::sql::Sql) {
    if sql.backend() == crate::pool::SqlxBackend::Postgres {
        sql.push(" FOR UPDATE");
    }
}

/// `FOR SHARE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_shared(sql: &mut crate::sql::Sql) {
    if sql.backend() == crate::pool::SqlxBackend::Postgres {
        sql.push(" FOR SHARE");
    }
}
