//! SeaORM-backed persistence implementation for built-in auth tables.

mod account_key_multiplicity;
#[cfg(test)]
mod account_multiplicity_tests;
mod accounts;
mod api_key_numbers;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_code_user_reference;
mod device_codes;
pub mod entities;
mod identity_fields;
#[cfg(test)]
mod invitation_staging_tests;
mod invitations;
mod jwks;
#[cfg(test)]
mod member_multiplicity_tests;
mod member_pair_multiplicity;
#[cfg(test)]
mod member_removal_tests;
#[cfg(test)]
mod member_role_tests;
mod members;
mod migrator;
mod nullable_organization_metadata;
#[cfg(test)]
mod nullable_organization_tests;
mod nullable_user_flags;
#[cfg(test)]
mod nullable_user_tests;
mod numeric_page;
#[cfg(test)]
mod numeric_page_tests;
#[cfg(test)]
mod organization_deletion_tests;
mod organization_extensions;
mod organization_reference;
#[cfg(test)]
mod organization_reference_tests;
mod organization_roles;
mod organizations;
mod passkeys;
mod sessions;
mod siwe_wallets;
mod sqlite_number;
mod teams;
mod two_factor;
#[cfg(test)]
mod two_factor_policy_tests;
mod two_factor_user_reference;
mod two_factor_verification_policy;
mod user_reference;
mod users;
mod verifications;
#[cfg(test)]
mod wallet_tests;
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

use crate::hooks::{SeaOrmHookContext, SeaOrmHooks, current_request_hook_context};
use crate::schema::{
    AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
use async_trait::async_trait;
use better_auth_core::config::AuthConfig;
use better_auth_core::error::{AuthError, AuthResult, DatabaseError};
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, SqlErr, TransactionTrait};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    db: DatabaseConnection,
    hooks: Vec<Arc<dyn SeaOrmHooks<S>>>,
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
        Self {
            config: config.into(),
            db,
            hooks: Vec::new(),
            _schema: PhantomData,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn SeaOrmHooks<S>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: SeaOrmHooks<S> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub const fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn SeaOrmHooks<S>>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a DatabaseTransaction>,
    ) -> SeaOrmHookContext<'a> {
        SeaOrmHookContext {
            config: self.config.as_ref(),
            db: &self.db,
            tx,
            request: current_request_hook_context(),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the database connection check fails.
    pub async fn test_connection(&self) -> Result<(), DbErr> {
        self.db.ping().await
    }
}

struct SeaOrmTransaction<'a, S: AuthSchema> {
    store: &'a SeaOrmStore<S>,
    tx: &'a DatabaseTransaction,
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
impl<S> AuthTransaction<S> for SeaOrmTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn get_team(
        &self,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<Option<better_auth_core::types::Team>> {
        self.store
            .get_team_with_connection(self.tx, Some(organization_id), team_id)
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
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let id = S::User::parse_id(id)?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(S::User::id_column().eq(id))
            .one(self.tx)
            .await
            .map_err(map_db_err)
    }
    async fn create_passkey(
        &self,
        data: better_auth_core::CreatePasskey,
    ) -> AuthResult<better_auth_core::Passkey> {
        self.store
            .create_passkey_with_connection(self.tx, data)
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
        fields: better_auth_core::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        use better_auth_core::AuthSession;
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
            .create_verification_record_with_connection(self.tx, Some(self.tx), data, publication)
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
        let tx_store = SeaOrmTransaction {
            store: self,
            tx: &tx,
            pending_after: tokio::sync::Mutex::new(Vec::new()),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after.into_inner();
        match outcome {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
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

pub(crate) fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

fn parse_rfc3339(value: &str, field: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_error| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}

/// Match the pinned SQLite adapter's decimal formatting of finite REAL values.
pub(crate) fn sqlite_real_text(input: f64) -> String {
    sqlite_number::real_text(input)
}
