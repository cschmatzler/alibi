//! SeaORM-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_key_numbers;
mod api_keys;
mod bundled_schema;
mod device_code_user_reference;
mod device_codes;
pub mod entities;
mod identity_fields;
mod invitations;
mod jwks;
mod members;
mod migrator;
mod nullable_user_flags;
#[cfg(test)]
mod nullable_user_tests;
mod organization_extensions;
mod organization_roles;
mod organizations;
mod passkeys;
mod sessions;
mod siwe_wallets;
mod sqlite_number;
mod teams;
mod two_factor;
mod two_factor_user_reference;
mod user_reference;
#[cfg(test)]
mod two_factor_policy_tests;
mod two_factor_verification_policy;
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

use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, SqlErr, TransactionTrait};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult, DatabaseError};
use crate::hooks::{SeaOrmHookContext, SeaOrmHooks, current_request_hook_context};
use crate::schema::{
    AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};

#[derive(Clone)]
pub struct SeaOrmStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    db: DatabaseConnection,
    hooks: Vec<Arc<dyn SeaOrmHooks<S>>>,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> SeaOrmStore<S> {
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        Self {
            config: config.into(),
            db,
            hooks: Vec::new(),
            _schema: PhantomData,
        }
    }

    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn SeaOrmHooks<S>>>) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn hook<H: SeaOrmHooks<S> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    pub fn config(&self) -> &Arc<AuthConfig> {
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
    Verification(S::Verification),
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
    async fn create_user(&self, create_user: better_auth_core::CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
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
                                hook.after_create_user(user, &hook_context).await?
                            }
                            AfterCreate::Account(account) => {
                                hook.after_create_account(account, &hook_context).await?
                            }
                            AfterCreate::Session(session) => {
                                hook.after_create_session(session, &hook_context).await?
                            }
                            AfterCreate::Verification(verification) => {
                                hook.after_create_verification(verification, &hook_context)
                                    .await?
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

fn map_db_err(err: DbErr) -> AuthError {
    match err.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::Constraint(message))
        }
        Some(SqlErr::ForeignKeyConstraintViolation(message)) => {
            AuthError::Database(DatabaseError::Constraint(message))
        }
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

pub(crate) fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

fn parse_rfc3339(value: &str, field: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}
