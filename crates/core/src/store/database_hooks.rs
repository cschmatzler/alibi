//! Database lifecycle hooks shared by the bundled persistence adapters.
//!
//! Each adapter names its connection and transaction handles through a
//! [`HookBackend`]; the hook contract and its ordering are the same for all.

use crate::config::AuthConfig;
use crate::error::AuthResult;
use crate::hooks::RequestHookContext;
use crate::schema::AuthSchema;
use crate::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
    UpdateVerification,
};
use async_trait::async_trait;

/// Control flow returned by database `before_*` hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookControl {
    Continue,
    Cancel,
}

impl HookControl {
    #[must_use]
    pub const fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancel)
    }
}

/// Database handles an adapter exposes to its lifecycle hooks.
pub trait HookBackend: Send + Sync + 'static {
    /// The adapter's shared connection or pool.
    type Connection: Send + Sync;
    /// The adapter's active auth transaction.
    type Transaction: Send + Sync;
}

/// Context passed to database lifecycle hooks.
pub struct DatabaseHookContext<'a, B: HookBackend> {
    pub config: &'a AuthConfig,
    pub db: &'a B::Connection,
    /// Present for writes inside an auth transaction. Creation after hooks
    /// run only after a successful commit and receive no active transaction.
    pub tx: Option<&'a B::Transaction>,
    pub request: Option<RequestHookContext>,
}

impl<B: HookBackend> std::fmt::Debug for DatabaseHookContext<'_, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseHookContext")
            .finish_non_exhaustive()
    }
}

/// Lifecycle hooks for intercepting auth writes.
///
/// Transactional creation after callbacks retain the created snapshots and
/// run in operation order after commit. Rollback discards them; callback errors
/// are returned to the caller after the auth writes have committed.
#[async_trait]
pub trait DatabaseHooks<S: AuthSchema, B: HookBackend>: Send + Sync {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_user(
        &self,
        _user: &S::User,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_update_user(
        &self,
        _id: &str,
        _update: &mut UpdateUser,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_user(
        &self,
        _user: &S::User,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_user(
        &self,
        _user: &S::User,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        _user: &S::User,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_create_session(
        &self,
        _session: &mut CreateSession,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        _session: &S::Session,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_update_session(
        &self,
        _token: &str,
        _fields: &mut crate::field_policy::FieldValues,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    /// Observe an update that ran its before hooks but found no persisted row.
    /// A before-hook veto does not invoke this callback.
    async fn after_update_session_missing(
        &self,
        _token: &str,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn after_update_session(
        &self,
        _session: &S::Session,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_session(
        &self,
        _session: &S::Session,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _session: &S::Session,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_create_account(
        &self,
        _account: &mut CreateAccount,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        _account: &S::Account,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_update_account(
        &self,
        _id: &str,
        _update: &mut UpdateAccount,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_account(
        &self,
        _account: &S::Account,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_account(
        &self,
        _account: &S::Account,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        _account: &S::Account,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_create_verification(
        &self,
        _verification: &mut CreateVerification,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    /// Observe initialized defaults and transform the actual admitted candidate.
    /// The legacy domain hook remains available for existing applications.
    async fn before_create_verification_record(
        &self,
        candidate: &mut crate::verification::VerificationCreation,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        let mut data = candidate.data();
        let control = self.before_create_verification(&mut data, ctx).await?;
        candidate.identifier = data.identifier;
        candidate.value = data.value;
        candidate.expires_at = data.expires_at;
        Ok(control)
    }

    /// Secondary-only values have no invented model or ID. The legacy model
    /// callback is invoked only when a real physical model was persisted.
    async fn after_create_verification_record(
        &self,
        snapshot: &crate::verification::VerificationSnapshot,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        if let Some(model) = snapshot.original_model::<S::Verification>() {
            self.after_create_verification(model, ctx).await?;
        }
        Ok(())
    }

    async fn after_create_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn before_update_verification(
        &self,
        _id: &str,
        _update: &mut UpdateVerification,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }

    /// Identifier updates invoke after hooks even when the adapter matched no
    /// row. Actual physical snapshots bridge the existing model callback.
    async fn after_update_verification_record(
        &self,
        snapshot: Option<&crate::verification::VerificationSnapshot>,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        if let Some(model) = snapshot.and_then(|value| value.original_model::<S::Verification>()) {
            self.after_update_verification(model, ctx).await?;
        }
        Ok(())
    }

    async fn after_delete_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        Ok(())
    }
}
