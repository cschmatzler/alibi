use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DatabaseTransaction};

use better_auth_core::AuthResult;
use better_auth_core::config::AuthConfig;
use better_auth_core::hooks::RequestHookContext;
pub use better_auth_core::hooks::current_request_hook_context;
use better_auth_core::schema::AuthSchema;
use better_auth_core::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
    UpdateVerification,
};

/// Control flow returned by `SeaORM` `before_*` hooks.
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

/// Context passed to `SeaORM` lifecycle hooks.
pub struct SeaOrmHookContext<'a> {
    pub config: &'a AuthConfig,
    pub db: &'a DatabaseConnection,
    /// Present for writes inside an auth transaction. Creation after hooks
    /// run only after a successful commit and receive no active transaction.
    pub tx: Option<&'a DatabaseTransaction>,
    pub request: Option<RequestHookContext>,
}

impl std::fmt::Debug for SeaOrmHookContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaOrmHookContext").finish_non_exhaustive()
    }
}

/// `SeaORM` lifecycle hooks for intercepting auth writes.
///
/// Transactional creation after callbacks retain the created snapshots and
/// run in operation order after commit. Rollback discards them; callback errors
/// are returned to the caller after the auth writes have committed.
#[async_trait]
pub trait SeaOrmHooks<S: AuthSchema>: Send + Sync {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_user(
        &self,
        _user: &S::User,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_update_user(
        &self,
        _id: &str,
        _update: &mut UpdateUser,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_user(
        &self,
        _user: &S::User,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_user(
        &self,
        _user: &S::User,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_delete_user(
        &self,
        _user: &S::User,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_create_session(
        &self,
        _session: &mut CreateSession,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        _session: &S::Session,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_update_session(
        &self,
        _token: &str,
        _fields: &mut better_auth_core::field_policy::FieldValues,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_session(
        &self,
        _session: &S::Session,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_session(
        &self,
        _session: &S::Session,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _session: &S::Session,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_create_account(
        &self,
        _account: &mut CreateAccount,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        _account: &S::Account,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_update_account(
        &self,
        _id: &str,
        _update: &mut UpdateAccount,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_account(
        &self,
        _account: &S::Account,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_account(
        &self,
        _account: &S::Account,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_delete_account(
        &self,
        _account: &S::Account,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_create_verification(
        &self,
        _verification: &mut CreateVerification,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn before_delete_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn before_update_verification(
        &self,
        _id: &str,
        _update: &mut UpdateVerification,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        Ok(HookControl::Continue)
    }

    async fn after_update_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }

    async fn after_delete_verification(
        &self,
        _verification: &S::Verification,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        Ok(())
    }
}
