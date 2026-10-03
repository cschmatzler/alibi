//! `SeaORM` bindings for the shared database lifecycle hooks.

pub use better_auth_core::hooks::current_request_hook_context;
use better_auth_core::schema::AuthSchema;
pub use better_auth_core::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use sea_orm::{DatabaseConnection, DatabaseTransaction};

/// The `SeaORM` hook backend: hooks receive its connection and transaction.
#[derive(Debug, Clone, Copy)]
pub struct SeaOrm;

impl HookBackend for SeaOrm {
    type Connection = DatabaseConnection;
    type Transaction = DatabaseTransaction;
}

/// Context passed to `SeaORM` lifecycle hooks.
pub type SeaOrmHookContext<'a> = DatabaseHookContext<'a, SeaOrm>;

/// `SeaORM` lifecycle hooks: implement [`DatabaseHooks`] for [`SeaOrm`].
///
/// Transactional creation after callbacks retain the created snapshots and
/// run in operation order after commit. Rollback discards them; callback errors
/// are returned to the caller after the auth writes have committed.
pub trait SeaOrmHooks<S: AuthSchema>: DatabaseHooks<S, SeaOrm> {}

impl<S: AuthSchema, T: DatabaseHooks<S, SeaOrm> + ?Sized> SeaOrmHooks<S> for T {}
