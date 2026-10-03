//! `SQLx` bindings for the shared database lifecycle hooks.

use crate::pool::{SqlxPool, SqlxTransaction};
pub use better_auth_core::hooks::current_request_hook_context;
use better_auth_core::schema::AuthSchema;
pub use better_auth_core::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};

/// The `SQLx` hook backend: hooks receive its pool and transaction.
#[derive(Debug, Clone, Copy)]
pub struct Sqlx;

impl HookBackend for Sqlx {
    type Connection = SqlxPool;
    type Transaction = SqlxTransaction;
}

/// Context passed to `SQLx` lifecycle hooks.
pub type SqlxHookContext<'a> = DatabaseHookContext<'a, Sqlx>;

/// `SQLx` lifecycle hooks: implement [`DatabaseHooks`] for [`Sqlx`].
///
/// Transactional creation after callbacks retain the created snapshots and
/// run in operation order after commit. Rollback discards them; callback errors
/// are returned to the caller after the auth writes have committed.
pub trait SqlxHooks<S: AuthSchema>: DatabaseHooks<S, Sqlx> {}

impl<S: AuthSchema, T: DatabaseHooks<S, Sqlx> + ?Sized> SqlxHooks<S> for T {}
