//! `SQLx` bindings for the shared database lifecycle hooks.

use crate::pool::{SqlxPool, SqlxTransaction};
pub use better_auth_core::hooks::current_request_hook_context;
pub use better_auth_core::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};

/// The `SQLx` hook backend: implement [`DatabaseHooks<S, SqlxBackend>`] to
/// receive its pool and transaction.
///
/// Transactional creation after callbacks retain the created snapshots and
/// run in operation order after commit. Rollback discards them; callback errors
/// are returned to the caller after the auth writes have committed.
#[derive(Debug, Clone, Copy)]
pub struct SqlxBackend;

impl HookBackend for SqlxBackend {
    type Connection = SqlxPool;
    type Transaction = SqlxTransaction;
}

/// Context passed to `SQLx` lifecycle hooks.
pub type SqlxHookContext<'a> = DatabaseHookContext<'a, SqlxBackend>;
