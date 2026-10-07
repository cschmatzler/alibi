//! `SeaORM` bindings for the shared database lifecycle hooks.

pub use alibi_core::hooks::current_request_hook_context;
pub use alibi_core::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use sea_orm::{DatabaseConnection, DatabaseTransaction};

/// The `SeaORM` hook backend: implement [`DatabaseHooks<S, SeaOrmBackend>`]
/// to receive its connection and transaction.
///
/// Transactional creation after callbacks retain the created snapshots and
/// run in operation order after commit. Rollback discards them; callback errors
/// are returned to the caller after the auth writes have committed.
#[derive(Debug, Clone, Copy)]
pub struct SeaOrmBackend;

impl HookBackend for SeaOrmBackend {
    type Connection = DatabaseConnection;
    type Transaction = DatabaseTransaction;
}

/// Context passed to `SeaORM` lifecycle hooks.
pub type SeaOrmHookContext<'a> = DatabaseHookContext<'a, SeaOrmBackend>;
