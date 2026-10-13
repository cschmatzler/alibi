//! `SQLx` bindings for the shared database lifecycle hooks.

use crate::error::map_sqlx_err;
use crate::pool::{SqlxPool, SqlxTransaction, SqlxTransactionGuard};
use alibi_core::error::AuthResult;
pub use alibi_core::hooks::current_request_hook_context;
pub use alibi_core::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};

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

/// Query access through the active auth transaction, or the pool outside one.
pub trait SqlxHookContextExt {
    /// Acquire a connection for application queries.
    ///
    /// Inside a transaction this locks its connection, so queries see earlier
    /// uncommitted auth writes and participate in commit or rollback. Outside
    /// one (including creation after hooks), this acquires a pool connection.
    /// Drop the guard before another auth operation or connection acquisition
    /// in the same transaction; holding it would block that operation.
    fn connection(&self) -> impl Future<Output = AuthResult<SqlxHookConnection<'_>>> + Send;
}

impl SqlxHookContextExt for SqlxHookContext<'_> {
    async fn connection(&self) -> AuthResult<SqlxHookConnection<'_>> {
        let inner = if let Some(transaction) = self.tx {
            HookConnection::Transaction(transaction.lock().await)
        } else {
            match self.db {
                #[cfg(feature = "sqlite")]
                SqlxPool::Sqlite(pool) => {
                    HookConnection::Sqlite(pool.acquire().await.map_err(map_sqlx_err)?)
                }
                #[cfg(feature = "postgres")]
                SqlxPool::Postgres(pool) => {
                    HookConnection::Postgres(pool.acquire().await.map_err(map_sqlx_err)?)
                }
            }
        };
        Ok(SqlxHookConnection { inner })
    }
}

#[derive(Debug)]
enum HookConnection<'a> {
    Transaction(SqlxTransactionGuard<'a>),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::pool::PoolConnection<sqlx::Sqlite>),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::pool::PoolConnection<sqlx::Postgres>),
}

/// A native connection acquired by [`SqlxHookContextExt::connection`].
///
/// Dropping this guard releases the transaction lock or returns the connection
/// to its pool. It never commits or rolls back the auth transaction itself.
#[derive(Debug)]
pub struct SqlxHookConnection<'a> {
    inner: HookConnection<'a>,
}

impl SqlxHookConnection<'_> {
    /// The SQLite connection, or `None` for a PostgreSQL backend.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(&mut self) -> Option<&mut sqlx::SqliteConnection> {
        match &mut self.inner {
            HookConnection::Transaction(guard) => guard.sqlite(),
            HookConnection::Sqlite(connection) => Some(connection),
            #[cfg(feature = "postgres")]
            HookConnection::Postgres(_) => None,
        }
    }

    /// The PostgreSQL connection, or `None` for a SQLite backend.
    #[cfg(feature = "postgres")]
    pub fn postgres(&mut self) -> Option<&mut sqlx::PgConnection> {
        match &mut self.inner {
            HookConnection::Transaction(guard) => guard.postgres(),
            HookConnection::Postgres(connection) => Some(connection),
            #[cfg(feature = "sqlite")]
            HookConnection::Sqlite(_) => None,
        }
    }
}
