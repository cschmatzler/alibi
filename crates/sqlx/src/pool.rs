//! Backend-tagged `SQLx` pools and transactions, and statement execution.

use crate::error::map_sqlx_err;
use crate::sql::{Sql, postgres_arguments, sqlite_arguments};
use better_auth_core::error::{AuthError, AuthResult};
use sqlx::postgres::{PgPool, PgRow, Postgres};
use sqlx::sqlite::{Sqlite, SqlitePool, SqliteRow};
use sqlx::{AssertSqlSafe, Decode, Type};

/// The database engine behind a pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlxBackend {
    Sqlite,
    Postgres,
}

/// An application's `SQLx` pool. Better Auth shares it with the application.
#[derive(Clone, Debug)]
pub enum SqlxPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl From<SqlitePool> for SqlxPool {
    fn from(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }
}

impl From<PgPool> for SqlxPool {
    fn from(pool: PgPool) -> Self {
        Self::Postgres(pool)
    }
}

impl SqlxPool {
    /// Connect a SQLite (`sqlite:`) or PostgreSQL (`postgres:`/`postgresql:`) URL.
    ///
    /// # Errors
    ///
    /// Returns the driver error, or a configuration error for another scheme.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        if url.starts_with("sqlite:") {
            SqlitePool::connect(url).await.map(Self::Sqlite)
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            PgPool::connect(url).await.map(Self::Postgres)
        } else {
            Err(sqlx::Error::Configuration(
                "Better Auth SQLx pools support sqlite: and postgres: URLs".into(),
            ))
        }
    }

    #[must_use]
    pub const fn backend(&self) -> SqlxBackend {
        match self {
            Self::Sqlite(_) => SqlxBackend::Sqlite,
            Self::Postgres(_) => SqlxBackend::Postgres,
        }
    }

    #[must_use]
    pub const fn as_sqlite(&self) -> Option<&SqlitePool> {
        match self {
            Self::Sqlite(pool) => Some(pool),
            Self::Postgres(_) => None,
        }
    }

    #[must_use]
    pub const fn as_postgres(&self) -> Option<&PgPool> {
        match self {
            Self::Postgres(pool) => Some(pool),
            Self::Sqlite(_) => None,
        }
    }

    /// Close every pooled connection.
    pub async fn close(&self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
            Self::Postgres(pool) => pool.close().await,
        }
    }

    /// Begin a transaction. SQLite uses `BEGIN IMMEDIATE` when `immediate` is set,
    /// acquiring its writer reservation before the first read.
    pub(crate) async fn begin(&self, immediate: bool) -> AuthResult<SqlxTransaction> {
        let inner = match self {
            Self::Sqlite(pool) if immediate => pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map(TransactionKind::Sqlite),
            Self::Sqlite(pool) => pool.begin().await.map(TransactionKind::Sqlite),
            Self::Postgres(pool) => pool.begin().await.map(TransactionKind::Postgres),
        }
        .map_err(map_sqlx_err)?;
        Ok(SqlxTransaction {
            backend: self.backend(),
            inner: tokio::sync::Mutex::new(Some(inner)),
        })
    }
}

/// An open driver transaction.
#[derive(Debug)]
pub enum TransactionKind {
    Sqlite(sqlx::Transaction<'static, Sqlite>),
    Postgres(sqlx::Transaction<'static, Postgres>),
}

/// An auth transaction shared with lifecycle hooks.
///
/// Statements serialize on an internal lock; hooks run between statements, so a
/// hook may [`lock`](Self::lock) the transaction to run its own queries in it.
#[derive(Debug)]
pub struct SqlxTransaction {
    backend: SqlxBackend,
    inner: tokio::sync::Mutex<Option<TransactionKind>>,
}

/// Exclusive access to an open auth transaction.
#[derive(Debug)]
pub struct SqlxTransactionGuard<'a>(tokio::sync::MutexGuard<'a, Option<TransactionKind>>);

impl SqlxTransactionGuard<'_> {
    /// The SQLite connection running this transaction.
    pub fn sqlite(&mut self) -> Option<&mut sqlx::SqliteConnection> {
        match self.0.as_mut()? {
            TransactionKind::Sqlite(transaction) => Some(&mut **transaction),
            TransactionKind::Postgres(_) => None,
        }
    }

    /// The PostgreSQL connection running this transaction.
    pub fn postgres(&mut self) -> Option<&mut sqlx::PgConnection> {
        match self.0.as_mut()? {
            TransactionKind::Postgres(transaction) => Some(&mut **transaction),
            TransactionKind::Sqlite(_) => None,
        }
    }
}

impl SqlxTransaction {
    #[must_use]
    pub const fn backend(&self) -> SqlxBackend {
        self.backend
    }

    /// Wait for the current statement, then run statements on this transaction.
    pub async fn lock(&self) -> SqlxTransactionGuard<'_> {
        SqlxTransactionGuard(self.inner.lock().await)
    }

    pub(crate) async fn commit(self) -> AuthResult<()> {
        match self.inner.into_inner() {
            Some(TransactionKind::Sqlite(transaction)) => transaction.commit().await,
            Some(TransactionKind::Postgres(transaction)) => transaction.commit().await,
            None => return Err(AuthError::internal("Transaction already finished")),
        }
        .map_err(map_sqlx_err)
    }

    pub(crate) async fn rollback(self) -> AuthResult<()> {
        match self.inner.into_inner() {
            Some(TransactionKind::Sqlite(transaction)) => transaction.rollback().await,
            Some(TransactionKind::Postgres(transaction)) => transaction.rollback().await,
            None => return Err(AuthError::internal("Transaction already finished")),
        }
        .map_err(map_sqlx_err)
    }
}

/// A model decodable from rows of both supported backends.
pub trait SqlxRow:
    for<'r> sqlx::FromRow<'r, SqliteRow> + for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin
{
}

impl<T> SqlxRow for T where
    T: for<'r> sqlx::FromRow<'r, SqliteRow> + for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin
{
}

/// A single-column value decodable from both supported backends.
pub(crate) trait SqlxScalar:
    for<'r> Decode<'r, Sqlite>
    + Type<Sqlite>
    + for<'r> Decode<'r, Postgres>
    + Type<Postgres>
    + Send
    + Unpin
{
}

impl<T> SqlxScalar for T where
    T: for<'r> Decode<'r, Sqlite>
        + Type<Sqlite>
        + for<'r> Decode<'r, Postgres>
        + Type<Postgres>
        + Send
        + Unpin
{
}

/// Where a statement runs: the shared pool or an open transaction.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Exec<'a> {
    Pool(&'a SqlxPool),
    Tx(&'a SqlxTransaction),
}

macro_rules! dispatch {
    ($exec:expr, $sql:expr, |$query:ident, $executor:ident| $body:expr) => {{
        let (text, args) = $sql.into_parts();
        match $exec {
            Exec::Pool(SqlxPool::Sqlite(pool)) => match sqlite_arguments(args) {
                Ok(arguments) => {
                    let $executor = pool;
                    let $query = (AssertSqlSafe(text), arguments);
                    $body
                }
                Err(error) => Err(sqlx::Error::Encode(error)),
            },
            Exec::Pool(SqlxPool::Postgres(pool)) => match postgres_arguments(args) {
                Ok(arguments) => {
                    let $executor = pool;
                    let $query = (AssertSqlSafe(text), arguments);
                    $body
                }
                Err(error) => Err(sqlx::Error::Encode(error)),
            },
            Exec::Tx(transaction) => {
                let mut guard = transaction.inner.lock().await;
                match guard.as_mut() {
                    Some(TransactionKind::Sqlite(open)) => match sqlite_arguments(args) {
                        Ok(arguments) => {
                            let $executor = &mut **open;
                            let $query = (AssertSqlSafe(text), arguments);
                            $body
                        }
                        Err(error) => Err(sqlx::Error::Encode(error)),
                    },
                    Some(TransactionKind::Postgres(open)) => match postgres_arguments(args) {
                        Ok(arguments) => {
                            let $executor = &mut **open;
                            let $query = (AssertSqlSafe(text), arguments);
                            $body
                        }
                        Err(error) => Err(sqlx::Error::Encode(error)),
                    },
                    None => Err(sqlx::Error::PoolClosed),
                }
            }
        }
        .map_err(map_sqlx_err)
    }};
}

impl Exec<'_> {
    pub(crate) const fn backend(self) -> SqlxBackend {
        match self {
            Self::Pool(pool) => pool.backend(),
            Self::Tx(transaction) => transaction.backend,
        }
    }

    pub(crate) async fn fetch_all<M: SqlxRow>(self, sql: Sql) -> AuthResult<Vec<M>> {
        dispatch!(self, sql, |query, executor| {
            sqlx::query_as_with(query.0, query.1)
                .fetch_all(executor)
                .await
        })
    }

    pub(crate) async fn fetch_optional<M: SqlxRow>(self, sql: Sql) -> AuthResult<Option<M>> {
        dispatch!(self, sql, |query, executor| {
            sqlx::query_as_with(query.0, query.1)
                .fetch_optional(executor)
                .await
        })
    }

    /// Run a statement, returning its affected row count.
    pub(crate) async fn execute(self, sql: Sql) -> AuthResult<u64> {
        dispatch!(self, sql, |query, executor| {
            sqlx::query_with(query.0, query.1)
                .execute(executor)
                .await
                .map(|result| result.rows_affected())
        })
    }

    pub(crate) async fn fetch_all_scalar<T: SqlxScalar>(self, sql: Sql) -> AuthResult<Vec<T>> {
        dispatch!(self, sql, |query, executor| {
            sqlx::query_scalar_with(query.0, query.1)
                .fetch_all(executor)
                .await
        })
    }

    /// Run a fixed multi-statement script without bound arguments.
    pub(crate) async fn execute_script(self, script: &'static str) -> AuthResult<()> {
        let result = match self {
            Exec::Pool(SqlxPool::Sqlite(pool)) => {
                sqlx::raw_sql(script).execute(pool).await.map(drop)
            }
            Exec::Pool(SqlxPool::Postgres(pool)) => {
                sqlx::raw_sql(script).execute(pool).await.map(drop)
            }
            Exec::Tx(transaction) => {
                let mut guard = transaction.inner.lock().await;
                match guard.as_mut() {
                    Some(TransactionKind::Sqlite(open)) => {
                        sqlx::raw_sql(script).execute(&mut **open).await.map(drop)
                    }
                    Some(TransactionKind::Postgres(open)) => {
                        sqlx::raw_sql(script).execute(&mut **open).await.map(drop)
                    }
                    None => Err(sqlx::Error::PoolClosed),
                }
            }
        };
        result.map_err(map_sqlx_err)
    }

    pub(crate) async fn fetch_scalar<T: SqlxScalar>(self, sql: Sql) -> AuthResult<Option<T>> {
        dispatch!(self, sql, |query, executor| {
            sqlx::query_scalar_with(query.0, query.1)
                .fetch_optional(executor)
                .await
        })
    }
}
