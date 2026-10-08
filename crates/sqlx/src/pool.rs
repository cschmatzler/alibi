//! Engine-tagged `SQLx` pools and transactions, and statement execution.

use crate::error::map_sqlx_err;
use crate::sql::Sql;
use alibi_core::error::{AuthError, AuthResult};
#[cfg(feature = "postgres")]
use sqlx::postgres::{PgPool, PgRow, Postgres};
#[cfg(feature = "sqlite")]
use sqlx::sqlite::{Sqlite, SqlitePool, SqliteRow};
use sqlx::{AssertSqlSafe, Decode, Type};

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("alibi-sqlx needs the `sqlite` or `postgres` feature");

/// The database engine behind a pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Sqlite,
    Postgres,
}

/// An application's `SQLx` pool. Better Auth shares it with the application.
#[derive(Clone, Debug)]
pub enum SqlxPool {
    #[cfg(feature = "sqlite")]
    Sqlite(SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(PgPool),
}

#[cfg(feature = "sqlite")]
impl From<SqlitePool> for SqlxPool {
    fn from(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }
}

#[cfg(feature = "postgres")]
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
    /// Returns the driver error, or a configuration error for a scheme whose
    /// engine feature is not enabled.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        #[cfg(feature = "sqlite")]
        if url.starts_with("sqlite:") {
            return SqlitePool::connect(url).await.map(Self::Sqlite);
        }
        #[cfg(feature = "postgres")]
        if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            return PgPool::connect(url).await.map(Self::Postgres);
        }
        Err(sqlx::Error::Configuration(
            "the database URL scheme is not an enabled Better Auth SQLx engine".into(),
        ))
    }

    #[must_use]
    pub const fn engine(&self) -> Engine {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => Engine::Sqlite,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => Engine::Postgres,
        }
    }

    #[cfg(feature = "sqlite")]
    #[must_use]
    pub const fn as_sqlite(&self) -> Option<&SqlitePool> {
        match self {
            Self::Sqlite(pool) => Some(pool),
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => None,
        }
    }

    #[cfg(feature = "postgres")]
    #[must_use]
    pub const fn as_postgres(&self) -> Option<&PgPool> {
        match self {
            Self::Postgres(pool) => Some(pool),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => None,
        }
    }

    /// Close every pooled connection.
    pub async fn close(&self) {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => pool.close().await,
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => pool.close().await,
        }
    }

    /// Run `statements` in order, without bound arguments. Generated
    /// application migrations install their tables this way.
    ///
    /// # Errors
    ///
    /// Returns the first driver error.
    pub async fn execute_batch(&self, statements: &[&str]) -> Result<(), sqlx::Error> {
        for statement in statements {
            let statement = AssertSqlSafe((*statement).to_owned());
            match self {
                #[cfg(feature = "sqlite")]
                Self::Sqlite(pool) => _ = sqlx::raw_sql(statement).execute(pool).await?,
                #[cfg(feature = "postgres")]
                Self::Postgres(pool) => _ = sqlx::raw_sql(statement).execute(pool).await?,
            }
        }
        Ok(())
    }

    /// Begin a transaction. SQLite uses `BEGIN IMMEDIATE` when `immediate` is set,
    /// acquiring its writer reservation before the first read.
    pub(crate) async fn begin(&self, immediate: bool) -> AuthResult<SqlxTransaction> {
        let inner = match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) if immediate => pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map(TransactionKind::Sqlite),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => pool.begin().await.map(TransactionKind::Sqlite),
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => {
                let _ = immediate;
                pool.begin().await.map(TransactionKind::Postgres)
            }
        }
        .map_err(map_sqlx_err)?;
        Ok(SqlxTransaction {
            engine: self.engine(),
            config: None,
            inner: tokio::sync::Mutex::new(Some(inner)),
        })
    }
}

/// An open driver transaction.
#[derive(Debug)]
pub(crate) enum TransactionKind {
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::Transaction<'static, Sqlite>),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::Transaction<'static, Postgres>),
}

/// An auth transaction shared with lifecycle hooks.
///
/// Statements serialize on an internal lock; hooks run between statements, so a
/// hook may [`lock`](Self::lock) the transaction to run its own queries in it.
#[derive(Debug)]
pub struct SqlxTransaction {
    engine: Engine,
    pub(crate) config: Option<std::sync::Arc<alibi_core::config::AuthConfig>>,
    inner: tokio::sync::Mutex<Option<TransactionKind>>,
}

/// Exclusive access to an open auth transaction.
#[derive(Debug)]
pub struct SqlxTransactionGuard<'a>(tokio::sync::MutexGuard<'a, Option<TransactionKind>>);

impl SqlxTransactionGuard<'_> {
    /// The SQLite connection running this transaction.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(&mut self) -> Option<&mut sqlx::SqliteConnection> {
        match self.0.as_mut()? {
            TransactionKind::Sqlite(transaction) => Some(&mut **transaction),
            #[cfg(feature = "postgres")]
            TransactionKind::Postgres(_) => None,
        }
    }

    /// The PostgreSQL connection running this transaction.
    #[cfg(feature = "postgres")]
    pub fn postgres(&mut self) -> Option<&mut sqlx::PgConnection> {
        match self.0.as_mut()? {
            TransactionKind::Postgres(transaction) => Some(&mut **transaction),
            #[cfg(feature = "sqlite")]
            TransactionKind::Sqlite(_) => None,
        }
    }
}

impl SqlxTransaction {
    #[must_use]
    pub const fn engine(&self) -> Engine {
        self.engine
    }

    /// Wait for the current statement, then run statements on this transaction.
    pub async fn lock(&self) -> SqlxTransactionGuard<'_> {
        SqlxTransactionGuard(self.inner.lock().await)
    }

    pub(crate) async fn commit(self) -> AuthResult<()> {
        match self.inner.into_inner() {
            #[cfg(feature = "sqlite")]
            Some(TransactionKind::Sqlite(transaction)) => transaction.commit().await,
            #[cfg(feature = "postgres")]
            Some(TransactionKind::Postgres(transaction)) => transaction.commit().await,
            None => return Err(AuthError::internal("Transaction already finished")),
        }
        .map_err(map_sqlx_err)
    }

    pub(crate) async fn rollback(self) -> AuthResult<()> {
        match self.inner.into_inner() {
            #[cfg(feature = "sqlite")]
            Some(TransactionKind::Sqlite(transaction)) => transaction.rollback().await,
            #[cfg(feature = "postgres")]
            Some(TransactionKind::Postgres(transaction)) => transaction.rollback().await,
            None => return Err(AuthError::internal("Transaction already finished")),
        }
        .map_err(map_sqlx_err)
    }
}

macro_rules! decodable {
    ($($row:tt)*) => {
        /// A model decodable from the rows of every enabled engine.
        pub trait SqlxRow: $($row)* + Send + Unpin {}

        impl<T> SqlxRow for T where T: $($row)* + Send + Unpin {}
    };
}

#[cfg(all(feature = "sqlite", feature = "postgres"))]
decodable!(for<'r> sqlx::FromRow<'r, SqliteRow> + for<'r> sqlx::FromRow<'r, PgRow>);
#[cfg(all(feature = "sqlite", not(feature = "postgres")))]
decodable!(for<'r> sqlx::FromRow<'r, SqliteRow>);
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
decodable!(for<'r> sqlx::FromRow<'r, PgRow>);

macro_rules! scalar {
    ($($bound:tt)*) => {
        /// A single-column value decodable from every enabled engine.
        pub(crate) trait SqlxScalar: $($bound)* + Send + Unpin {}

        impl<T> SqlxScalar for T where T: $($bound)* + Send + Unpin {}
    };
}

#[cfg(all(feature = "sqlite", feature = "postgres"))]
scalar!(for<'r> Decode<'r, Sqlite> + Type<Sqlite> + for<'r> Decode<'r, Postgres> + Type<Postgres>);
#[cfg(all(feature = "sqlite", not(feature = "postgres")))]
scalar!(for<'r> Decode<'r, Sqlite> + Type<Sqlite>);
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
scalar!(for<'r> Decode<'r, Postgres> + Type<Postgres>);

/// Where a statement runs: the shared pool or an open transaction.
#[derive(Clone, Copy, Debug)]
enum ExecConnection<'a> {
    Pool(&'a SqlxPool),
    Tx(&'a SqlxTransaction),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Exec<'a> {
    connection: ExecConnection<'a>,
    config: Option<&'a alibi_core::config::AuthConfig>,
}
impl<'a> Exec<'a> {
    #[expect(
        non_snake_case,
        reason = "Retain the connection constructor names used by adapter call sites"
    )]
    pub(crate) const fn Pool(pool: &'a SqlxPool) -> Self {
        Self {
            connection: ExecConnection::Pool(pool),
            config: None,
        }
    }
    #[expect(
        non_snake_case,
        reason = "Retain the connection constructor names used by adapter call sites"
    )]
    pub(crate) fn Tx(tx: &'a SqlxTransaction) -> Self {
        Self {
            connection: ExecConnection::Tx(tx),
            config: tx.config.as_deref(),
        }
    }
    pub(crate) const fn with_config(mut self, config: &'a alibi_core::config::AuthConfig) -> Self {
        self.config = Some(config);
        self
    }
    pub(crate) fn schema_name(self) -> Option<&'a str> {
        self.config
            .and_then(|config| config.advanced.database.schema_name.as_deref())
    }
    fn qualify(self, mut sql: String) -> AuthResult<String> {
        if let Some(mapping) = self
            .config
            .and_then(|config| config.advanced.database.two_factor.as_ref())
        {
            sql = alibi_core::database_sql::map_two_factor(&sql, mapping)?;
        }
        if self.engine() == Engine::Postgres
            && let Some(schema) = self
                .config
                .and_then(|config| config.advanced.database.schema_name.as_deref())
        {
            return alibi_core::database_sql::qualify_schema(&sql, schema);
        }
        Ok(sql)
    }
}

/// Bind `$sql` for the engine behind `$exec` and run `$body` with `$query`
/// (text and arguments) on `$executor`.
macro_rules! dispatch {
    ($exec:expr, $sql:expr, |$query:ident, $executor:ident| $body:expr) => {{
        let exec = $exec;
        let (text, args) = $sql.into_parts();
        let text = exec.qualify(text)?;
        match exec.connection {
            #[cfg(feature = "sqlite")]
            ExecConnection::Pool(SqlxPool::Sqlite(pool)) => {
                match crate::sql::sqlite_arguments(args) {
                    Ok(arguments) => {
                        let $executor = pool;
                        let $query = (AssertSqlSafe(text), arguments);
                        $body
                    }
                    Err(error) => Err(sqlx::Error::Encode(error)),
                }
            }
            #[cfg(feature = "postgres")]
            ExecConnection::Pool(SqlxPool::Postgres(pool)) => {
                match crate::sql::postgres_arguments(args) {
                    Ok(arguments) => {
                        let $executor = pool;
                        let $query = (AssertSqlSafe(text), arguments);
                        $body
                    }
                    Err(error) => Err(sqlx::Error::Encode(error)),
                }
            }
            ExecConnection::Tx(transaction) => {
                let mut guard = transaction.inner.lock().await;
                match guard.as_mut() {
                    #[cfg(feature = "sqlite")]
                    Some(TransactionKind::Sqlite(open)) => match crate::sql::sqlite_arguments(args)
                    {
                        Ok(arguments) => {
                            let $executor = &mut **open;
                            let $query = (AssertSqlSafe(text), arguments);
                            $body
                        }
                        Err(error) => Err(sqlx::Error::Encode(error)),
                    },
                    #[cfg(feature = "postgres")]
                    Some(TransactionKind::Postgres(open)) => {
                        match crate::sql::postgres_arguments(args) {
                            Ok(arguments) => {
                                let $executor = &mut **open;
                                let $query = (AssertSqlSafe(text), arguments);
                                $body
                            }
                            Err(error) => Err(sqlx::Error::Encode(error)),
                        }
                    }
                    None => Err(sqlx::Error::PoolClosed),
                }
            }
        }
        .map_err(map_sqlx_err)
    }};
}

impl Exec<'_> {
    pub(crate) const fn engine(self) -> Engine {
        match self.connection {
            ExecConnection::Pool(pool) => pool.engine(),
            ExecConnection::Tx(transaction) => transaction.engine,
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

    pub(crate) async fn fetch_scalar<T: SqlxScalar>(self, sql: Sql) -> AuthResult<Option<T>> {
        dispatch!(self, sql, |query, executor| {
            sqlx::query_scalar_with(query.0, query.1)
                .fetch_optional(executor)
                .await
        })
    }

    /// Run a fixed multi-statement script without bound arguments.
    pub(crate) async fn execute_script(self, script: &'static str) -> AuthResult<()> {
        let script = self.qualify(script.to_owned())?;
        let result = match self.connection {
            #[cfg(feature = "sqlite")]
            ExecConnection::Pool(SqlxPool::Sqlite(pool)) => {
                sqlx::raw_sql(AssertSqlSafe(script.clone()))
                    .execute(pool)
                    .await
                    .map(drop)
            }
            #[cfg(feature = "postgres")]
            ExecConnection::Pool(SqlxPool::Postgres(pool)) => {
                sqlx::raw_sql(AssertSqlSafe(script.clone()))
                    .execute(pool)
                    .await
                    .map(drop)
            }
            ExecConnection::Tx(transaction) => {
                let mut guard = transaction.inner.lock().await;
                match guard.as_mut() {
                    #[cfg(feature = "sqlite")]
                    Some(TransactionKind::Sqlite(open)) => {
                        sqlx::raw_sql(AssertSqlSafe(script.clone()))
                            .execute(&mut **open)
                            .await
                            .map(drop)
                    }
                    #[cfg(feature = "postgres")]
                    Some(TransactionKind::Postgres(open)) => {
                        sqlx::raw_sql(AssertSqlSafe(script.clone()))
                            .execute(&mut **open)
                            .await
                            .map(drop)
                    }
                    None => Err(sqlx::Error::PoolClosed),
                }
            }
        };
        result.map_err(map_sqlx_err)
    }
}
