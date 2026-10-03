//! Store contract tests, run against both bundled stores.
//!
//! Each test is generic over [`Backend`] and runs once for `SeaOrmStore` and
//! once for `SqlxStore` over a file-backed SQLite database. Tests that do not
//! depend on SQLite-only SQL (triggers, `typeof`, `rowid`) also have ignored
//! PostgreSQL variants: set `BETTER_AUTH_TEST_POSTGRES_URL` to a disposable
//! database and run them with `--run-ignored only`. Each test gets a fresh
//! schema there.
//!
//! Tests inspect and perturb physical state through an independent side pool,
//! so the assertions do not depend on either store's own query layer. Raw SQL
//! uses `$n` placeholders, which both engines accept.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "storage contract tests fail fast on setup and assert persisted invariants directly"
)]

mod accounts;
mod api_keys;
#[cfg(all(feature = "sqlx", feature = "seaorm"))]
mod character_ids;
mod invitations;
mod jwks;
mod members;
mod migrations;
mod native_api_keys;
mod native_device_codes;
mod optional_records;
mod organizations;
mod rate_limit;
mod sessions;
mod stateless;
mod teams;
#[cfg(all(feature = "sqlx", feature = "seaorm"))]
mod timestamps;
mod two_factor;
mod users;
mod verifications;
mod wallets;

use async_trait::async_trait;
use better_auth::{AuthConfig, AuthSchema};
use better_auth_core::RateLimitStorage;
use better_auth_core::store::{AuthStore, DatabaseHooks, HookBackend, SchemaMigrator};
use better_auth_sqlx::sqlx::{
    self, PgPool, Row, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions,
};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// One bundled store implementation under test.
#[async_trait]
pub(crate) trait Backend: Send + Sync + Sized + 'static {
    type Schema: AuthSchema;
    type Hooks: HookBackend;
    type Connection: Clone + Send + Sync + 'static;
    type Store: AuthStore<Self::Schema> + SchemaMigrator + Send + Sync + 'static;
    type RateLimit: RateLimitStorage + SchemaMigrator + Clone + 'static;
    type UuidSchema: AuthSchema;
    type UuidStore: AuthStore<Self::UuidSchema> + Send + Sync + 'static;

    /// Open a pool, optionally capped at `connections`.
    async fn connect(url: &str, connections: Option<u32>) -> TestResult<Self::Connection>;
    fn store(config: Arc<AuthConfig>, connection: &Self::Connection) -> Self::Store;
    fn hook<H: DatabaseHooks<Self::Schema, Self::Hooks> + 'static>(
        store: Self::Store,
        hook: H,
    ) -> Self::Store;
    fn rate_limit(connection: &Self::Connection) -> Self::RateLimit;
    /// A store over the application-owned `uuid_verifications` table.
    fn uuid_store(config: Arc<AuthConfig>, connection: &Self::Connection) -> Self::UuidStore;
    async fn close(connection: Self::Connection) -> TestResult;
}

/// The side pool over the database under test.
#[derive(Clone)]
pub(crate) enum Raw {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

macro_rules! on_raw {
    ($raw:expr, |$pool:ident| $body:expr) => {
        match $raw {
            Raw::Sqlite($pool) => $body,
            Raw::Postgres($pool) => $body,
        }
    };
}
pub(crate) use on_raw;

impl Raw {
    pub(crate) const fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres(_))
    }

    pub(crate) async fn execute(&self, sql: &str, args: &[&str]) -> TestResult<u64> {
        on_raw!(self, |pool| {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
            for arg in args {
                query = query.bind(*arg);
            }
            Ok(query.execute(pool).await?.rows_affected())
        })
    }

    /// Set one timestamp column of the rows matching a text key column,
    /// encoded by SQLx's chrono codec as both stores write it.
    pub(crate) async fn set_timestamp(
        &self,
        table: &str,
        column: &str,
        key: (&str, &str),
        value: DateTime<Utc>,
    ) -> TestResult {
        let (key_column, id) = key;
        let sql = format!("UPDATE {table} SET {column} = $1 WHERE {key_column} = $2");
        on_raw!(self, |pool| {
            _ = sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
                .bind(value)
                .bind(id)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    pub(crate) async fn count(&self, table: &str) -> TestResult<i64> {
        self.count_where(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .await
    }

    pub(crate) async fn count_where(&self, sql: &str, args: &[&str]) -> TestResult<i64> {
        on_raw!(self, |pool| {
            let mut query = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()));
            for arg in args {
                query = query.bind(*arg);
            }
            Ok(query.fetch_one(pool).await?)
        })
    }

    /// One text column of the first row, if any.
    pub(crate) async fn text(&self, sql: &str, args: &[&str]) -> TestResult<Option<String>> {
        on_raw!(self, |pool| {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
            for arg in args {
                query = query.bind(*arg);
            }
            Ok(match query.fetch_optional(pool).await? {
                Some(row) => row.try_get::<Option<String>, _>(0)?,
                None => None,
            })
        })
    }

    /// Every physical column of every row, in rowid order, as JSON text.
    /// SQLite only.
    pub(crate) async fn table(&self, table: &str) -> TestResult<String> {
        let Self::Sqlite(pool) = self else {
            return Err("physical table snapshots use SQLite rowids".into());
        };
        let columns: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT name FROM pragma_table_xinfo('{table}')"
        )))
        .fetch_all(pool)
        .await?;
        let object = columns
            .iter()
            .map(|name| format!("'{name}',\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        Ok(self
            .text(
                &format!(
                    "SELECT json_group_array(json_object({object})) FROM (SELECT * FROM \"{table}\" ORDER BY rowid)"
                ),
                &[],
            )
            .await?
            .unwrap_or_default())
    }

    pub(crate) async fn tables(&self, tables: &[&str]) -> TestResult<Vec<String>> {
        let mut snapshots = Vec::new();
        for table in tables {
            snapshots.push(self.table(table).await?);
        }
        Ok(snapshots)
    }
}

/// A fresh database under test and an independent side pool over it.
pub(crate) struct Db {
    directory: Option<PathBuf>,
    pub(crate) url: String,
    pub(crate) raw: Raw,
}

impl std::ops::Deref for Db {
    type Target = Raw;
    fn deref(&self) -> &Raw {
        &self.raw
    }
}

impl Db {
    /// A file-backed SQLite database.
    pub(crate) async fn sqlite() -> TestResult<Self> {
        let directory =
            std::env::temp_dir().join(format!("better-auth-storage-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.join("auth.sqlite").display()
        );
        let raw = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await?;
        Ok(Self {
            directory: Some(directory),
            url,
            raw: Raw::Sqlite(raw),
        })
    }

    /// A fresh schema in `BETTER_AUTH_TEST_POSTGRES_URL`, selected through
    /// the connection's search path.
    pub(crate) async fn postgres() -> TestResult<Self> {
        let base = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")
            .map_err(|_error| "BETTER_AUTH_TEST_POSTGRES_URL must name a disposable database")?;
        let schema = format!("better_auth_{}", uuid::Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base)
            .await?;
        _ = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await?;
        admin.close().await;
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let raw = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await?;
        Ok(Self {
            directory: None,
            url,
            raw: Raw::Postgres(raw),
        })
    }

    /// Another fresh database of the same engine.
    pub(crate) async fn fresh(&self) -> TestResult<Self> {
        if self.is_postgres() {
            Self::postgres().await
        } else {
            Self::sqlite().await
        }
    }

    /// A store connection over this database with the bundled schema installed.
    pub(crate) async fn migrated<B: Backend>(
        &self,
        secret: &str,
    ) -> TestResult<(B::Connection, B::Store)> {
        let connection = B::connect(&self.url, None).await?;
        let store = B::store(Arc::new(AuthConfig::new(secret)), &connection);
        store.migrate().await?;
        Ok((connection, store))
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
            _ = std::fs::remove_dir_all(directory);
        }
    }
}

pub(crate) struct SeaOrm;

#[async_trait]
impl Backend for SeaOrm {
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    type Hooks = better_auth_seaorm::SeaOrmBackend;
    type Connection = better_auth_seaorm::DatabaseConnection;
    type Store = better_auth_seaorm::SeaOrmStore<Self::Schema>;
    type RateLimit = better_auth_seaorm::SeaOrmRateLimitStorage;
    type UuidSchema = verifications::seaorm_uuid::Schema;
    type UuidStore = better_auth_seaorm::SeaOrmStore<Self::UuidSchema>;

    async fn connect(url: &str, connections: Option<u32>) -> TestResult<Self::Connection> {
        let mut options = better_auth_seaorm::sea_orm::ConnectOptions::new(url.to_owned());
        if let Some(connections) = connections {
            _ = options
                .max_connections(connections)
                .min_connections(connections);
        }
        Ok(better_auth_seaorm::Database::connect(options).await?)
    }

    fn store(config: Arc<AuthConfig>, connection: &Self::Connection) -> Self::Store {
        better_auth_seaorm::SeaOrmStore::new(config, connection.clone())
    }

    fn hook<H: DatabaseHooks<Self::Schema, Self::Hooks> + 'static>(
        store: Self::Store,
        hook: H,
    ) -> Self::Store {
        store.hook(hook)
    }

    fn rate_limit(connection: &Self::Connection) -> Self::RateLimit {
        better_auth_seaorm::SeaOrmRateLimitStorage::new(connection.clone())
    }

    fn uuid_store(config: Arc<AuthConfig>, connection: &Self::Connection) -> Self::UuidStore {
        better_auth_seaorm::SeaOrmStore::new(config, connection.clone())
    }

    async fn close(connection: Self::Connection) -> TestResult {
        Ok(connection.close().await?)
    }
}

pub(crate) struct Sqlx;

#[async_trait]
impl Backend for Sqlx {
    type Schema = better_auth_sqlx::store::__private_test_support::bundled_schema::BundledSchema;
    type Hooks = better_auth_sqlx::SqlxBackend;
    type Connection = better_auth_sqlx::SqlxPool;
    type Store = better_auth_sqlx::SqlxStore<Self::Schema>;
    type RateLimit = better_auth_sqlx::SqlxRateLimitStorage;
    type UuidSchema = verifications::sqlx_uuid::Schema;
    type UuidStore = better_auth_sqlx::SqlxStore<Self::UuidSchema>;

    async fn connect(url: &str, connections: Option<u32>) -> TestResult<Self::Connection> {
        if url.starts_with("postgres") {
            let mut options = PgPoolOptions::new();
            if let Some(connections) = connections {
                options = options
                    .max_connections(connections)
                    .min_connections(connections);
            }
            return Ok(options.connect(url).await?.into());
        }
        let mut options = SqlitePoolOptions::new();
        if let Some(connections) = connections {
            options = options
                .max_connections(connections)
                .min_connections(connections);
        }
        Ok(options.connect(url).await?.into())
    }

    fn store(config: Arc<AuthConfig>, connection: &Self::Connection) -> Self::Store {
        better_auth_sqlx::SqlxStore::new(config, connection.clone())
    }

    fn hook<H: DatabaseHooks<Self::Schema, Self::Hooks> + 'static>(
        store: Self::Store,
        hook: H,
    ) -> Self::Store {
        store.hook(hook)
    }

    fn rate_limit(connection: &Self::Connection) -> Self::RateLimit {
        better_auth_sqlx::SqlxRateLimitStorage::new(connection.clone())
    }

    fn uuid_store(config: Arc<AuthConfig>, connection: &Self::Connection) -> Self::UuidStore {
        better_auth_sqlx::SqlxStore::new(config, connection.clone())
    }

    async fn close(connection: Self::Connection) -> TestResult {
        connection.close().await;
        Ok(())
    }
}

/// Run each named generic test once per backend on SQLite.
macro_rules! backend_tests {
    ($($name:ident),* $(,)?) => {
        mod on_seaorm {
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $name() -> $crate::storage::TestResult {
                    super::$name::<$crate::storage::SeaOrm>($crate::storage::Db::sqlite().await?).await
                }
            )*
        }
        mod on_sqlx {
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $name() -> $crate::storage::TestResult {
                    super::$name::<$crate::storage::Sqlx>($crate::storage::Db::sqlite().await?).await
                }
            )*
        }
    };
}
pub(crate) use backend_tests;

/// Run each named generic test once per backend on PostgreSQL.
macro_rules! postgres_tests {
    ($($name:ident),* $(,)?) => {
        mod on_seaorm_postgres {
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
                async fn $name() -> $crate::storage::TestResult {
                    super::$name::<$crate::storage::SeaOrm>($crate::storage::Db::postgres().await?).await
                }
            )*
        }
        mod on_sqlx_postgres {
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
                async fn $name() -> $crate::storage::TestResult {
                    super::$name::<$crate::storage::Sqlx>($crate::storage::Db::postgres().await?).await
                }
            )*
        }
    };
}
pub(crate) use postgres_tests;
