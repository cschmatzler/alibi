//! The auth store under test. Fixtures share one SQLite database, served
//! through `SqlxStore`; the `seaorm` feature serves it through `SeaOrmStore`.
//! Fixture scaffolding (seeding, inspection, resets) uses the SeaORM connection
//! in both builds; it is test setup, not the store being compared.

use better_auth::{AuthConfig, AuthSchema};
use better_auth_seaorm::DatabaseConnection;
use better_auth_seaorm::sea_orm::DbErr;
use std::sync::Arc;

#[cfg(feature = "seaorm")]
mod selected {
    pub use better_auth_seaorm::SeaOrmBackend as Backend;
    pub use better_auth_seaorm::SeaOrmHookContext as HookContext;
    pub use better_auth_seaorm::SeaOrmStore as Store;
    pub use better_auth_seaorm::store::entities;
    pub type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
}

#[cfg(not(feature = "seaorm"))]
mod selected {
    pub use better_auth_sqlx::SqlxBackend as Backend;
    pub use better_auth_sqlx::SqlxHookContext as HookContext;
    pub use better_auth_sqlx::SqlxStore as Store;
    pub use better_auth_sqlx::store::entities;
    pub type TestSchema =
        better_auth_sqlx::store::__private_test_support::bundled_schema::BundledSchema;
}

pub(crate) use selected::*;

#[cfg(feature = "seaorm")]
impl better_auth_seaorm::sea_orm::ActiveModelBehavior
    for crate::session_field_model::application_session::ActiveModel
{
}

/// The selected store over the fixture database.
pub(crate) fn store<S: AuthSchema>(
    config: impl Into<Arc<AuthConfig>>,
    database: DatabaseConnection,
) -> Store<S> {
    #[cfg(feature = "seaorm")]
    {
        Store::new(config, database)
    }
    #[cfg(not(feature = "seaorm"))]
    {
        Store::new(config, database.get_sqlite_connection_pool().clone())
    }
}

/// Install the bundled schema with the selected store's migrator.
pub(crate) async fn migrate(database: &DatabaseConnection) -> Result<(), DbErr> {
    #[cfg(feature = "seaorm")]
    {
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(database).await
    }
    #[cfg(not(feature = "seaorm"))]
    {
        let pool = better_auth_sqlx::SqlxPool::from(database.get_sqlite_connection_pool().clone());
        better_auth_sqlx::store::__private_test_support::migrator::run_migrations(&pool)
            .await
            .map_err(|error| DbErr::Custom(error.to_string()))
    }
}

/// Read rows into the selected backend's model type.
#[cfg(feature = "seaorm")]
pub(crate) async fn rows<M>(
    database: &DatabaseConnection,
    sql: &str,
    args: Vec<String>,
) -> Result<Vec<M>, DbErr>
where
    M: better_auth_seaorm::sea_orm::FromQueryResult,
{
    use better_auth_seaorm::sea_orm::{DbBackend, Statement};
    M::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        sql,
        args.into_iter().map(Into::into),
    ))
    .all(database)
    .await
}

/// Read rows into the selected backend's model type.
#[cfg(not(feature = "seaorm"))]
pub(crate) async fn rows<M>(
    database: &DatabaseConnection,
    sql: &str,
    args: Vec<String>,
) -> Result<Vec<M>, DbErr>
where
    M: for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
{
    let mut query = sqlx::query_as::<_, M>(sqlx::AssertSqlSafe(sql.to_owned()));
    for arg in args {
        query = query.bind(arg);
    }
    query
        .fetch_all(database.get_sqlite_connection_pool())
        .await
        .map_err(|error| DbErr::Custom(error.to_string()))
}

/// Run one statement on a hook's database connection.
pub(crate) async fn hook_execute(
    database: &<Backend as better_auth::store::HookBackend>::Connection,
    sql: &str,
    args: Vec<String>,
) -> better_auth::AuthResult<u64> {
    #[cfg(feature = "seaorm")]
    {
        use better_auth_seaorm::sea_orm::{ConnectionTrait, Statement};
        database
            .execute_raw(Statement::from_sql_and_values(
                database.get_database_backend(),
                sql,
                args.into_iter().map(Into::into),
            ))
            .await
            .map(|result| result.rows_affected())
            .map_err(|error| better_auth::AuthError::internal(error.to_string()))
    }
    #[cfg(not(feature = "seaorm"))]
    {
        let pool = database
            .as_sqlite()
            .ok_or_else(|| better_auth::AuthError::internal("fixture database is SQLite"))?;
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
        for arg in args {
            query = query.bind(arg);
        }
        query
            .execute(pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(|error| better_auth::AuthError::internal(error.to_string()))
    }
}

/// Read rows on a hook's transaction when present, otherwise its connection.
#[cfg(feature = "seaorm")]
pub(crate) async fn hook_rows<M>(
    context: &HookContext<'_>,
    sql: &str,
) -> better_auth::AuthResult<Vec<M>>
where
    M: better_auth_seaorm::sea_orm::FromQueryResult,
{
    use better_auth_seaorm::sea_orm::{DbBackend, Statement};
    let statement = Statement::from_string(DbBackend::Sqlite, sql);
    let rows = match context.tx {
        Some(tx) => M::find_by_statement(statement).all(tx).await,
        None => M::find_by_statement(statement).all(context.db).await,
    };
    rows.map_err(|error| better_auth::AuthError::internal(error.to_string()))
}

/// Read rows on a hook's transaction when present, otherwise its connection.
#[cfg(not(feature = "seaorm"))]
pub(crate) async fn hook_rows<M>(
    context: &HookContext<'_>,
    sql: &str,
) -> better_auth::AuthResult<Vec<M>>
where
    M: for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
{
    let query = || sqlx::query_as::<_, M>(sqlx::AssertSqlSafe(sql.to_owned()));
    let rows = match context.tx {
        Some(tx) => {
            let mut guard = tx.lock().await;
            let connection = guard
                .sqlite()
                .ok_or_else(|| better_auth::AuthError::internal("fixture database is SQLite"))?;
            query().fetch_all(connection).await
        }
        None => {
            let pool = context
                .db
                .as_sqlite()
                .ok_or_else(|| better_auth::AuthError::internal("fixture database is SQLite"))?;
            query().fetch_all(pool).await
        }
    };
    rows.map_err(|error| better_auth::AuthError::internal(error.to_string()))
}

/// A SeaORM connection to the store's database, for fixture scaffolding.
pub(crate) fn database_of<S: AuthSchema>(store: &Store<S>) -> DatabaseConnection {
    #[cfg(feature = "seaorm")]
    {
        store.connection().clone()
    }
    #[cfg(not(feature = "seaorm"))]
    {
        let pool = store
            .pool()
            .as_sqlite()
            .cloned()
            .unwrap_or_else(|| unreachable!("fixture stores use SQLite"));
        better_auth_seaorm::sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool)
    }
}

/// Install the process tracing subscriber. The SQLx build adds the layer that
/// reports statements to [`observe`] callbacks.
pub(crate) fn init_tracing() {
    #[cfg(feature = "seaorm")]
    tracing_subscriber::fmt::init();
    #[cfg(not(feature = "seaorm"))]
    {
        use tracing_subscriber::{EnvFilter, Layer, filter::Targets, prelude::*};
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(EnvFilter::from_default_env()))
            .with(
                statements::Layer.with_filter(
                    Targets::new()
                        .with_target("sqlx::query", tracing::Level::TRACE)
                        .with_target("fixture::statements", tracing::Level::TRACE),
                ),
            )
            .init();
    }
}

/// A fixture database whose stores report each executed statement's SQL.
#[derive(Clone)]
pub(crate) struct Observed {
    pub(crate) database: DatabaseConnection,
    #[cfg(not(feature = "seaorm"))]
    span: tracing::Span,
}

/// Report the SQL of statements run by stores built on `Observed::database`
/// while serving `Observed::scope` routes. SeaORM uses its metric callback;
/// SQLx reports statements through `tracing`, scoped by a request span.
pub(crate) fn observe(
    database: &DatabaseConnection,
    callback: impl Fn(&str) + Send + Sync + 'static,
) -> Observed {
    #[cfg(feature = "seaorm")]
    {
        let mut database = database.clone();
        database.set_metric_callback(move |info| {
            if !info.failed {
                callback(&info.statement.sql);
            }
        });
        Observed { database }
    }
    #[cfg(not(feature = "seaorm"))]
    {
        Observed {
            database: database.clone(),
            span: statements::span(Arc::new(callback)),
        }
    }
}

impl Observed {
    /// Serve `router` inside the observation scope.
    pub(crate) fn scope<T: Clone + Send + Sync + 'static>(
        &self,
        router: axum::Router<T>,
    ) -> axum::Router<T> {
        #[cfg(feature = "seaorm")]
        {
            router
        }
        #[cfg(not(feature = "seaorm"))]
        {
            use tracing::Instrument;
            let span = self.span.clone();
            router.layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    next.run(request).instrument(span.clone())
                },
            ))
        }
    }
}

#[cfg(not(feature = "seaorm"))]
mod statements {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::{layer::Context, registry::LookupSpan};

    type Callback = Arc<dyn Fn(&str) + Send + Sync>;

    fn observers() -> &'static Mutex<HashMap<u64, Callback>> {
        static OBSERVERS: OnceLock<Mutex<HashMap<u64, Callback>>> = OnceLock::new();
        OBSERVERS.get_or_init(Mutex::default)
    }

    pub(super) fn span(callback: Callback) -> tracing::Span {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut observers) = observers().lock() {
            _ = observers.insert(id, callback);
        }
        tracing::info_span!(target: "fixture::statements", "observed_statements", observer = id)
    }

    struct Observer(u64);

    #[derive(Default)]
    struct Fields {
        observer: Option<u64>,
        summary: String,
        statement: String,
    }

    impl Visit for Fields {
        fn record_u64(&mut self, field: &Field, value: u64) {
            if field.name() == "observer" {
                self.observer = Some(value);
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "summary" => value.clone_into(&mut self.summary),
                "db.statement" => value.clone_into(&mut self.statement),
                _ => {}
            }
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            match field.name() {
                "summary" => self.summary = format!("{value:?}").trim_matches('"').to_owned(),
                "db.statement" => {
                    self.statement = format!("{value:?}").trim_matches('"').to_owned()
                }
                _ => {}
            }
        }
    }

    pub(super) struct Layer;

    impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> tracing_subscriber::Layer<S> for Layer {
        fn on_new_span(
            &self,
            attributes: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            context: Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            attributes.record(&mut fields);
            if let (Some(observer), Some(span)) = (fields.observer, context.span(id)) {
                span.extensions_mut().insert(Observer(observer));
            }
        }

        fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, S>) {
            let Some(observer) = context.event_scope(event).and_then(|mut scope| {
                scope.find_map(|span| span.extensions().get::<Observer>().map(|o| o.0))
            }) else {
                return;
            };
            let mut fields = Fields::default();
            event.record(&mut fields);
            // sqlx sends short statements as the summary alone.
            let sql = if fields.statement.trim().is_empty() {
                fields.summary
            } else {
                fields.statement.trim().to_owned()
            };
            let callback = observers()
                .lock()
                .ok()
                .and_then(|observers| observers.get(&observer).cloned());
            if let Some(callback) = callback {
                callback(&sql);
            }
        }
    }
}
