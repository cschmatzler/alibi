//! A configured PostgreSQL namespace with an unchanged runtime search path.
use crate::TestSchema;
use alibi::{
    AuthBuilder, AuthConfig, AuthResult,
    integrations::axum::AxumIntegration,
    plugins::{EmailPasswordPlugin, SessionManagementPlugin, UserManagementPlugin},
};
use alibi::seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use axum::{Json, Router, routing::get};
use serde_json::json;
use std::sync::Arc;
pub(crate) async fn router(base: &AuthConfig) -> AuthResult<Router> {
    let Ok(connection_url) = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL") else {
        return Ok(Router::new());
    };
    let database = Database::connect(&connection_url)
        .await
        .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
    let namespace = format!("compat_schema_rust_{}", std::env::var("PORT").unwrap());
    let mut config = base
        .clone()
        .base_path("/__test/profiles/postgres-schema/api/auth");
    config.advanced.database.schema_name = Some(namespace.clone());
    #[cfg(feature = "seaorm")]
    let store = alibi::seaorm::SeaOrmStore::<TestSchema>::new(config.clone(), database.clone());
    #[cfg(not(feature = "seaorm"))]
    let store = {
        let runtime = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&connection_url)
            .await
            .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
        alibi::sqlx::SqlxStore::<TestSchema>::new(config.clone(), runtime)
    };
    alibi::store::SchemaMigrator::migrate(&store).await?;
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(UserManagementPlugin::new())
            .build()
            .await?,
    );
    let routes = auth.clone().axum_router().with_state(auth);
    Ok(Router::new().nest("/__test/profiles/postgres-schema/api/auth",routes).route("/__test/postgres-schema/state",get(move || {let database=database.clone();let namespace=namespace.clone();async move {
        let users=database.query_all_raw(Statement::from_string(DbBackend::Postgres,format!("SELECT id, name, email FROM \"{namespace}\".users ORDER BY email"))).await.unwrap();
        let sessions=database.query_all_raw(Statement::from_string(DbBackend::Postgres,format!("SELECT user_id FROM \"{namespace}\".sessions"))).await.unwrap();
        let schemas=database.query_all_raw(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1",[namespace.clone().into()])).await.unwrap();
        let path=database.query_one_raw(Statement::from_string(DbBackend::Postgres,"SHOW search_path")).await.unwrap().unwrap().try_get::<String>("","search_path").unwrap();
        Json(json!({"schemaExists":schemas.len()==1,"connectionUsesNamespace":path.contains(&namespace),"users":users.iter().map(|row|json!({"id":row.try_get::<String>("","id").unwrap(),"name":row.try_get::<String>("","name").unwrap(),"email":row.try_get::<String>("","email").unwrap()})).collect::<Vec<_>>(),"sessions":sessions.iter().map(|row|json!({"owner":row.try_get::<String>("","user_id").unwrap()})).collect::<Vec<_>>() }))
    }})))
}
