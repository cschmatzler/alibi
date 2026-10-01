//! Equivalent passkey configurations and actual SQLite observations.
use crate::TestSchema;
use axum::{
    extract::Query,
    routing::{get, post},
    Json, Router,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{EmailPasswordPlugin, PasskeyPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::{
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
    SeaOrmStore,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserQuery {
    user_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Clock {
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for (name, age) in [("passkey-fresh", 1), ("passkey-no-freshness", 0)] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut configured = config.clone().base_path(&path);
        configured.session.fresh_age = Some(chrono::Duration::seconds(age));
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(configured.clone())
                .store(SeaOrmStore::<TestSchema>::new(configured, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(PasskeyPlugin::new())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let state_database = database.clone();
    Ok(router
        .route(
            "/__test/passkey-state",
            get(move |Query(query): Query<UserQuery>| {
                let database = state_database.clone();
                async move {
                    let rows = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            "SELECT user_id, counter, name FROM passkeys ORDER BY id",
                        ))
                        .await
                        .unwrap();
                    let passkeys: Vec<Value> = rows
                        .iter()
                        .map(|row| {
                            json!({
                                "userId": row.try_get::<String>("", "user_id").unwrap(),
                                "counter": row.try_get::<i64>("", "counter").unwrap(),
                                "name": row.try_get::<Option<String>>("", "name").unwrap(),
                            })
                        })
                        .collect();
                    let sessions = database
                        .query_one_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?",
                            [query.user_id.into()],
                        ))
                        .await
                        .unwrap()
                        .unwrap();
                    let challenges = database
                        .query_one_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            "SELECT COUNT(*) AS count FROM verifications",
                        ))
                        .await
                        .unwrap()
                        .unwrap();
                    Json(json!({ "passkeys": passkeys,
                "sessions": {"count": sessions.try_get::<i64>("", "count").unwrap()},
                "challenges": {"count": challenges.try_get::<i64>("", "count").unwrap()} }))
                }
            }),
        )
        .route(
            "/__test/passkey-challenge-clock",
            post(move |Json(clock): Json<Clock>| {
                let database = database.clone();
                async move {
                    database
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "UPDATE verifications SET expires_at = ?",
                            [clock.expires_at.into()],
                        ))
                        .await
                        .unwrap();
                    Json(json!({"updated": true}))
                }
            }),
        ))
}
