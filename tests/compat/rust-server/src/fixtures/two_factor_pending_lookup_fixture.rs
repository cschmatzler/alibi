//! Application-owned database metrics and physical state for pending challenges.
use crate::TestSchema;
use alibi::seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use alibi::{
    Alibi, AuthBuilder, AuthConfig, AuthError, AuthResult,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
        two_factor::{SendTwoFactorOtp, TwoFactorBackupStorage, TwoFactorConfig},
    },
    wire::UserView,
};
use alibi::{
    CreateVerification, UpdateUser,
    store::{UserStore, VerificationStore},
};
use axum::{Json, Router, routing::post};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
type Auth = Arc<Alibi<TestSchema>>;
#[derive(Default)]
struct Trace {
    armed: bool,
    receipts: Vec<String>,
}
#[derive(Default)]
struct Delivery(Mutex<HashMap<String, String>>);
#[async_trait::async_trait]
impl SendTwoFactorOtp for Delivery {
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
        if let Some(email) = &user.email {
            self.0
                .lock()
                .map_err(|_| AuthError::internal("delivery lock poisoned"))?
                .insert(email.clone(), otp.into());
        }
        Ok(())
    }
}
fn phase(sql: &str) -> Option<&'static str> {
    let query = sql.to_lowercase();
    if query.starts_with("select") && query.contains("from \"verifications\"") {
        if query.contains("\"identifier\" =") {
            return Some("lookup");
        }
        if query.contains("\"expires_at\" <") {
            return Some("cleanup-read");
        }
    }
    if query.starts_with("delete")
        && query.contains("from \"verifications\"")
        && query.contains("\"expires_at\" <")
    {
        return Some("cleanup-delete");
    }
    if query.starts_with("select") && query.contains("from \"users\"") {
        return Some("user");
    }
    None
}
async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,"SELECT id,identifier,value,expires_at,created_at,updated_at FROM verifications ORDER BY CASE WHEN identifier LIKE '2fa-attempts-%' THEN 0 WHEN identifier LIKE '2fa-otp-%' THEN 1 WHEN identifier LIKE '2fa-%' THEN 2 ELSE 3 END,created_at,id")).await.map_err(|error|AuthError::internal(error.to_string()))?;
    let mut verifications = Vec::new();
    for row in rows {
        let string = |column| {
            row.try_get::<String>("", column)
                .map_err(|error| AuthError::internal(error.to_string()))
        };
        let date = |column| {
            row.try_get::<DateTime<Utc>>("", column)
                .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
                .map_err(|error| AuthError::internal(error.to_string()))
        };
        verifications.push(json!({"id":string("id")?,"identifier":string("identifier")?,"value":string("value")?,"expiresAt":date("expires_at")?,"createdAt":date("created_at")?,"updatedAt":date("updated_at")?}));
    }
    let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,"SELECT t.id,t.user_id,t.secret,t.backup_codes,t.verified,CAST(t.failed_verification_count AS REAL) AS failed_verification_count,t.locked_until FROM two_factor t JOIN users u ON u.id=t.user_id ORDER BY u.email,t.id")).await.map_err(|error|AuthError::internal(error.to_string()))?;
    let mut factors = Vec::new();
    for row in rows {
        let string = |column| {
            row.try_get::<String>("", column)
                .map_err(|error| AuthError::internal(error.to_string()))
        };
        let verified = row
            .try_get::<Option<bool>>("", "verified")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let count = row
            .try_get::<Option<f64>>("", "failed_verification_count")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let locked = row
            .try_get::<Option<DateTime<Utc>>>("", "locked_until")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        factors.push(json!({"id":string("id")?,"userId":string("user_id")?,"secret":string("secret")?,"backupCodes":string("backup_codes")?,"verified":verified,"failedVerificationCount":count,"lockedUntil":locked.map(|date|date.to_rfc3339_opts(SecondsFormat::Millis,true))}));
    }
    Ok(json!({"verifications":verifications,"factors":factors}))
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Auth>> {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let delivery = Arc::new(Delivery::default());
    let store = Arc::new(crate::backend::store::<TestSchema>(
        base.clone(),
        database.clone(),
    ));
    let mut router = Router::new();
    for name in [
        "two-factor-pending-lookup",
        "two-factor-pending-lookup-disabled",
        "two-factor-pending-lookup-zero",
        "two-factor-pending-lookup-zero-disabled",
    ] {
        let recorded = trace.clone();
        let observed = crate::backend::observe(&database, move |sql| {
            if let Some(name) = phase(sql) {
                if let Ok(mut trace) = recorded.lock() {
                    if trace.armed {
                        trace.receipts.push(name.into());
                        if name == "user" {
                            trace.armed = false;
                        }
                    }
                }
            }
        });
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.verification.disable_cleanup = name.ends_with("-disabled");
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    observed.database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    skip_verification_on_enable: true,
                    two_factor_cookie_max_age: if name.contains("-zero") { 0.0 } else { 600.0 },
                    backup_storage: TwoFactorBackupStorage::Plain,
                    send_otp: Some(delivery.clone()),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(
            &path,
            observed.scope(auth.clone().axum_router().with_state(auth)),
        );
    }
    Ok(router.route(
        "/__test/two-factor-pending-lookup",
        post(move |Json(body): Json<Value>| {
            let trace = trace.clone();
            let delivery = delivery.clone();
            let store = store.clone();
            let database = database.clone();
            async move {
                trace
                    .lock()
                    .map_err(|_| AuthError::internal("trace lock poisoned"))?
                    .armed = false;
                let text = |key| body[key].as_str().unwrap_or_default();
                match text("action") {
                    "clear" => {
                        trace
                            .lock()
                            .map_err(|_| AuthError::internal("trace lock poisoned"))?
                            .receipts
                            .clear();
                        return Ok(Json(json!({"cleared":true})));
                    }
                    "arm" => {
                        let mut trace = trace
                            .lock()
                            .map_err(|_| AuthError::internal("trace lock poisoned"))?;
                        trace.receipts.clear();
                        trace.armed = true;
                        return Ok::<_, AuthError>(Json(json!({"armed":true})));
                    }
                    "delivery" => {
                        return Ok(Json(
                            delivery
                                .0
                                .lock()
                                .map_err(|_| AuthError::internal("delivery lock poisoned"))?
                                .get(text("email"))
                                .map(|otp| json!({"otp":otp}))
                                .unwrap_or(Value::Null),
                        ));
                    }
                    "snapshot" => {
                        let receipts = trace
                            .lock()
                            .map_err(|_| AuthError::internal("trace lock poisoned"))?
                            .receipts
                            .clone();
                        return Ok(Json(
                            json!({"receipts":receipts,"snapshot":snapshot(&database).await?}),
                        ));
                    }
                    "seed" => {
                        let expires = DateTime::parse_from_rfc3339(text("expiresAt"))
                            .map_err(|error| AuthError::internal(error.to_string()))?
                            .with_timezone(&Utc);
                        let row = store
                            .create_verification(CreateVerification {
                                identifier: text("identifier").into(),
                                value: text("value").into(),
                                expires_at: expires,
                            })
                            .await?;
                        if body["createdAt"].is_string() {
                            database
                                .execute_raw(Statement::from_sql_and_values(
                                    DbBackend::Sqlite,
                                    "UPDATE verifications SET created_at=? WHERE id=?",
                                    [text("createdAt").into(), row.id.into()],
                                ))
                                .await
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                        }
                    }
                    "patch" => {
                        for (key, column) in [("expiresAt", "expires_at"), ("value", "value")] {
                            if body[key].is_string() {
                                database
                                    .execute_raw(Statement::from_sql_and_values(
                                        DbBackend::Sqlite,
                                        format!(
                                            "UPDATE verifications SET {column}=? WHERE identifier=?"
                                        ),
                                        [text(key).into(), text("identifier").into()],
                                    ))
                                    .await
                                    .map_err(|error| AuthError::internal(error.to_string()))?;
                            }
                        }
                    }
                    "user" => {
                        store
                            .update_user(
                                text("userId"),
                                UpdateUser {
                                    name: Some(text("name").into()),
                                    ..Default::default()
                                },
                            )
                            .await?;
                    }
                    _ => {}
                }
                Ok(Json(json!({"changed":true})))
            }
        }),
    ))
}
