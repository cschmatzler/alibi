use crate::TestSchema;
use axum::{Router, extract::Json, routing::post};
use alibi::{
    AuthBuilder, AuthConfig, AuthResult, BetterAuth,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
        two_factor::{
            SendTwoFactorOtp, TwoFactorConfig, TwoFactorOtpCipher, TwoFactorOtpHasher,
            TwoFactorOtpStorage,
        },
    },
    wire::UserView,
};
use alibi_seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
type Receipts = Arc<Mutex<HashMap<String, Vec<Value>>>>;
#[derive(Clone, Default)]
pub(crate) struct State {
    deliveries: Arc<Mutex<HashMap<String, Value>>>,
    receipts: Receipts,
}
impl State {
    pub(crate) async fn reset(&self) {
        self.deliveries.lock().await.clear();
        self.receipts.lock().await.clear();
    }
}
struct Callback {
    profile: String,
    state: State,
}
impl Callback {
    async fn record(&self, phase: &str, input: &str) {
        self.state
            .receipts
            .lock()
            .await
            .entry(self.profile.clone())
            .or_default()
            .push(json!({"phase":phase,"input":input}));
    }
}
#[async_trait::async_trait]
impl SendTwoFactorOtp for Callback {
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
        if let Some(email) = &user.email {
            self.state
                .deliveries
                .lock()
                .await
                .insert(email.clone(), json!({"userId":user.id,"otp":otp}));
        }
        self.record("send", otp).await;
        Ok(())
    }
}
#[async_trait::async_trait]
impl TwoFactorOtpHasher for Callback {
    async fn hash(&self, input: &str) -> AuthResult<String> {
        self.record("hash", input).await;
        Ok(format!("hash-{}", input.chars().rev().collect::<String>()))
    }
}
#[async_trait::async_trait]
impl TwoFactorOtpCipher for Callback {
    async fn encrypt(&self, input: &str) -> AuthResult<String> {
        self.record("encrypt", input).await;
        Ok(format!(
            "cipher-{}",
            input.chars().rev().collect::<String>()
        ))
    }
    async fn decrypt(&self, input: &str) -> AuthResult<String> {
        self.record("decrypt", input).await;
        Ok(input
            .strip_prefix("cipher-")
            .unwrap_or("")
            .chars()
            .rev()
            .collect())
    }
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router<Arc<BetterAuth<TestSchema>>>, State)> {
    let state = State::default();
    let mut router = Router::new();
    for name in [
        "two-factor-otp-plain",
        "two-factor-otp-hashed",
        "two-factor-otp-encrypted",
        "two-factor-otp-custom-hash",
        "two-factor-otp-custom-cipher",
        "two-factor-otp-zero",
        "two-factor-otp-negative",
        "two-factor-otp-nan",
        "two-factor-otp-half",
        "two-factor-otp-large",
        "two-factor-otp-infinite-digits",
        "two-factor-otp-infinite-expiry",
        "two-factor-otp-negative-expiry",
    ] {
        let callback = Arc::new(Callback {
            profile: name.to_owned(),
            state: state.clone(),
        });
        let numeric = match name {
            "two-factor-otp-nan" => Some((f64::NAN, f64::NAN, f64::NAN)),
            "two-factor-otp-half" => Some((0.5, 0.5, f64::INFINITY)),
            "two-factor-otp-large" => Some((32769.5, 1e8, f64::INFINITY)),
            "two-factor-otp-infinite-digits" => Some((f64::INFINITY, 3.0, 5.0)),
            "two-factor-otp-infinite-expiry" => Some((6.0, f64::INFINITY, 5.0)),
            "two-factor-otp-negative-expiry" => Some((6.0, -1.0, 5.0)),
            _ => None,
        };
        let (digits, period, attempts) = if let Some(settings) = numeric {
            settings
        } else if name.ends_with("zero") {
            (0.0, 3.0, 5.0)
        } else if name.ends_with("negative") {
            (-1.0, 3.0, 5.0)
        } else if name.ends_with("plain") {
            (6.0, 3.0, 5.0)
        } else if name.ends_with("encrypted") {
            (8.0, 0.0, 0.0)
        } else if name.ends_with("hashed") {
            (3.5, 0.5, 2.5)
        } else {
            (3.0, 1.0, 2.0)
        };
        let storage = if name.ends_with("custom-hash") {
            TwoFactorOtpStorage::CustomHash(callback.clone())
        } else if name.ends_with("custom-cipher") {
            TwoFactorOtpStorage::CustomCipher(callback.clone())
        } else if name.ends_with("hashed") {
            TwoFactorOtpStorage::Hashed
        } else if name.ends_with("encrypted") {
            TwoFactorOtpStorage::Encrypted
        } else {
            TwoFactorOtpStorage::Plain
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.app_name = "Fixture Auth".to_owned();
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_signup(true)
                        .enable_username(false),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    send_otp: Some(callback),
                    otp_digits: digits,
                    otp_period_minutes: period,
                    otp_allowed_attempts: attempts,
                    otp_storage: storage,
                    totp_disabled: name.ends_with("hashed"),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = state.clone();
    Ok((
        router.route(
            "/__test/two-factor-otp-config",
            post(move |Json(body): Json<Control>| control(body, database.clone(), state.clone())),
        ),
        controls,
    ))
}
#[derive(Deserialize)]
struct Control {
    profile: String,
    email: String,
    identifier: Option<String>,
    counter: Option<String>,
    expire: Option<bool>,
}
async fn control(
    body: Control,
    database: DatabaseConnection,
    state: State,
) -> Result<Json<Value>, axum::http::StatusCode> {
    let delivery = state.deliveries.lock().await.get(&body.email).cloned();
    let row=if let Some(identifier)=body.identifier.clone(){database.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"SELECT id,identifier,value,expires_at AS expiresAt FROM verifications WHERE identifier=? ORDER BY created_at DESC",[identifier.into()])).await}else if let Some(user)=delivery.as_ref().and_then(|value|value.get("userId")).and_then(Value::as_str){database.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"SELECT id,identifier,value,expires_at AS expiresAt FROM verifications WHERE identifier LIKE ? OR identifier IN(SELECT '2fa-otp-'||identifier FROM verifications WHERE value=? AND identifier LIKE '2fa-%') ORDER BY created_at DESC",[format!("2fa-otp-{user}!%").into(),user.into()])).await}else{Ok(None)}.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let current = if let Some(row) = row {
        let identifier: String = row
            .try_get("", "identifier")
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(counter) = body.counter {
            let value: String = row
                .try_get("", "value")
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
            database
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE verifications SET value=? WHERE identifier=?",
                    [
                        format!("{}:{counter}", value.split(':').next().unwrap_or("")).into(),
                        identifier.clone().into(),
                    ],
                ))
                .await
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        if body.expire == Some(true) {
            database
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE verifications SET expires_at=? WHERE identifier=?",
                    [
                        (Utc::now() - chrono::Duration::seconds(1)).into(),
                        identifier.clone().into(),
                    ],
                ))
                .await
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        let row=database.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"SELECT id,identifier,value,expires_at AS expiresAt FROM verifications WHERE identifier=? ORDER BY created_at DESC",[identifier.into()])).await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        Some(
            json!({"id":row.try_get::<String>("","id").map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,"identifier":row.try_get::<String>("","identifier").map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,"value":row.try_get::<String>("","value").map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,"expiresAt":row.try_get::<chrono::DateTime<Utc>>("","expiresAt").map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?}),
        )
    } else {
        None
    };
    let identifier = body.identifier.as_deref().or_else(|| {
        current
            .as_ref()
            .and_then(|row| row.get("identifier"))
            .and_then(Value::as_str)
    });
    let generations = if let Some(identifier) = identifier {
        database
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS total FROM verifications WHERE identifier=?",
                [identifier.into()],
            ))
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
            .try_get::<i64>("", "total")
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        0
    };
    Ok(Json(
        json!({"delivery":delivery,"row":current,"generations":generations,"receipts":state.receipts.lock().await.get(&body.profile).cloned().unwrap_or_default()}),
    ))
}
