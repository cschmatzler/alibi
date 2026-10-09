//! Local magic-link delivery and explicit configuration fixtures.
use crate::TestSchema;
use crate::fixtures::passwordless_numeric_fixture::numeric_setting;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, MagicLinkTokenGenerator,
    MagicLinkTokenHasher, MagicLinkTokenStorage, SendMagicLink,
};
use alibi::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

struct ApplicationHasher(Arc<Mutex<String>>);
#[async_trait]
impl MagicLinkTokenHasher for ApplicationHasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        tokio::task::yield_now().await;
        match self.0.lock().await.as_str() {
            "coded" => {
                return Err(alibi::AuthError::Api {
                    status: 403,
                    code: Some("MAGIC_HASH_REJECTED".into()),
                    message: "Application hasher rejected".into(),
                });
            }
            "ordinary" => return Err(alibi::AuthError::internal("Application hasher failed")),
            _ => {}
        }
        Ok(format!("application:{token}"))
    }
}

#[derive(Default)]
struct GeneratorState {
    mode: String,
    receipts: Vec<String>,
}
struct ControlledGenerator(Arc<Mutex<GeneratorState>>);
#[async_trait]
impl MagicLinkTokenGenerator for ControlledGenerator {
    async fn generate(&self, email: &str) -> AuthResult<String> {
        tokio::task::yield_now().await;
        let mut state = self.0.lock().await;
        state.receipts.push(email.to_owned());
        if state.mode == "coded" {
            return Err(alibi::AuthError::Api {
                status: 403,
                code: Some("MAGIC_GENERATOR_REJECTED".into()),
                message: "Application generator rejected".into(),
            });
        }
        Ok(format!("controlled-link-{email}"))
    }
}

struct CustomToken;
#[async_trait]
impl MagicLinkTokenGenerator for CustomToken {
    async fn generate(&self, email: &str) -> AuthResult<String> {
        Ok(format!("custom-link-{email}"))
    }
}

pub(super) type Outbox = Arc<Mutex<HashMap<String, Value>>>;
#[derive(Clone)]
struct Sender(Outbox);
#[async_trait]
impl SendMagicLink for Sender {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        _context: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        let auth = _context.context::<TestSchema>().unwrap();
        let identifier = if auth.config.base_path.contains("magic-link-custom-hasher") {
            format!("application:{}", delivery.token)
        } else if auth.config.base_path.contains("magic-link-hashed") {
            use base64::Engine as _;
            use sha2::Digest as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(delivery.token.as_bytes()))
        } else {
            delivery.token.clone()
        };
        let context = crate::fixtures::passwordless_context::snapshot(
            _context,
            &format!("magic-link:{identifier}"),
        )
        .await?;
        let serialized = serde_json::to_value(delivery)?;
        let mut value = json!({"url": serialized["url"], "token": serialized["token"], "metadata": serialized["metadata"]});
        if let Some(context) = context {
            value["context"] = context;
        }
        _ = self.0.lock().await.insert(delivery.email.clone(), value);
        if auth.config.base_path.contains("magic-link-sender-coded") {
            return Err(alibi::AuthError::Api {
                status: 403,
                code: Some("MAGIC_DELIVERY_REJECTED".into()),
                message: "Application delivery rejected".into(),
            });
        }
        if auth.config.base_path.contains("magic-link-sender-ordinary") {
            return Err(alibi::AuthError::internal("Application delivery failed"));
        }
        Ok(())
    }
}

pub(super) fn plugin(outbox: Outbox) -> MagicLinkPlugin {
    MagicLinkPlugin::new(MagicLinkConfig {
        send_magic_link: Some(Arc::new(Sender(outbox))),
        ..Default::default()
    })
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    outbox: Outbox,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let hasher_mode = Arc::new(Mutex::new("success".to_owned()));
    let generator_state = Arc::new(Mutex::new(GeneratorState::default()));
    for name in [
        "magic-link-rate-policy",
        "magic-link-hashed",
        "magic-link-hashed-custom-token",
        "magic-link-custom-hasher",
        "magic-link-custom-hasher-errors",
        "magic-link-generator-reject",
        "magic-link-sender-coded",
        "magic-link-sender-ordinary",
        "magic-link-disabled",
        "magic-link-numeric-lifetime-zero",
        "magic-link-numeric-lifetime-fraction",
        "magic-link-numeric-lifetime-negative",
        "magic-link-numeric-lifetime-nan",
        "magic-link-numeric-lifetime-infinity",
        "magic-link-numeric-lifetime-negative-infinity",
    ] {
        let config = config
            .clone()
            .base_path(format!("/__test/profiles/{name}/api/auth"));
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config.clone(),
                    database.clone(),
                ))
                .rate_limit(
                    RateLimitConfig::new()
                        .enabled(name == "magic-link-rate-policy")
                        .default_limit(std::time::Duration::from_secs(60), 10000),
                )
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(EmailVerificationPlugin::new().send_on_sign_up(false))
                .plugin(PasswordManagementPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                    rate_limit: if name == "magic-link-rate-policy" {
                        alibi::EndpointRateLimit {
                            window_seconds: 1.0,
                            max_requests: 2.0,
                        }
                    } else {
                        MagicLinkConfig::default().rate_limit
                    },
                    send_magic_link: Some(Arc::new(Sender(outbox.clone()))),
                    generate_token: if name == "magic-link-generator-reject" {
                        Some(Arc::new(ControlledGenerator(generator_state.clone()))
                            as Arc<dyn MagicLinkTokenGenerator>)
                    } else {
                        (name == "magic-link-hashed-custom-token")
                            .then(|| Arc::new(CustomToken) as Arc<dyn MagicLinkTokenGenerator>)
                    },
                    storage: if name.starts_with("magic-link-custom-hasher") {
                        MagicLinkTokenStorage::Custom(Arc::new(ApplicationHasher(
                            if name.ends_with("-errors") {
                                hasher_mode.clone()
                            } else {
                                Arc::new(Mutex::new("success".to_owned()))
                            },
                        )))
                    } else if name.starts_with("magic-link-hashed") {
                        MagicLinkTokenStorage::Hashed
                    } else {
                        MagicLinkTokenStorage::Plain
                    },
                    disable_sign_up: name == "magic-link-disabled",
                    expires_in: numeric_setting(name, "lifetime", 300.0),
                }))
                .build()
                .await?,
        );
        router = router.nest(
            &config.base_path,
            auth.clone().axum_router().with_state(auth),
        );
    }
    router = router.route(
        "/__test/magic-link/hasher-control",
        post(move |Json(body): Json<Value>| {
            let mode = hasher_mode.clone();
            async move {
                *mode.lock().await = body["mode"].as_str().unwrap_or("success").to_owned();
                Json(json!({"status":true}))
            }
        }),
    );
    router = router.route("/__test/magic-link/generator-control", post(move |Json(body): Json<Value>| {
        let state = generator_state.clone();
        let database = database.clone();
        async move {
            let mut state = state.lock().await;
            if let Some(mode) = body["mode"].as_str() { state.mode = mode.to_owned(); }
            if body["clear"].as_bool() == Some(true) { state.receipts.clear(); }
            let counts: (i64, i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe("SELECT (SELECT COUNT(*) FROM verifications), (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM sessions)"))
                .fetch_one(database.get_sqlite_connection_pool()).await.unwrap();
            Json(json!({"mode":state.mode,"receipts":state.receipts,"proofCount":counts.0,"userCount":counts.1,"sessionCount":counts.2}))
        }
    }));
    Ok(router.route(
        "/__test/magic-link",
        get(move |Query(query): Query<HashMap<String, String>>| {
            let outbox = outbox.clone();
            async move {
                Json(
                    outbox
                        .lock()
                        .await
                        .get(query.get("email").map(String::as_str).unwrap_or_default())
                        .cloned()
                        .unwrap_or(Value::Null),
                )
            }
        }),
    ))
}
