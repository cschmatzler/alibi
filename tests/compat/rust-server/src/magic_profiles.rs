//! Local magic-link delivery and explicit configuration fixtures.
use crate::TestSchema;
use crate::fixtures::passwordless_numeric_fixture::numeric_setting;
use async_trait::async_trait;
use axum::{Json, Router, extract::Query, routing::get};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, MagicLinkTokenStorage, SendMagicLink,
};
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::sea_orm::DatabaseConnection;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

pub(super) type Outbox = Arc<Mutex<HashMap<String, Value>>>;
#[derive(Clone)]
struct Sender(Outbox);
#[async_trait]
impl SendMagicLink for Sender {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        let auth = _context.context::<TestSchema>().unwrap();
        let identifier = if auth.config.base_path.contains("magic-link-hashed") {
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
    for name in [
        "magic-link-hashed",
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
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(EmailVerificationPlugin::new().send_on_sign_up(false))
                .plugin(PasswordManagementPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                    send_magic_link: Some(Arc::new(Sender(outbox.clone()))),
                    storage: if name == "magic-link-hashed" {
                        MagicLinkTokenStorage::Hashed
                    } else {
                        MagicLinkTokenStorage::Plain
                    },
                    disable_sign_up: name == "magic-link-disabled",
                    expires_in: numeric_setting(name, "lifetime", 300.0),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(
            &config.base_path,
            auth.clone().axum_router().with_state(auth),
        );
    }
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
