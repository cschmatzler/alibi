//! Core verification configuration fixtures, outside the public route inventory.

use crate::{CompatVerificationSender, EmailOutboxRecord, TestSchema};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, SendVerificationEmail, SessionManagementPlugin,
};
use alibi::wire::UserView;
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi::seaorm::sea_orm::DatabaseConnection;
use async_trait::async_trait;
use axum::{Json, Router, routing::get};
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

struct Sender {
    inner: CompatVerificationSender,
    fail: bool,
    rate_limited: bool,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SendVerificationEmail for Sender {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        if self.rate_limited {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.send(user, url, token).await?;
        if self.rate_limited
            && alibi::hooks::current_request_hook_context().is_some_and(|request| {
                request
                    .headers
                    .get("x-verification-sender-mode")
                    .is_some_and(|mode| mode == "fail")
            })
        {
            return Err(AuthError::Api {
                status: 429,
                code: Some("APPLICATION_MAIL_LIMIT".into()),
                message: "Application mail limit reached".into(),
            });
        }
        if self.fail {
            Err(AuthError::bad_request("fixture delivery failed"))
        } else {
            Ok(())
        }
    }
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    outbox: Arc<Mutex<HashMap<String, EmailOutboxRecord>>>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for name in [
        "email-verification-rate-limited",
        "email-verification-required",
        "email-verification-no-signup-mail",
        "email-verification-failing-notifications",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = config.clone().base_path(&path);
        let sender = Sender {
            inner: CompatVerificationSender {
                outbox: outbox.clone(),
            },
            fail: name == "email-verification-failing-notifications",
            rate_limited: name == "email-verification-rate-limited",
            calls: calls.clone(),
        };
        let plugin = EmailVerificationPlugin::new()
            .verification_token_expiry(Duration::seconds(90))
            .send_on_sign_in(true)
            .custom_send_verification_email(Arc::new(sender));
        let plugin = if matches!(
            name,
            "email-verification-no-signup-mail" | "email-verification-rate-limited"
        ) {
            plugin.send_on_sign_up(false)
        } else {
            plugin
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_username(false)
                        .require_email_verification(true),
                )
                .plugin(plugin)
                .plugin(SessionManagementPlugin::new())
                .build()
                .await?,
        );
        let routes = auth.clone().axum_router().with_state(auth);
        router = router.nest(&path, routes);
    }
    Ok(router.route(
        "/__test/verification-sender-calls",
        get(move || {
            let calls = calls.clone();
            async move { Json(serde_json::json!({"calls": calls.load(Ordering::SeqCst)})) }
        }),
    ))
}
