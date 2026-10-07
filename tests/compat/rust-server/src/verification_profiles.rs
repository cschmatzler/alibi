//! Core verification configuration fixtures, outside the public route inventory.

use crate::{CompatVerificationSender, EmailOutboxRecord, TestSchema};
use async_trait::async_trait;
use axum::Router;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, SendVerificationEmail, SessionManagementPlugin,
};
use alibi::wire::UserView;
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi_seaorm::sea_orm::DatabaseConnection;
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

struct Sender {
    inner: CompatVerificationSender,
    fail: bool,
}

#[async_trait]
impl SendVerificationEmail for Sender {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        self.inner.send(user, url, token).await?;
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
    for name in [
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
        };
        let plugin = EmailVerificationPlugin::new()
            .verification_token_expiry(Duration::seconds(90))
            .send_on_sign_in(true)
            .custom_send_verification_email(Arc::new(sender));
        let plugin = if name == "email-verification-no-signup-mail" {
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
    Ok(router)
}
