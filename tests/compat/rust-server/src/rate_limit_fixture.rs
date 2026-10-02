//! Public authentication requests with the genuine enabled limiter.
use crate::{TestSchema, otp_profiles};
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::{RateLimitConfig, RateLimitRule, RateLimitResolver, EndpointRateLimit};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct HeaderQuota;
#[async_trait::async_trait]
impl RateLimitResolver for HeaderQuota {
    async fn resolve(&self, request: &better_auth_core::AuthRequest, inherited: &EndpointRateLimit) -> AuthResult<Option<EndpointRateLimit>> {
        Ok(if request.headers.get("x-rate-bypass").is_some_and(|value| value == "yes") {
            None
        } else {
            Some(EndpointRateLimit { max_requests: 1.0, window_seconds: if request.headers.get("x-rate-zero").is_some_and(|value| value == "yes") { 0.0 } else { inherited.window_seconds } })
        })
    }
}

pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    outbox: otp_profiles::Outbox,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let mut router = Router::new();
    for name in ["ordered", "default"] {
        let mut config = base.clone();
        config.base_path = format!("/__test/profiles/rate-limit-{name}/api/auth");
        let path = config.base_path.clone();
        let mut limits = RateLimitConfig::new().default_limit(Duration::from_secs(60), if name == "ordered" { 1 } else { 10000 });
        if name == "ordered" {
            limits = limits.endpoint("/sign-up/*", Duration::from_secs(60), 2)
                .endpoint("/sign-up/email", Duration::from_secs(60), 4)
                .rule("/get-session", RateLimitRule::Dynamic(Arc::new(HeaderQuota)))
                .rule("/list-sessions", RateLimitRule::Disabled);
        }
        let auth = Arc::new(AuthBuilder::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
            .rate_limit(limits)
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(otp_profiles::plugin(outbox.clone()))
            .build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
