//! Public authentication requests with the genuine enabled limiter.
use crate::{TestSchema, otp_profiles};
use axum::Router;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::{
    EndpointRateLimit, RateLimitConfig, RateLimitResolver, RateLimitRule,
};
use alibi::plugins::EmailPasswordPlugin;
use alibi::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use alibi_seaorm::DatabaseConnection;
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct HeaderQuota;
#[async_trait::async_trait]
impl RateLimitResolver for HeaderQuota {
    async fn resolve(
        &self,
        request: &alibi_core::AuthRequest,
        inherited: &EndpointRateLimit,
    ) -> AuthResult<Option<EndpointRateLimit>> {
        Ok(
            if request
                .headers
                .get("x-rate-bypass")
                .is_some_and(|value| value == "yes")
            {
                None
            } else {
                Some(EndpointRateLimit {
                    max_requests: 1.0,
                    window_seconds: if request
                        .headers
                        .get("x-rate-zero")
                        .is_some_and(|value| value == "yes")
                    {
                        0.0
                    } else {
                        inherited.window_seconds
                    },
                })
            },
        )
    }
}

pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    outbox: otp_profiles::Outbox,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let mut router = Router::new();
    let cache = Arc::new(alibi_core::MemoryCacheAdapter::new());
    for name in ["ordered", "default", "secondary-a", "secondary-b"] {
        let mut config = base.clone();
        config.base_path = format!("/__test/profiles/rate-limit-{name}/api/auth");
        let path = config.base_path.clone();
        let mut limits = RateLimitConfig::new().default_limit(
            Duration::from_secs(60), if name == "ordered" { 1 } else { 10000 },
        );
        if name.starts_with("secondary-") {
            limits = limits.storage(Arc::new(alibi_core::CacheRateLimitStorage::new(cache.clone())))
                .endpoint("/get-session", Duration::from_secs(1), 2)
                .rule("/list-sessions", RateLimitRule::Disabled);
        }
        if name == "ordered" {
            limits = limits
                .endpoint("/sign-up/*", Duration::from_secs(60), 2)
                .endpoint("/sign-up/email", Duration::from_secs(60), 4)
                .rule(
                    "/get-session",
                    RateLimitRule::Dynamic(Arc::new(HeaderQuota)),
                )
                .rule("/list-sessions", RateLimitRule::Disabled);
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(limits)
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(otp_profiles::plugin(outbox.clone()))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let control_cache = cache.clone();
    router = router.route("/__test/rate-limit-secondary/control", axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>| {let cache = control_cache.clone(); async move {
        use alibi_core::CacheAdapter;
        axum::Json(serde_json::json!({"value": cache.get(query.get("key").expect("requested key")).await.unwrap()}))
    }}));
    Ok(router)
}
