//! Public authentication requests with the genuine enabled limiter.
use crate::{TestSchema, otp_profiles};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::{EndpointRateLimit, RateLimitConfig, RateLimitResolver, RateLimitRule};
use alibi::plugins::EmailPasswordPlugin;
use alibi::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use alibi_seaorm::DatabaseConnection;
use axum::Router;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct CounterApplication {
    cache: Arc<alibi_core::MemoryCacheAdapter>,
    mode: Arc<std::sync::Mutex<String>>,
    events: Arc<std::sync::Mutex<Vec<String>>>,
}
impl CounterApplication {
    fn event(&self, name: &str) {
        self.events.lock().unwrap().push(name.to_owned());
    }
}
struct GetSetOnly(CounterApplication);
struct RecoverableCounter(CounterApplication);
// The first adapter genuinely inherits the public unsupported-increment default.
#[async_trait::async_trait]
impl alibi_core::CacheAdapter for GetSetOnly {
    async fn set(&self, key: &str, value: &str, ttl: chrono::Duration) -> AuthResult<()> {
        self.0.event("set");
        self.0.cache.set(key, value, ttl).await
    }
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.0.event("get");
        self.0.cache.get(key).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.0.event("delete");
        self.0.cache.delete(key).await
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.0.cache.exists(key).await
    }
    async fn expire(&self, key: &str, ttl: chrono::Duration) -> AuthResult<()> {
        self.0.cache.expire(key, ttl).await
    }
    async fn clear(&self) -> AuthResult<()> {
        self.0.cache.clear().await
    }
}
#[async_trait::async_trait]
impl alibi_core::CacheAdapter for RecoverableCounter {
    async fn set(&self, key: &str, value: &str, ttl: chrono::Duration) -> AuthResult<()> {
        self.0.event("set");
        self.0.cache.set(key, value, ttl).await
    }
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.0.event("get");
        self.0.cache.get(key).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.0.event("delete");
        self.0.cache.delete(key).await
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.0.cache.exists(key).await
    }
    async fn expire(&self, key: &str, ttl: chrono::Duration) -> AuthResult<()> {
        self.0.cache.expire(key, ttl).await
    }
    async fn clear(&self) -> AuthResult<()> {
        self.0.cache.clear().await
    }

    async fn increment(&self, key: &str, ttl: Duration) -> AuthResult<f64> {
        let mode = self.0.mode.lock().unwrap().clone();
        if mode == "missing" {
            return GetSetOnly(self.0.clone()).increment(key, ttl).await;
        }
        self.0.event("increment");
        if mode == "throws" {
            return Err(alibi::AuthError::internal(
                "Application counter unavailable",
            ));
        }
        self.0.cache.increment(key, ttl).await
    }
}
#[derive(Debug)]
struct SignupQuota;
#[async_trait::async_trait]
impl RateLimitResolver for SignupQuota {
    async fn resolve(
        &self,
        request: &alibi_core::AuthRequest,
        _: &EndpointRateLimit,
    ) -> AuthResult<Option<EndpointRateLimit>> {
        Ok(
            if request
                .headers
                .get("x-rate-bypass")
                .is_some_and(|v| v == "yes")
            {
                None
            } else {
                Some(EndpointRateLimit {
                    max_requests: 2.0,
                    window_seconds: 60.0,
                })
            },
        )
    }
}

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
    let application = CounterApplication {
        cache: Arc::new(alibi_core::MemoryCacheAdapter::new()),
        mode: Arc::new(std::sync::Mutex::new("normal".to_owned())),
        events: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    for name in [
        "ordered",
        "default",
        "secondary-a",
        "secondary-b",
        "secondary-failure",
    ] {
        let mut config = base.clone();
        config.base_path = format!("/__test/profiles/rate-limit-{name}/api/auth");
        let path = config.base_path.clone();
        let mut limits = RateLimitConfig::new().default_limit(
            Duration::from_secs(60),
            if name == "ordered" { 1 } else { 10000 },
        );
        if name.starts_with("secondary-") {
            limits = limits
                .storage(Arc::new(alibi_core::CacheRateLimitStorage::new(
                    cache.clone(),
                )))
                .endpoint("/get-session", Duration::from_secs(1), 2)
                .rule("/list-sessions", RateLimitRule::Disabled);
        }
        if name == "secondary-failure" {
            limits = limits
                .storage(Arc::new(alibi_core::CacheRateLimitStorage::new(Arc::new(
                    RecoverableCounter(application.clone()),
                ))))
                .rule(
                    "/sign-up/email",
                    RateLimitRule::Dynamic(Arc::new(SignupQuota)),
                );
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
    let read_application = application.clone();
    router = router.route(
        "/__test/rate-limit-secondary/failure",
        axum::routing::get(move || {
            let app = read_application.clone();
            async move {
                axum::Json(
                    serde_json::json!({"events":std::mem::take(&mut *app.events.lock().unwrap())}),
                )
            }
        })
        .post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let app = application.clone();
            async move {
                *app.mode.lock().unwrap() = body["mode"].as_str().unwrap().to_owned();
                app.events.lock().unwrap().clear();
                axum::Json(serde_json::json!({"events":[]}))
            }
        }),
    );
    let control_cache = cache.clone();
    router = router.route("/__test/rate-limit-secondary/control", axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>| {let cache = control_cache.clone(); async move {
        use alibi_core::CacheAdapter;
        axum::Json(serde_json::json!({"value": cache.get(query.get("key").expect("requested key")).await.unwrap()}))
    }}));
    Ok(router)
}
