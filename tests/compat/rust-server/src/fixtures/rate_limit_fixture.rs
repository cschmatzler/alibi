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

#[derive(Debug, Default)]
struct CustomQuota {
    rows: std::sync::Mutex<std::collections::BTreeMap<String, (u32, i64)>>,
    failure: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl alibi_core::RateLimitStorage for CustomQuota {
    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<alibi_core::RateLimitDecision> {
        if self.failure.load(std::sync::atomic::Ordering::SeqCst) {return Err(alibi::AuthError::internal("Application quota storage failed"));}
        let now = chrono::Utc::now().timestamp_millis();
        let mut rows = self.rows.lock().unwrap();
        if let Some((count,last)) = rows.get(key).filter(|(_,last)| ((now-*last) as f64) < rule.window_seconds*1000.0) {
            if f64::from(*count) >= rule.max_requests {return Ok(alibi_core::RateLimitDecision::Blocked {retry_after: (((*last as f64)+rule.window_seconds*1000.0-(now as f64))/1000.0).ceil()});}
        }
        let count = rows.get(key).filter(|(_,last)| ((now-*last) as f64) < rule.window_seconds*1000.0).map_or(1, |(count,_)| count+1);
        rows.insert(key.into(),(count,now));
        Ok(alibi_core::RateLimitDecision::Allowed)
    }
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    outbox: otp_profiles::Outbox,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let mut router = Router::new();
    let custom = Arc::new(CustomQuota::default());
    let cache = Arc::new(alibi_core::MemoryCacheAdapter::new());
    for name in ["ordered", "default", "secondary-a", "secondary-b", "custom", "custom-memory"] {
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
        if name.starts_with("custom") {
            limits = limits.endpoint("/get-session", Duration::from_secs(1), 2);
            if name == "custom" {limits = limits.storage(custom.clone());}
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
    router = router.route("/__test/rate-limit-custom/control", axum::routing::get({let custom=custom.clone();move || {let custom=custom.clone();async move {
        let rows=custom.rows.lock().unwrap().iter().map(|(key,(count,last))| serde_json::json!({"key":key,"count":count,"lastRequest":chrono::DateTime::from_timestamp_millis(*last).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)})).collect::<Vec<_>>();
        axum::Json(serde_json::json!({"failure":custom.failure.load(std::sync::atomic::Ordering::SeqCst),"rows":rows}))
    }}}).post({let custom=custom.clone();move |axum::Json(input):axum::Json<serde_json::Value>| {let custom=custom.clone();async move {
        custom.failure.store(input["failure"].as_bool().unwrap(),std::sync::atomic::Ordering::SeqCst);
        let rows=custom.rows.lock().unwrap().iter().map(|(key,(count,last))| serde_json::json!({"key":key,"count":count,"lastRequest":chrono::DateTime::from_timestamp_millis(*last).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis,true)})).collect::<Vec<_>>();
        axum::Json(serde_json::json!({"failure":custom.failure.load(std::sync::atomic::Ordering::SeqCst),"rows":rows}))
    }}}));
    let control_cache = cache.clone();
    router = router.route("/__test/rate-limit-secondary/control", axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>| {let cache = control_cache.clone(); async move {
        use alibi_core::CacheAdapter;
        axum::Json(serde_json::json!({"value": cache.get(query.get("key").expect("requested key")).await.unwrap()}))
    }}));
    Ok(router)
}
