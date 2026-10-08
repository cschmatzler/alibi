//! Public authentication requests with the genuine enabled limiter.
use crate::{TestSchema, otp_profiles};
use axum::{Json, routing::{get, post}};
use alibi_core::store::SchemaMigrator;
use alibi_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{Value, json};
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
    #[cfg(feature = "seaorm")]
    let storage = Arc::new(alibi_seaorm::SeaOrmRateLimitStorage::new(database.clone()));
    #[cfg(not(feature = "seaorm"))]
    let storage = Arc::new(alibi_sqlx::SqlxRateLimitStorage::new(alibi_sqlx::SqlxPool::from(database.get_sqlite_connection_pool().clone())));
    storage.migrate().await?;
    let control_database = database.clone();
    let read_database = database.clone();
    let mut router = Router::new().route("/__test/rate-database-state", get(move || {
        let database = read_database.clone();
        async move {
            let rows = database.query_all_raw(Statement::from_string(DbBackend::Sqlite, "SELECT key,count,last_request FROM rate_limit ORDER BY key")).await.unwrap();
            Json(rows.into_iter().map(|row| json!({"key": row.try_get::<String>("", "key").unwrap(), "count": row.try_get::<f64>("", "count").unwrap(), "lastRequest": row.try_get::<i64>("", "last_request").unwrap()})).collect::<Vec<_>>())
        }
    }));
    router = router.route("/__test/rate-database-control", post(move |Json(body): Json<Value>| {
        let database = control_database.clone();
        async move {
            let sql = if body["action"] == "disable" { "ALTER TABLE rate_limit RENAME TO fixtureRateLimitHeld" } else { "ALTER TABLE fixtureRateLimitHeld RENAME TO rate_limit" };
            database.execute_raw(Statement::from_string(DbBackend::Sqlite, sql)).await.unwrap();
            Json(json!({"status": true}))
        }
    }));
    let custom = Arc::new(CustomQuota::default());
    let cache = Arc::new(alibi_core::MemoryCacheAdapter::new());
    let application = CounterApplication {
        cache: Arc::new(alibi_core::MemoryCacheAdapter::new()),
        mode: Arc::new(std::sync::Mutex::new("normal".to_owned())),
        events: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    for name in [
        "ordered",
        "default",
        "custom",
        "custom-memory",
        "database-first",
        "database-second",
        "secondary-a",
        "secondary-b",
        "secondary-failure",
        "concurrent-memory",
        "concurrent-secondary-a",
        "concurrent-secondary-b",
    ] {
        let mut config = base.clone();
        config.base_path = format!("/__test/profiles/rate-limit-{name}/api/auth");
        let path = config.base_path.clone();
        let mut limits = RateLimitConfig::new().default_limit(
            Duration::from_secs(60),
            if name == "ordered" { 1 } else { 10000 },
        );
        if name.starts_with("database-") {
            limits = limits.storage(storage.clone()).endpoint("/get-session", Duration::from_secs(1), 2);
        }
        if name.contains("secondary") {
            limits = limits.storage(Arc::new(alibi_core::CacheRateLimitStorage::new(
                cache.clone(),
            )));
            if !name.starts_with("concurrent-") {
                limits = limits
                    .endpoint("/get-session", Duration::from_secs(1), 2)
                    .rule("/list-sessions", RateLimitRule::Disabled);
            }
        }
        if name.starts_with("concurrent-") {
            limits = limits.endpoint("/sign-up/email", Duration::from_secs(60), 3);
        }
        if name.starts_with("custom") {
            limits = limits.endpoint("/get-session", Duration::from_secs(1), 2);
            if name == "custom" {limits = limits.storage(custom.clone());}
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
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                database.clone(),
            ))
            .rate_limit(limits)
            .plugin(EmailPasswordPlugin::new().enable_username(false));
        let builder = if name.starts_with("concurrent-") {
            builder
        } else {
            builder.plugin(otp_profiles::plugin(outbox.clone()))
        };
        let auth = Arc::new(builder.build().await?);
        if name == "secondary-failure" {
            // The reference fixture awaits this public handler inside its outer
            // host catch. Preserve that host boundary for propagated quota errors.
            let mounted: Router<Arc<BetterAuth<TestSchema>>> = Router::new().fallback(move |axum::extract::OriginalUri(uri): axum::extract::OriginalUri, request: axum::extract::Request| {
                let auth=auth.clone();async move {
                    use axum::response::IntoResponse;
                    let (parts,body)=request.into_parts();
                    let method=match parts.method.as_str() {"POST"=>alibi_core::HttpMethod::Post,"GET"=>alibi_core::HttpMethod::Get,_=>alibi_core::HttpMethod::Options};
                    let headers=parts.headers.iter().filter_map(|(name,value)|value.to_str().ok().map(|value|(name.to_string(),value.to_owned()))).collect();
                    let bytes=axum::body::to_bytes(body,1024*1024).await.unwrap();
                    let query=url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()).map(|(name,value)|(name.into_owned(),value.into_owned())).collect();
                    let request=alibi_core::AuthRequest::from_parts(method,uri.path().to_owned(),headers,(!bytes.is_empty()).then(||bytes.to_vec()),query);
                    match auth.handle_request(request).await {
                        Ok(result)=>{let mut response=axum::response::Response::builder().status(result.status);for (name,value) in result.headers {response=response.header(name,value);}response.body(axum::body::Body::from(result.body)).unwrap()},
                        Err(_)=>(axum::http::StatusCode::INTERNAL_SERVER_ERROR,[("content-type","application/json;charset=utf-8")],Json(json!({"message":"Internal server error"}))).into_response(),
                    }
                }
            });
            router=router.nest(&path,mounted);
        } else {
            router = router.nest(&path, auth.clone().axum_router().with_state(auth));
        }
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
