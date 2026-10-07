//! Request-local origin policy at the public dispatch and physical storage boundary.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "contract regressions assert complete endpoint outcomes"
)]
use crate::storage::{Backend, Db, TestResult, backend_tests};
use alibi::config::{BaseUrlProtocol, DynamicBaseUrl, TrustedOriginsResolver};
use alibi::plugins::magic_link::MagicLinkDelivery;
use alibi::plugins::{EmailPasswordPlugin, MagicLinkConfig, MagicLinkPlugin, SendMagicLink};
use alibi::{AuthBuilder, AuthConfig};
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    BeforeRequestAction, CallbackContext, HttpMethod,
};
use async_trait::async_trait;
use serde_json::json;
use std::sync::{Arc, Mutex};

backend_tests!(dynamic_origin_dispatch, dynamic_origin_magic_link);
const SECRET: &str = "origin-policy-fixture-secret-at-least-32";
fn config() -> AuthConfig {
    AuthConfig::new(SECRET)
        .dynamic_base_url(DynamicBaseUrl {
            allowed_hosts: vec!["*.example.test".into(), "localhost:8080".into()],
            protocol: Some(BaseUrlProtocol::Auto),
            fallback: Some("https://fallback.test".into()),
        })
        .trusted_origins_resolver(ClientOrigin)
}
struct ClientOrigin;
#[async_trait]
impl TrustedOriginsResolver for ClientOrigin {
    async fn resolve(&self, request: &AuthRequest) -> AuthResult<Vec<String>> {
        assert!(request.path().starts_with("/api/auth/"));
        assert!(request.url().is_some());
        match request.header("x-origin-error").map(String::as_str) {
            Some("ordinary") => {
                return Err(alibi_core::AuthError::internal(
                    "private origin resolver failure",
                ));
            }
            Some("api") => {
                return Err(alibi_core::AuthError::forbidden(
                    "origin policy unavailable",
                ));
            }
            _ => {}
        }
        Ok(
            if request.header("x-client").map(String::as_str) == Some("mobile") {
                vec!["myapp://client/cb".into()]
            } else {
                vec![]
            },
        )
    }
}
fn request(
    method: HttpMethod,
    path: &str,
    host: &str,
    origin: Option<&str>,
    body: serde_json::Value,
) -> AuthRequest {
    let mut headers = std::collections::HashMap::from([
        ("host".into(), host.into()),
        ("content-type".into(), "application/json".into()),
    ]);
    if let Some(origin) = origin {
        _ = headers.insert("origin".into(), origin.into());
    }
    AuthRequest::from_parts(
        method,
        format!("/api/auth{path}"),
        headers,
        Some(body.to_string().into_bytes()),
        Default::default(),
    )
    .with_url(url::Url::parse(&format!("https://{host}/api/auth{path}")).unwrap())
}
// Exercise the installed SDK lifecycle callbacks, which must receive the same
// effective policy as the endpoint rather than the builder's static config.
struct OriginContextProbe;
fn assert_effective<S: AuthSchema>(req: &AuthRequest, ctx: &AuthContext<S>) {
    assert_eq!(
        ctx.config.base_url,
        format!("https://{}", req.header("host").unwrap())
    );
    assert!(!ctx.config.is_origin_trusted("https://evil.test"));
    assert!(
        req.header("x-origin-error").is_none(),
        "resolver failures must precede plugin callbacks"
    );
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OriginContextProbe {
    fn name(&self) -> &'static str {
        "origin-context-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        assert_effective(req, ctx);
        Ok(None)
    }
    async fn on_http_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        assert_effective(req, ctx);
        Ok(None)
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        assert_effective(req, ctx);
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        assert_effective(req, ctx);
        Ok(response)
    }
}
async fn dynamic_origin_dispatch<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cfg = config();
    let auth = AuthBuilder::<B::Schema>::new(cfg.clone())
        .store(B::store(Arc::new(cfg), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig {
            enabled: false,
            ..Default::default()
        })
        .plugin(OriginContextProbe)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    for (mode, status) in [("ordinary", 500), ("api", 403)] {
        let mut req = request(
            HttpMethod::Post,
            "/sign-up/email",
            "a.example.test",
            Some("https://a.example.test"),
            json!({"email":"resolver-blocked@fixture.test","password":"password123","name":"Blocked"}),
        );
        drop(req.headers.insert("x-origin-error".into(), mode.into()));
        let response = auth.handle_request(req).await?;
        assert_eq!(response.status, status);
        assert!(response.headers.get("set-cookie").is_none());
        for table in ["users", "accounts", "sessions"] {
            assert_eq!(db.count(table).await?, 0);
        }
    }
    for origin in [
        "https://evil.test",
        "https://a.example.test.evil.test",
        "http://localhost:8081",
    ] {
        let response = auth
            .handle_request(request(
                HttpMethod::Post,
                "/sign-up/email",
                "a.example.test",
                Some(origin),
                json!({"email":"blocked@fixture.test","password":"password123","name":"Blocked"}),
            ))
            .await?;
        assert_eq!(response.status, 403, "{origin}: {:?}", response.body);
        assert!(response.headers.get("set-cookie").is_none());
        assert_eq!(db.count("users").await?, 0);
        assert_eq!(db.count("sessions").await?, 0);
    }
    let response = auth
        .handle_request(request(
            HttpMethod::Post,
            "/sign-up/email",
            "a.example.test",
            Some("https://a.example.test"),
            json!({"email":"owner@fixture.test","password":"password123","name":"Owner"}),
        ))
        .await?;
    assert_eq!(response.status, 200, "{:?}", response.body);
    assert!(response.headers.get("set-cookie").is_some());
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("sessions").await?, 1);
    for (callback, mobile, accepted) in [
        ("https://b.example.test:443/cb?q=1#fragment", false, true),
        ("https://user:pass@b.example.test/cb", false, true),
        ("https://b.example.test:444/cb", false, false),
        ("https://b.example.test.evil.test/cb", false, false),
        ("myapp://CLIENT/cb/sub?q=1#fragment", true, true),
        ("myapp://client/cb/%2e%2e/evil", true, false),
        ("myapp://client/cb?ignored=1", false, false),
        ("myapp://client:123/cb", true, false),
        ("myapp://user@client/cb", true, false),
    ] {
        let before = db.count("sessions").await?;
        let mut req = request(
            HttpMethod::Post,
            "/sign-in/email",
            "b.example.test",
            Some("https://b.example.test"),
            json!({"email":"owner@fixture.test","password":"password123","callbackURL":callback}),
        );
        if mobile {
            _ = req.headers.insert("x-client".into(), "mobile".into());
        }
        let response = auth.handle_request(req).await?;
        assert_eq!(
            response.status,
            if accepted { 200 } else { 403 },
            "{callback}: {:?}",
            response.body
        );
        assert_eq!(
            response.headers.get("location").map(String::as_str),
            accepted.then_some(callback)
        );
        assert_eq!(response.headers.get("set-cookie").is_some(), accepted);
        assert_eq!(db.count("sessions").await?, before + i64::from(accepted));
    }
    println!(
        "{}: dispatch users={} sessions={}",
        std::any::type_name::<B>(),
        db.count("users").await?,
        db.count("sessions").await?
    );
    assert_eq!(auth.config().base_url, "http://localhost:3000");
    assert!(auth.config().trusted_origins.is_empty());
    drop(auth);
    B::close(connection).await?;
    Ok(())
}
struct Delivery(Arc<Mutex<Option<MagicLinkDelivery>>>);
#[async_trait]
impl SendMagicLink for Delivery {
    async fn send(&self, delivery: &MagicLinkDelivery, _: &CallbackContext) -> AuthResult<()> {
        *self.0.lock().unwrap() = Some(delivery.clone());
        Ok(())
    }
}
async fn dynamic_origin_magic_link<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cfg = config();
    let delivered = Arc::new(Mutex::new(None));
    let auth = AuthBuilder::<B::Schema>::new(cfg.clone())
        .store(B::store(Arc::new(cfg), &connection))
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(Arc::new(Delivery(Arc::clone(&delivered)))),
            ..Default::default()
        }))
        .build()
        .await?;
    let response = auth
        .handle_request(request(
            HttpMethod::Post,
            "/sign-in/magic-link",
            "a.example.test",
            Some("https://a.example.test"),
            json!({"email":"magic@fixture.test","callbackURL":"/done"}),
        ))
        .await?;
    assert_eq!(response.status, 200, "{:?}", response.body);
    let delivery = delivered.lock().unwrap().clone().unwrap();
    assert!(
        delivery
            .url
            .starts_with("https://a.example.test/api/auth/magic-link/verify?")
    );
    assert_eq!(db.count("verifications").await?, 1);
    for callback in ["https://a.example.test.evil.test/done", "myapp://client/cb"] {
        let mut req = request(
            HttpMethod::Get,
            "/magic-link/verify",
            "b.example.test",
            None,
            json!(null),
        );
        _ = req.query.insert("token".into(), delivery.token.clone());
        _ = req.query.insert("callbackURL".into(), callback.into());
        let response = auth.handle_request(req).await?;
        assert_eq!(response.status, 403);
        assert!(response.headers.get("set-cookie").is_none());
        assert_eq!(db.count("verifications").await?, 1);
        assert_eq!(db.count("users").await?, 0);
        assert_eq!(db.count("sessions").await?, 0);
    }
    let mut req = request(
        HttpMethod::Get,
        "/magic-link/verify",
        "b.example.test",
        None,
        json!(null),
    );
    _ = req.query.insert("token".into(), delivery.token);
    _ = req.query.insert("callbackURL".into(), "/done".into());
    let replay = req.clone();
    let response = auth.handle_request(req).await?;
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("location").map(String::as_str),
        Some("https://b.example.test/done")
    );
    assert!(response.headers.get("set-cookie").is_some());
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("sessions").await?, 1);
    let response = auth.handle_request(replay).await?;
    assert!(response.headers.get("set-cookie").is_none());
    assert_eq!(db.count("sessions").await?, 1);
    drop(auth);
    B::close(connection).await?;
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture setup propagates errors while contract assertions intentionally fail the test"
)]
async fn dynamic_origin_resolution() -> TestResult {
    let mut observations = Vec::new();
    for (host, transport, forwarded_host, forwarded_protocol, trust, expected) in [
        (
            "a.example.test",
            "https://a.example.test",
            "evil.test",
            "http",
            false,
            "https://a.example.test",
        ),
        (
            "a.example.test",
            "https://a.example.test",
            "evil.test",
            "http",
            true,
            "https://fallback.test",
        ),
        (
            "a.example.test.evil.test",
            "https://internal.test",
            "b.example.test",
            "http",
            false,
            "https://fallback.test",
        ),
        (
            "a.example.test.evil.test",
            "https://internal.test",
            "b.example.test",
            "http",
            true,
            "http://b.example.test",
        ),
        (
            "localhost:8080",
            "http://localhost:8080",
            "evil.test",
            "http",
            false,
            "http://localhost:8080",
        ),
        (
            "localhost:8080",
            "http://localhost:8080",
            "evil.test",
            "http",
            true,
            "https://fallback.test",
        ),
    ] {
        let mut cfg = config();
        cfg.advanced.trust_forwarded_host = trust;
        let mut req = request(HttpMethod::Get, "/ok", host, None, json!(null));
        req = req.with_url(url::Url::parse(transport)?);
        _ = req
            .headers
            .insert("x-forwarded-host".into(), forwarded_host.into());
        _ = req
            .headers
            .insert("x-forwarded-proto".into(), forwarded_protocol.into());
        let effective = cfg.resolve_request(&req).await?;
        assert_eq!(effective.base_url, expected);
        assert!(!effective.is_origin_trusted("https://evil.test"));
        observations.push(json!({"host":host,"url":transport,"trust":trust,"result":format!("{}/api/auth", effective.base_url)}));
    }
    println!(
        "native-resolutions={}",
        serde_json::to_string(&observations)?
    );
    for (protocol, expected, accepts_http) in [
        (None, "http://a.example.test", false),
        (Some(BaseUrlProtocol::Auto), "http://a.example.test", true),
        (Some(BaseUrlProtocol::Http), "http://a.example.test", true),
        (
            Some(BaseUrlProtocol::Https),
            "https://a.example.test",
            false,
        ),
    ] {
        let mut cfg = config();
        cfg.dynamic_base_url.as_mut().unwrap().protocol = protocol;
        let req = request(HttpMethod::Get, "/ok", "a.example.test", None, json!(null))
            .with_url(url::Url::parse("http://a.example.test/api/auth/ok")?);
        let effective = cfg.resolve_request(&req).await?;
        assert_eq!(effective.base_url, expected);
        assert_eq!(
            effective.is_origin_trusted("http://a.example.test"),
            accepts_http
        );
    }
    for (host, expected_http) in [
        ("127.example.test", false),
        ("127.0.0.1", true),
        ("[::1]", true),
    ] {
        let mut cfg = config();
        cfg.dynamic_base_url = Some(DynamicBaseUrl {
            allowed_hosts: vec![host.into()],
            protocol: None,
            fallback: None,
        });
        let effective = cfg
            .resolve_request(&request(HttpMethod::Get, "/ok", host, None, json!(null)))
            .await?;
        assert_eq!(
            effective.is_origin_trusted(&format!("http://{host}")),
            expected_http
        );
    }
    let mut cfg = config();
    cfg.dynamic_base_url.as_mut().unwrap().allowed_hosts.clear();
    assert!(cfg.validate().is_err());
    cfg.dynamic_base_url
        .as_mut()
        .unwrap()
        .allowed_hosts
        .push("a.example.test".into());
    cfg.dynamic_base_url.as_mut().unwrap().fallback = None;
    assert!(
        cfg.resolve_request(&request(
            HttpMethod::Get,
            "/ok",
            "evil.test",
            None,
            json!(null)
        ))
        .await
        .is_err()
    );
    Ok(())
}

#[test]
fn dynamic_origin_pattern_contract() {
    let mut observations = Vec::new();
    for (target, pattern, expected) in [
        (
            "https://b.example.test:443/cb?q=1#fragment",
            "https://*.example.test",
            true,
        ),
        (
            "https://user:pass@b.example.test/cb",
            "https://*.example.test",
            true,
        ),
        (
            "https://b.example.test:444/cb",
            "https://*.example.test",
            false,
        ),
        (
            "https://b.example.test.evil.test/cb",
            "https://*.example.test",
            false,
        ),
        (
            "myapp://CLIENT/cb/sub?q=1#fragment",
            "myapp://client/cb",
            true,
        ),
        ("myapp://client/cb/%2e%2e/evil", "myapp://client/cb", false),
        ("myapp://client:123/cb", "myapp://client/cb", false),
        ("myapp://user@client/cb", "myapp://client/cb", false),
        ("myapp://client/cb?q=1", "myapp://client/cb", true),
        ("myapp://client/cb?q=1", "myapp://*", false),
    ] {
        let cfg = AuthConfig::new(SECRET)
            .base_url("https://unrelated.test")
            .trusted_origins(vec![pattern.into()]);
        let result = cfg.is_redirect_target_trusted(target);
        assert_eq!(result, expected, "{target} against {pattern}");
        observations.push(json!({"url":target,"pattern":pattern,"result":result}));
    }
    println!(
        "native-patterns={}",
        serde_json::to_string(&observations).unwrap()
    );
}
