//! Request-local linking authority through real callbacks and both physical stores.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "endpoint regression setup and independent storage receipts fail fast"
)]
use crate::storage::{Backend, Db, TestResult, backend_tests};
use async_trait::async_trait;
use better_auth::config::{BaseUrlProtocol, DynamicBaseUrl};
use better_auth::plugins::{OAuthPlugin, oauth::OAuthProvider};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, CreateAccount, CreateUser, HttpMethod, SessionManager,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
const SECRET: &str = "request-provider-fixture-secret-at-least-32";
backend_tests!(dynamic_provider_callbacks);

fn req(method: HttpMethod, path: &str, host: &str, trust: &str, body: Value) -> AuthRequest {
    let mut r = AuthRequest::new(method, format!("/api/auth{path}"));
    r.headers.extend([
        ("host".into(), host.into()),
        ("origin".into(), format!("https://{host}")),
        ("x-trust".into(), trust.into()),
        ("content-type".into(), "application/json".into()),
    ]);
    r.body = Some(body.to_string().into_bytes());
    r.with_url(url::Url::parse(&format!("https://{host}/api/auth{path}")).unwrap())
}
async fn issuer() -> (String, tokio::task::JoinHandle<()>, Arc<Mutex<Vec<Value>>>) {
    use axum::{
        Form, Json, Router,
        http::HeaderMap,
        routing::{get, post},
    };
    let receipts = Arc::new(Mutex::new(vec![]));
    let tokens = receipts.clone();
    let profiles = receipts.clone();
    let app = Router::new().route("/oauth/token", post(move |Form(form): Form<std::collections::HashMap<String,String>>| {
        let receipts = tokens.clone(); async move {
            receipts.lock().unwrap().push(json!({"tokenForm":form}));
            Json(json!({"access_token":form["code"],"token_type":"Bearer","scope":"read_user"}))
        }
    })).route("/api/v4/user", get(move |headers: HeaderMap| { let receipts = profiles.clone(); async move {
        let code = headers.get("authorization").unwrap().to_str().unwrap().strip_prefix("Bearer ").unwrap();
        let profile = json!({"id":code,"email":format!("{code}@example.test"),"name":code,"state":"active","locked":false,"email_verified":false});
        receipts.lock().unwrap().push(json!({"profile":profile})); Json(profile)
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, receipts)
}
async fn start<S: AuthSchema>(
    auth: &BetterAuth<S>,
    code: &str,
    trust: &str,
    cookie: Option<&str>,
) -> (String, String, Value) {
    let path = if cookie.is_some() {
        "/link-social"
    } else {
        "/sign-in/social"
    };
    let mut r = req(
        HttpMethod::Post,
        path,
        "a.example.test",
        trust,
        json!({"provider":"gitlab","callbackURL":"https://a.example.test/done","errorCallbackURL":"https://a.example.test/failed","disableRedirect":true}),
    );
    if let Some(cookie) = cookie {
        _ = r.headers.insert("cookie".into(), cookie.into());
    }
    let response = auth.handle_request(r).await.unwrap();
    assert_eq!(
        response.status,
        200,
        "{code}: {:?}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let u = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert!(u.path().ends_with("/oauth/authorize"));
    let params: std::collections::HashMap<String, String> = u.query_pairs().into_owned().collect();
    assert_eq!(params["scope"], "read_user");
    assert_eq!(params["client_id"], "fixture-client");
    assert_eq!(
        params["redirect_uri"],
        "https://a.example.test/api/auth/callback/gitlab"
    );
    let cookies = response
        .headers
        .get_all("set-cookie")
        .map(|v| v.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    (params["state"].clone(), cookies, body)
}
fn callback(code: &str, host: &str, trust: &str, state: &str, cookies: &str) -> AuthRequest {
    let mut r = req(
        HttpMethod::Get,
        "/callback/gitlab",
        host,
        trust,
        Value::Null,
    );
    r.query
        .extend([("state".into(), state.into()), ("code".into(), code.into())]);
    _ = r.headers.insert("cookie".into(), cookies.into());
    r
}
async fn dynamic_provider_callbacks<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut cfg = AuthConfig::new(SECRET).dynamic_base_url(DynamicBaseUrl {
        allowed_hosts: vec!["*.example.test".into()],
        protocol: Some(BaseUrlProtocol::Https), fallback: None,
    });
    // Original public API supports only one globally configured trust list.
    cfg.account.account_linking.trusted_providers = vec!["gitlab".into()];
    let (issuer, server, _) = issuer().await;
    let auth = AuthBuilder::<B::Schema>::new(cfg.clone())
        .store(B::store(Arc::new(cfg), &connection))
        .rate_limit(better_auth::middleware::RateLimitConfig { enabled: false, ..Default::default() })
        .plugin(OAuthPlugin::new().add_provider("gitlab",
            OAuthProvider::gitlab_with_issuer("fixture-client", "fixture-secret", &issuer)))
        .build().await?;
    _ = auth.store().create_user(CreateUser::new().with_email("deny@example.test")
        .with_name("deny").with_email_verified(true)).await?;
    let (state, cookies, _) = start(&auth, "deny", "allow", None).await;
    let response = auth.handle_request(callback("deny", "a.example.test", "deny", &state, &cookies)).await?;
    println!("ORIGINAL MAIN BEFORE: location={:?}, accounts={}, sessions={}",
        response.headers.get("location"), db.count("accounts").await?, db.count("sessions").await?);
    server.abort();
    assert_eq!(response.headers.get("location").unwrap(),
        "https://a.example.test/failed?error=account_not_linked",
        "request-dependent denial must prevent unverified-provider linking; original static trust cannot express it");
    B::close(connection).await?; Ok(())
}
