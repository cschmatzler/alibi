//! Managed keyring lifecycle through real handlers, with independent physical SQL checks.
use super::postgres_tests;
use super::{Backend, Db, TestResult, backend_tests};
use base64::Engine as _;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use better_auth::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use better_auth_core::endpoint::EndpointOptions;
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};
use chrono::Duration;
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "native-jwk-172-secret-at-least-32-characters";
const ORIGIN: &str = "http://localhost:43177";
backend_tests!(native_jwk_workflow);
postgres_tests!(native_jwk_workflow);

fn plugins<S: AuthSchema>(builder: AuthBuilder<S>, grace: i64) -> AuthBuilder<S> {
    builder
        .rate_limit(better_auth::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(JwtPlugin::with_config(JwtPluginConfig {
            rotation_interval: Some(Duration::seconds(2)),
            grace_period: Duration::seconds(grace),
            disable_setting_jwt_header: true,
            ..Default::default()
        }))
}
fn config() -> AuthConfig {
    AuthConfig::new(SECRET).base_url(ORIGIN)
}
fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}
async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    trace: &mut Vec<Value>,
    path: &str,
    input: Option<Value>,
    cookie: &str,
) -> TestResult<AuthResponse> {
    let mut req = AuthRequest::new(
        if input.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(req.headers.insert("cookie".into(), cookie.into()));
    req.body = input.map(|v| serde_json::to_vec(&v).unwrap());
    let response = Box::pin(auth.handle_request(req)).await?;
    trace.push(json!({"path":path,"status":response.status,"body":String::from_utf8(response.body.clone())?}));
    Ok(response)
}
fn token_key(token: &str) -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').next().unwrap())
        .unwrap();
    serde_json::from_slice::<Value>(&header).unwrap()["kid"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn verified<S: AuthSchema>(auth: &BetterAuth<S>, token: &str) -> TestResult<bool> {
    Ok(auth
        .dispatch_endpoint(
            JwtPlugin::verify_endpoint(token, None),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .payload
        .is_some())
}
async fn native_jwk_workflow<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = config();
    config.session = config.session.stateless();
    let auth = plugins(
        AuthBuilder::new(config.clone()).store(B::store(Arc::new(config.clone()), &connection)),
        60,
    )
    .build()
    .await?;
    let token = workflow(
        &auth,
        std::any::type_name::<B>().rsplit("::").next().unwrap(),
    )
    .await?;
    assert_eq!(db.count("jwks").await?, 2);
    assert_eq!(db.count("sessions").await?, 0);
    let stored = db
        .text("SELECT private_key FROM jwks LIMIT 1", &[])
        .await?
        .unwrap();
    assert!(serde_json::from_str::<String>(&stored).is_ok());
    let restarted = plugins(
        AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)),
        60,
    )
    .build()
    .await?;
    assert!(verified(&restarted, &token).await?);
    B::close(connection).await
}
#[tokio::test]
async fn without_database_native_jwk_workflow() -> TestResult {
    let auth = plugins(AuthBuilder::without_database(config()), 60)
        .build()
        .await?;
    let token = workflow(&auth, "without-database").await?;
    let restarted = plugins(AuthBuilder::without_database(config()), 60)
        .build()
        .await?;
    assert!(restarted.store().list_jwks().await?.is_empty());
    assert!(!verified(&restarted, &token).await?);
    assert_eq!(auth.store().list_jwks().await?.len(), 2);
    let mut trace = Vec::new();
    let jwks = call(&restarted, &mut trace, "/jwks", None, "").await?;
    assert_eq!(jwks.status, 200);
    assert!(!verified(&restarted, &token).await?);
    assert_eq!(restarted.store().list_jwks().await?.len(), 1);
    save(
        "native-restart.json",
        &json!({"trace":trace,"oldRetained":2,"freshKeys":1,"oldTokenValid":false}),
    )?;
    Ok(())
}
fn save(name: &str, value: &Value) -> TestResult {
    if let Ok(dir) = std::env::var("JWK_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join(name),
            serde_json::to_vec_pretty(value)?,
        )?;
    }
    Ok(())
}
async fn workflow<S: AuthSchema>(auth: &BetterAuth<S>, backend: &str) -> TestResult<String> {
    let mut trace = Vec::new();
    let first = call(auth, &mut trace, "/jwks", None, "").await?;
    assert_eq!(
        first.status,
        200,
        "native JWKS provisioning: {}",
        body(&first)
    );
    let keys = body(&first);
    let id = keys["keys"][0]["kid"].as_str().unwrap();
    let row = auth.store().get_jwk_by_id(id).await?.unwrap();
    assert_eq!(row.alg.as_deref(), Some("EdDSA"));
    assert_eq!(row.crv.as_deref(), Some("Ed25519"));
    assert!(row.expires_at.is_some());
    assert!(serde_json::from_str::<String>(&row.private_key).is_ok());
    assert!(keys["keys"][0].get("d").is_none());
    assert!(keys["keys"][0].get("privateKey").is_none());
    assert!(auth.store().get_jwk_by_id("absent").await?.is_none());
    let denied = call(auth, &mut trace, "/token", None, "").await?;
    assert_eq!(denied.status, 401);
    assert_eq!(auth.store().list_jwks().await?.len(), 1);
    let signup = call(
        auth,
        &mut trace,
        "/sign-up/email",
        Some(json!({"email":"jwk172@example.com","name":"owner","password":"Password123!"})),
        "",
    )
    .await?;
    assert_eq!(signup.status, 200);
    let cookie = signup
        .headers
        .get_all("set-cookie")
        .map(|v| v.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let issued = call(auth, &mut trace, "/token", None, &cookie).await?;
    assert_eq!(issued.status, 200);
    let token = body(&issued)["token"].as_str().unwrap().to_owned();
    assert!(verified(auth, &token).await?);
    assert_eq!(token_key(&token), id);
    assert_eq!(auth.store().list_jwks().await?.len(), 1);
    let reused = call(auth, &mut trace, "/token", None, &cookie).await?;
    assert_eq!(reused.status, 200);
    assert_eq!(token_key(body(&reused)["token"].as_str().unwrap()), id);
    assert_eq!(auth.store().list_jwks().await?.len(), 1);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let rotated = call(auth, &mut trace, "/token", None, &cookie).await?;
    assert_eq!(rotated.status, 200);
    let rotated_token = body(&rotated)["token"].as_str().unwrap().to_owned();
    assert_ne!(token_key(&rotated_token), id);
    assert!(verified(auth, &rotated_token).await?);
    assert_eq!(auth.store().list_jwks().await?.len(), 2);
    let grace = call(auth, &mut trace, "/jwks", None, "").await?;
    assert_eq!(body(&grace)["keys"].as_array().unwrap().len(), 2);
    assert!(verified(auth, &token).await?);
    // Public retirement is a handler filter, not physical deletion or verifyJWT retirement.
    let retired = plugins(
        AuthBuilder::new(config()).store_arc(auth.store().clone()),
        0,
    )
    .build()
    .await?;
    let public = call(&retired, &mut trace, "/jwks", None, "").await?;
    assert!(
        !body(&public)["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["kid"] == id)
    );
    assert!(verified(&retired, &token).await?);
    assert!(retired.store().get_jwk_by_id(id).await?.is_some());
    let mut wrong_config = config();
    wrong_config.secret = "different-native-jwk-secret-at-least-32-characters".into();
    let wrong = plugins(
        AuthBuilder::new(wrong_config).store_arc(auth.store().clone()),
        60,
    )
    .build()
    .await?;
    assert!(
        wrong
            .dispatch_endpoint(
                JwtPlugin::sign_endpoint(json!({"sub":"owner"}).into()),
                EndpointOptions::default()
            )
            .await
            .is_err()
    );
    assert_eq!(wrong.store().list_jwks().await?.len(), 2);
    assert!(verified(&wrong, &token).await?);
    save(
        &format!("native-{backend}.json"),
        &json!({"trace":trace,"effects":{"generated":1,"reused":1,"rotated":2,"retiredRowRetained":true,"retiredTokenVerified":true,"wrongSecretSignRejected":true}}),
    )?;
    Ok(token)
}
