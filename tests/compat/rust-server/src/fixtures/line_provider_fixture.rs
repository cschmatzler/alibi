//! Real LINE factory and independently verified remote direct-proof exchanges.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{LineOptions, OAuthProvider, OAuthUserInfo};
use alibi::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi::seaorm::DatabaseConnection;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
static MAPPER_RECEIPTS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
#[derive(Clone, Default)]
pub(crate) struct Fixture {
    control: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(crate) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts.lock().await.clear();
        MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clear();
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let fixture = Fixture::default();
    let mut router = Router::new();
    for mode in [
        "default",
        "public",
        "configured",
        "disabled-scope",
        "disabled-configured",
        "mapped",
        "implicit-disabled",
        "signup-disabled",
        "configured-endpoint",
        "empty-clients",
        "client-key",
        "disabled-idtoken",
    ] {
        let path = format!("/__test/profiles/social-line-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = LineOptions::new(
            if mode == "empty-clients" {
                ""
            } else {
                "fixture-social-client"
            },
            (mode != "public").then(|| "fixture-social-secret".into()),
        );
        options.verification_endpoint = Some(format!("{}/__test/line/verify", config.base_url));
        options.user_info_endpoint = Some(format!("{}/__test/line/userinfo", config.base_url));
        if ["configured", "disabled-configured"].contains(&mode) {
            options.scope = ["configured-scope", "openid", "punctuation !~*'()"]
                .map(String::from)
                .to_vec();
        }
        options.disable_default_scope = ["disabled-scope", "disabled-configured"].contains(&mode);
        if mode == "configured-endpoint" {
            options.authorization_endpoint=Some("https://alternate-line.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value".into());
            options.redirect_uri = Some("https://client.example.invalid/line-return".into());
        }
        if mode == "mapped" {
            options.map_profile_to_user = Some(|profile| {
                MAPPER_RECEIPTS
                    .lock()
                    .expect("mapper receipt lock")
                    .push(profile);
                Ok(OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: "cannot-replace-raw-account".into(),
                    name: Some("Mapped Line User".into()),
                    email: "mapped-line@example.invalid".into(),
                    email_verified: true,
                    image: Some("https://images.example.invalid/mapped-line.png".into()),
                })
            });
        }
        if mode == "client-key" {
            options.client_key = Some("fixture-line-client-key".into());
        }
        let mut provider = OAuthProvider::line_with_options(options);
        provider.token_url = format!("{}/__test/line/token", config.base_url);
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        provider.disable_id_token_sign_in = mode == "disabled-idtoken";
        provider.disable_sign_up = mode == "signup-disabled";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(
                    settings,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("line", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/line/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/line/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/line/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/__test/line/token", post(token))
        .route("/__test/line/userinfo", get(profile))
        .route("/__test/line/verify", post(verify))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
fn receipt(path: &str, method: &str, headers: &HeaderMap, body: Value) -> Value {
    json!({"path":path,"method":method,"authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"body":body})
}
fn status(control: &Value, key: &str) -> StatusCode {
    control
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .unwrap_or(StatusCode::OK)
}
async fn profile(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/userinfo", "GET", &headers, json!(body)));
    let control = fixture.control.lock().await;
    let first = control.get("profile").cloned().unwrap_or_else(||json!({"sub":"fixture-line-subject","name":"Line User","email":"line@example.invalid","picture":"https://images.example.invalid/line.png"}));
    let response = first;
    (status(&control, "userInfoStatus"), Json(response))
}
async fn token(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/token", "POST", &headers, json!(fields)));
    let control = fixture.control.lock().await;
    (status(&control,"tokenStatus"),Json(control.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"fixture-line-access","refresh_token":"fixture-line-refresh","scope":"openid profile email","expires_in":3600,"id_token":control.get("idToken")}))))
}

async fn verify(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/verify", "POST", &headers, json!(fields)));
    let control = fixture.control.lock().await;
    let remote_status = status(&control, "verifyStatus");
    if remote_status != StatusCode::OK {
        return (
            remote_status,
            Json(json!({"error":"remote verification unavailable"})),
        );
    }
    let claims = fields
        .get("id_token")
        .and_then(|token| verify_remote_proof(token, &fields));
    match claims {
        Some(claims) => (
            StatusCode::OK,
            Json(control.get("verifyResponse").cloned().unwrap_or(claims)),
        ),
        None => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid remote proof"})),
        ),
    }
}
fn verify_remote_proof(
    token: &str,
    fields: &std::collections::BTreeMap<String, String>,
) -> Option<Value> {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    let segments: Vec<_> = token.split('.').collect();
    let [header, payload, signature] = segments.as_slice() else {
        return None;
    };
    let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parsed_header: Value = serde_json::from_slice(&decoder.decode(header).ok()?).ok()?;
    if parsed_header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return None;
    }
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(b"fixture-line-independent-hmac-key-32").ok()?;
    mac.update(format!("{header}.{payload}").as_bytes());
    mac.verify_slice(&decoder.decode(signature).ok()?).ok()?;
    let claims: Value = serde_json::from_slice(&decoder.decode(payload).ok()?).ok()?;
    if claims.get("iss").and_then(Value::as_str) != Some("https://access.line.me") {
        return None;
    }
    let client_id = fields.get("client_id")?;
    let admitted = match claims.get("aud") {
        Some(Value::String(audience)) => audience == client_id,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(client_id.as_str())),
        _ => false,
    };
    if !admitted {
        return None;
    }
    let now = chrono::Utc::now().timestamp() as f64;
    if claims
        .get("exp")
        .and_then(Value::as_f64)
        .is_none_or(|expires| expires <= now)
    {
        return None;
    }
    if let Some(nonce) = fields.get("nonce").filter(|nonce| !nonce.is_empty()) {
        if claims.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
            return None;
        }
    }
    Some(claims)
}
