//! Actual Facebook app inspection, Graph profiles and signed Limited Login.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{FacebookOptions, HttpOAuthJwksSource, OAuthProvider, OAuthUserInfo};
use alibi::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::DatabaseConnection;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
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
    let mut modes: Vec<String> = [
        "default",
        "configured",
        "disabled-scope",
        "disabled-configured",
        "mapped",
        "client-array",
        "missing-secret",
        "empty-clients",
        "configured-endpoint",
        "client-key",
        "disabled-idtoken",
        "implicit-disabled",
        "signup-disabled",
        "fields",
    ]
    .map(String::from)
    .to_vec();
    modes.extend(
        [
            "no-iat",
            "old",
            "future",
            "raw-positive-iat",
            "raw-negative-iat",
            "issuer",
            "audience",
            "expired",
            "not-before",
            "iat-type",
            "nonce",
            "hashed-nonce",
            "signature",
            "unknown-kid",
            "missing-subject",
            "null-subject",
            "blank-subject",
            "missing-email",
            "null-email",
            "empty-email",
            "numeric-name",
            "null-name",
            "empty-image",
        ]
        .map(|name| format!("jwt-{name}")),
    );
    modes.extend(
        [
            "removed",
            "algorithm",
            "use",
            "operations",
            "private",
            "duplicate",
            "invalid-ext",
            "duplicate-import",
            "weak-modulus",
        ]
        .map(|name| format!("keys-{name}")),
    );
    for mode in modes {
        let path = format!("/__test/profiles/social-facebook-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = FacebookOptions::new(
            "fixture-social-client",
            (mode != "missing-secret").then(|| "fixture-social-secret".into()),
        );
        options.token_inspection_endpoint =
            Some(format!("{}/__test/facebook/debug", config.base_url));
        options.user_info_endpoint = Some(format!("{}/__test/facebook/userinfo", config.base_url));
        options.jwks_source = Some(Arc::new(HttpOAuthJwksSource::new(format!(
            "{}/__test/facebook/keys",
            config.base_url
        ))));
        if mode == "empty-clients" {
            options.client_ids.clear();
        }
        if mode == "client-array" {
            options.client_ids.push("fixture-facebook-secondary".into());
        }
        if ["configured", "disabled-configured"].contains(&mode.as_str()) {
            options.scope = ["configured-scope", "email", "punctuation !~*'()"]
                .map(String::from)
                .to_vec();
            options.config_id = Some("ConfiguredFacebook".into());
        }
        options.disable_default_scope =
            ["disabled-scope", "disabled-configured"].contains(&mode.as_str());
        if mode == "fields" {
            options.fields = ["email", "birthday", "locale"].map(String::from).to_vec();
        }
        if mode == "configured-endpoint" {
            options.authorization_endpoint = Some("https://alternate-facebook.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value".into());
            options.redirect_uri = Some("https://client.example.invalid/facebook-return".into());
        }
        if mode == "client-key" {
            options.client_key = Some("fixture-facebook-client-key".into());
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
                    name: Some("Mapped Facebook User".into()),
                    email: "mapped-facebook@example.invalid".into(),
                    email_verified: false,
                    image: Some("https://images.example.invalid/mapped-facebook.png".into()),
                })
            });
        }
        let mut provider = OAuthProvider::facebook_with_options(options);
        provider.token_url = format!("{}/__test/facebook/token", config.base_url);
        provider.disable_id_token_sign_in = mode == "disabled-idtoken";
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
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
                .plugin(OAuthPlugin::new().add_provider("facebook", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/facebook/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/facebook/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/facebook/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/__test/facebook/token", post(token))
        .route("/__test/facebook/keys", get(keys))
        .route("/__test/facebook/debug", get(inspect))
        .route("/__test/facebook/userinfo", get(profile))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
fn receipt(
    path: &str,
    method: &str,
    headers: &HeaderMap,
    query: BTreeMap<String, String>,
    body: Option<Value>,
) -> Value {
    json!({"path":path,"method":method,"authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"query":query,"body":body})
}
fn status(control: &Value, key: &str) -> StatusCode {
    control
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .unwrap_or(StatusCode::OK)
}
async fn keys(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Json<Value> {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/keys", "GET", &headers, query, None));
    Json(
        fixture
            .control
            .lock()
            .await
            .get("keys")
            .cloned()
            .unwrap_or_else(|| {
                serde_json::from_str(include_str!("../../../../fixtures/one-tap/jwks.json"))
                    .expect("valid trusted JWKS")
            }),
    )
}
async fn inspect(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/debug", "GET", &headers, query, None));
    let control = fixture.control.lock().await;
    (status(&control, "inspectionStatus"), Json(control.get("inspection").cloned().unwrap_or_else(||json!({"data":{"is_valid":true,"app_id":"fixture-social-client","user_id":control.get("profile").and_then(|value|value.get("id")).filter(|value|!value.is_null()).cloned().unwrap_or_else(||json!("fixture-facebook-subject"))}}))))
}
async fn profile(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/userinfo", "GET", &headers, query, None));
    let control = fixture.control.lock().await;
    (status(&control, "userInfoStatus"), Json(control.get("profile").cloned().unwrap_or_else(||json!({"id":"fixture-facebook-subject","name":"Facebook User","email":"facebook@example.invalid","email_verified":true,"picture":{"data":{"url":"https://images.example.invalid/facebook.png","height":50,"width":50,"is_silhouette":false}}}))))
}
async fn token(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let fields: BTreeMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    fixture.receipts.lock().await.push(receipt(
        "/token",
        "POST",
        &headers,
        BTreeMap::new(),
        Some(json!(fields)),
    ));
    let control = fixture.control.lock().await;
    (status(&control, "tokenStatus"), Json(control.get("tokenResponse").cloned().unwrap_or_else(|| {
        let mut value = json!({"access_token":"fixture-facebook-access","refresh_token":"fixture-facebook-refresh","token_type":"Bearer","expires_in":3600});
        if let Some(token) = control.get("idToken").filter(|value|!value.is_null()) { value["id_token"] = token.clone(); }
        value
    })))
}
