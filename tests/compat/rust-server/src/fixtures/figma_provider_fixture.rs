//! Real Figma profiles and observed trusted endpoint exchanges.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{FigmaOptions, OAuthProvider, OAuthUserInfo};
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
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
    ] {
        let path = format!("/__test/profiles/social-figma-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = FigmaOptions::new(
            if mode == "empty-clients" {
                ""
            } else {
                "fixture-social-client"
            },
            (mode != "public").then(|| "fixture-social-secret".into()),
        );
        options.user_info_endpoint = Some(format!("{}/__test/figma/userinfo", config.base_url));
        if ["configured", "disabled-configured"].contains(&mode) {
            options.scope = [
                "file_content:read",
                "current_user:read",
                "punctuation !~*'()",
            ]
            .map(String::from)
            .to_vec();
        }
        options.disable_default_scope = ["disabled-scope", "disabled-configured"].contains(&mode);
        if mode == "configured-endpoint" {
            options.authorization_endpoint=Some("https://alternate-figma.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value".into());
            options.redirect_uri = Some("https://client.example.invalid/figma-return".into());
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
                    name: Some("Mapped Figma User".into()),
                    email: "mapped-figma@example.invalid".into(),
                    email_verified: true,
                    image: Some("https://images.example.invalid/mapped-figma.png".into()),
                })
            });
        }
        if mode == "client-key" {
            options.client_key = Some("fixture-figma-client-key".into());
        }
        let mut provider = OAuthProvider::figma_with_options(options);
        provider.token_url = format!("{}/__test/figma/token", config.base_url);
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        provider.disable_sign_up = mode == "signup-disabled";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("figma", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/figma/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/figma/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/figma/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/__test/figma/token", post(token))
        .route("/__test/figma/userinfo", get(profile))
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
    (status(&control,"userInfoStatus"),Json(control.get("profile").cloned().unwrap_or_else(||json!({"id":"fixture-figma-subject","handle":"Figma User","email":"figma@example.invalid","email_verified":true,"img_url":"https://images.example.invalid/figma.png"}))))
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
    (status(&control,"tokenStatus"),Json(control.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"fixture-figma-access","refresh_token":"fixture-figma-refresh","scope":"current_user:read","expires_in":3600}))))
}
