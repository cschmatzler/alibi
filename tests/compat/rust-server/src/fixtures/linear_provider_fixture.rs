//! Actual Linear GraphQL factory and observed trusted endpoint exchanges.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{LinearOptions, OAuthProvider, OAuthUserInfo};
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
    ] {
        let path = format!("/__test/profiles/social-linear-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = LinearOptions::new(
            if mode == "empty-clients" {
                ""
            } else {
                "fixture-social-client"
            },
            (mode != "public").then(|| "fixture-social-secret".into()),
        );
        options.user_info_endpoint = Some(format!("{}/__test/linear/userinfo", config.base_url));
        if ["configured", "disabled-configured"].contains(&mode) {
            options.scope = ["configured-scope", "read", "punctuation !~*'()"]
                .map(String::from)
                .to_vec();
        }
        options.disable_default_scope = ["disabled-scope", "disabled-configured"].contains(&mode);
        if mode == "configured-endpoint" {
            options.authorization_endpoint=Some("https://alternate-linear.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value".into());
            options.redirect_uri = Some("https://client.example.invalid/linear-return".into());
        }
        if mode == "mapped" {
            options.map_profile_to_user = Some(|profile| {
                MAPPER_RECEIPTS
                    .lock()
                    .expect("mapper receipt lock")
                    .push(profile.clone());
                Ok(OAuthUserInfo {
                    additional_fields: [("linearPublic".into(), json!({"source":profile.get("id").cloned().unwrap_or(Value::Null),"scopes":["read"]}))].into_iter().collect(),
                    id: "cannot-replace-raw-account".into(),
                    name: Some("Mapped Linear User".into()),
                    email: "mapped-linear@example.invalid".into(),
                    email_verified: true,
                    image: Some("https://images.example.invalid/mapped-linear.png".into()),
                })
            });
        }
        if mode == "client-key" {
            options.client_key = Some("fixture-linear-client-key".into());
        }
        let mut provider = OAuthProvider::linear_with_options(options);
        provider.token_url = format!("{}/__test/linear/token", config.base_url);
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
                .plugin(OAuthPlugin::new().add_provider("linear", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/linear/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/linear/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/linear/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/__test/linear/token", post(token))
        .route("/__test/linear/userinfo", post(profile))
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
    fixture.receipts.lock().await.push(receipt(
        "/userinfo",
        "POST",
        &headers,
        serde_json::from_str(&body).expect("actual GraphQL request body"),
    ));
    let control = fixture.control.lock().await;
    let first = control.get("profile").cloned().unwrap_or_else(||json!({"id":"fixture-linear-subject","name":"Linear User","email":"linear@example.invalid","avatarUrl":"https://images.example.invalid/linear.png","active":true,"createdAt":"2020-01-01T00:00:00.000Z","updatedAt":"2020-01-02T00:00:00.000Z"}));
    let response = control
        .get("envelope")
        .cloned()
        .unwrap_or_else(|| json!({"data":{"viewer":first}}));
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
    (status(&control,"tokenStatus"),Json(control.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"fixture-linear-access","refresh_token":"fixture-linear-refresh","scope":"read","expires_in":3600}))))
}
