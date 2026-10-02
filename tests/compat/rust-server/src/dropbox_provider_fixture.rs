//! Real Dropbox profiles and observed trusted endpoint exchanges.
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
use better_auth::plugins::oauth::{
    DropboxAccessType, DropboxOptions, OAuthProvider, OAuthUserInfo,
};
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
static MAPPER_RECEIPTS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
#[derive(Clone, Default)]
pub(super) struct Fixture {
    control: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(super) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts.lock().await.clear();
        MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clear();
    }
}
pub(super) async fn router(
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
        "offline",
        "online",
        "legacy",
        "mapped",
        "implicit-disabled",
        "signup-disabled",
        "configured-endpoint",
        "empty-clients",
        "client-key",
    ] {
        let path = format!("/__test/profiles/social-dropbox-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = DropboxOptions::new(
            if mode == "empty-clients" {
                ""
            } else {
                "fixture-social-client"
            },
            (mode != "public").then(|| "fixture-social-secret".into()),
        );
        options.user_info_endpoint = Some(format!("{}/__test/dropbox/userinfo", config.base_url));
        if ["configured", "disabled-configured"].contains(&mode) {
            options.scope = [
                "files.metadata.read",
                "account_info.read",
                "punctuation !~*'()",
            ]
            .map(String::from)
            .to_vec();
        }
        options.disable_default_scope = ["disabled-scope", "disabled-configured"].contains(&mode);
        options.access_type = match mode {
            "offline" => Some(DropboxAccessType::Offline),
            "online" => Some(DropboxAccessType::Online),
            "legacy" => Some(DropboxAccessType::Legacy),
            _ => None,
        };
        if mode == "configured-endpoint" {
            options.authorization_endpoint=Some("https://alternate-dropbox.example.invalid/authorize?state=stale&state=duplicate&client_id=stale&retained=value".into());
            options.redirect_uri = Some("https://client.example.invalid/dropbox-return".into());
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
                    name: Some("Mapped Dropbox User".into()),
                    email: "mapped-dropbox@example.invalid".into(),
                    email_verified: false,
                    image: Some("https://images.example.invalid/mapped-dropbox.png".into()),
                })
            });
        }
        if mode == "client-key" {
            options.client_key = Some("fixture-dropbox-client-key".into());
        }
        let mut provider = OAuthProvider::dropbox_with_options(options);
        provider.token_url = format!("{}/__test/dropbox/token", config.base_url);
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        provider.disable_sign_up = mode == "signup-disabled";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("dropbox", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/dropbox/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/dropbox/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/dropbox/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/__test/dropbox/token", post(token))
        .route("/__test/dropbox/userinfo", post(profile))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
fn receipt(path: &str, headers: &HeaderMap, body: Value) -> Value {
    json!({"path":path,"method":"POST","authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"body":body})
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
        .push(receipt("/userinfo", &headers, json!(body)));
    let control = fixture.control.lock().await;
    (status(&control,"userInfoStatus"),Json(control.get("profile").cloned().unwrap_or_else(||json!({"account_id":"fixture-dropbox-subject","name":{"display_name":"Dropbox User","given_name":"Dropbox","surname":"User"},"email":"dropbox@example.invalid","email_verified":true,"profile_photo_url":"https://images.example.invalid/dropbox.png"}))))
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
        .push(receipt("/token", &headers, json!(fields)));
    let control = fixture.control.lock().await;
    (status(&control,"tokenStatus"),Json(control.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"fixture-dropbox-access","refresh_token":"fixture-dropbox-refresh","scope":"account_info.read","expires_in":3600}))))
}
