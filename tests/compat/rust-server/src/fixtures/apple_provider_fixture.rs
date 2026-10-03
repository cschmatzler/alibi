//! Actual Apple factory with trusted local HTTP and observed provider receipts.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{AppleOptions, HttpOAuthJwksSource, OAuthProvider};
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::DatabaseConnection;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
#[derive(Clone, Default)]
pub(crate) struct Fixture {
    control: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(crate) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts.lock().await.clear();
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
        "configured",
        "disabled-scope",
        "disabled-configured",
        "bundle",
        "audience",
        "client-array",
        "disabled-idtoken",
        "signup-disabled",
        "implicit-disabled",
        "encrypted",
        "mapped",
        "empty-clients",
    ] {
        let path = format!("/__test/profiles/social-apple-{mode}/api/auth");
        let mut settings = config.clone().base_path(&path);
        settings.account.encrypt_oauth_tokens = mode == "encrypted";
        let mut options = AppleOptions::new("fixture-social-client", "fixture-social-secret");
        options.jwks_source = Some(Arc::new(HttpOAuthJwksSource::new(format!(
            "{}/__test/apple/keys",
            config.base_url
        ))));
        if mode == "client-array" {
            options.client_ids.push("fixture-apple-secondary".into());
        }
        if mode == "configured" || mode == "disabled-configured" {
            options.scope.push("configured-scope".into());
        }
        options.disable_default_scope = mode.starts_with("disabled-") && mode != "disabled-idtoken";
        options.disable_id_token_sign_in = mode == "disabled-idtoken";
        if mode == "bundle" {
            options.app_bundle_identifier = Some("fixture-apple-bundle".into());
        }
        if mode == "audience" {
            options.audience = Some(vec!["fixture-apple-audience".into()]);
            options.app_bundle_identifier = Some("ignored-bundle".into());
        }
        if mode == "mapped" {
            options.map_profile_to_user = Some(|profile| {
                Ok(better_auth::plugins::oauth::OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: "cannot-replace-source-subject".into(),
                    name: Some(format!(
                        "Mapped {}",
                        profile
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                    )),
                    email: "mapped-apple@example.invalid".into(),
                    email_verified: false,
                    image: Some("https://images.example.invalid/mapped-apple.png".into()),
                })
            });
        }
        if mode == "empty-clients" {
            options.client_ids.clear();
        }
        let mut provider = OAuthProvider::apple_with_options(options);
        if mode == "bundle" || mode == "audience" {
            provider = provider.with_client_ids(vec!["fixture-builder-client".into()]);
        }
        provider.token_url = format!("{}/__test/apple/token", config.base_url);
        provider.disable_sign_up = mode == "signup-disabled";
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(
                    settings,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("apple", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/apple/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/apple/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route("/__test/apple/keys", get(keys))
        .route("/__test/apple/token", post(token))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
async fn keys(State(fixture): State<Fixture>, headers: HeaderMap) -> Json<Value> {
    fixture.receipts.lock().await.push(json!({"path":"/keys", "method":"GET", "authorization":headers.get("authorization").and_then(|value| value.to_str().ok()), "contentType":headers.get("content-type").and_then(|value| value.to_str().ok()),"body":null}));
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
async fn token(State(fixture): State<Fixture>, headers: HeaderMap, body: String) -> Json<Value> {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture.receipts.lock().await.push(json!({"path":"/token", "method":"POST", "authorization":headers.get("authorization").and_then(|value| value.to_str().ok()), "contentType":headers.get("content-type").and_then(|value| value.to_str().ok()),"body":fields}));
    let control = fixture.control.lock().await;
    Json(control.get("tokenResponse").cloned().unwrap_or_else(|| json!({"access_token":"fixture-apple-access","refresh_token":"fixture-apple-refresh","id_token":control.get("idToken"),"token_type":"Bearer","expires_in":3600})))
}
