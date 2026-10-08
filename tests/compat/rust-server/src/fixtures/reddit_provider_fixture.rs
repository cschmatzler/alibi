//! Actual Reddit factory with trusted local HTTP and observed provider receipts.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{OAuthProvider, RedditOptions};
use alibi::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::DatabaseConnection;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
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
        MAPPER_RECEIPTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
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
        "public",
        "encoded",
        "mapped",
        "implicit-disabled",
        "signup-disabled",
        "required",
        "configured-endpoint",
        "prompt",
        "empty-endpoint",
        "client-key",
        "permanent",
        "empty-duration",
        "mapped-empty-email",
    ] {
        let path = format!("/__test/profiles/social-reddit-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let (client_id, secret) = if mode == "encoded" {
            ("client :+!*'()", "secret :+!*'()")
        } else {
            ("fixture-social-client", "fixture-social-secret")
        };
        let mut options =
            RedditOptions::new(client_id, (mode != "public").then(|| secret.to_owned()));
        options.user_info_endpoint = Some(format!("{}/__test/reddit/user", config.base_url));
        if mode == "configured" || mode == "disabled-configured" {
            options.scope = vec![
                "configured-scope".into(),
                "shared-scope".into(),
                "configured-scope".into(),
            ];
        }
        if mode == "empty-endpoint" {
            options.authorization_endpoint = Some(String::new());
            options.redirect_uri = Some(String::new());
        }
        if mode == "permanent" {
            options.duration = Some("permanent".into());
        }
        if mode == "empty-duration" {
            options.duration = Some(String::new());
        }
        options.disable_default_scope = mode.starts_with("disabled-");
        if mode == "configured-endpoint" {
            options.authorization_endpoint =
                Some("https://configured.example.invalid/authorize".into());
            options.redirect_uri = Some("https://configured.example.invalid/callback".into());
        }
        if mode == "mapped" || mode == "mapped-empty-email" {
            options.map_profile_to_user = Some(if mode == "mapped-empty-email" {
                map_empty_email
            } else {
                map_profile
            });
        }
        let mut provider = OAuthProvider::reddit_with_options(options);
        provider.token_url = format!("{}/__test/reddit/token", config.base_url);
        provider.disable_sign_up = mode == "signup-disabled";
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        provider.require_email_verification = mode == "required";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(
                    settings,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("reddit", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = controls(fixture.clone());
    Ok((router.merge(controls), fixture))
}
fn map_profile(profile: Value) -> Result<alibi::plugins::oauth::OAuthUserInfo, String> {
    MAPPER_RECEIPTS
        .lock()
        .map_err(|error| error.to_string())?
        .push(profile.clone());
    Ok(alibi::plugins::oauth::OAuthUserInfo {
        additional_fields: Default::default(),
        id: "cannot-replace-account-subject".into(),
        name: Some(format!(
            "Mapped {}",
            profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
        )),
        email: "mapped-reddit@example.invalid".into(),
        email_verified: true,
        image: Some("https://images.example.invalid/mapped-reddit.png".into()),
    })
}
fn map_empty_email(profile: Value) -> Result<alibi::plugins::oauth::OAuthUserInfo, String> {
    let mut user = map_profile(profile)?;
    user.email.clear();
    Ok(user)
}
fn controls(fixture: Fixture) -> Router {
    let controls = Router::new()
        .route(
            "/__test/reddit/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/reddit/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route("/__test/reddit/user", get(profile))
        .route(
            "/__test/reddit/mapper-receipts",
            get(|| async {
                Json(
                    MAPPER_RECEIPTS
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                )
            }),
        )
        .route("/__test/reddit/token", post(token))
        .route("/__test/reddit/leak", post(leak))
        .with_state(fixture.clone());
    controls
}
async fn profile(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    fixture.receipts.lock().await.push(json!({"path":"/user","method":"GET","authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"accept":headers.get("accept").and_then(|value|value.to_str().ok()),"userAgent":headers.get("user-agent").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"body":null}));
    let control = fixture.control.lock().await;
    (axum::http::StatusCode::from_u16(control.get("profileStatus").and_then(Value::as_u64).unwrap_or(200).try_into().unwrap_or(500)).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),Json(control.get("profile").cloned().unwrap_or_else(||json!({"id":"fixture-reddit-subject","name":"Reddit Name","icon_img":"https://images.example.invalid/reddit.png?size=large","email":"reddit@example.invalid"}))))
}
async fn leak(State(fixture): State<Fixture>, headers: HeaderMap, body: String) -> Json<Value> {
    fixture.receipts.lock().await.push(json!({"path":"/leak","authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"body":body}));
    Json(json!({"access_token":"leaked-access","refresh_token":"leaked-refresh"}))
}
async fn token(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: String,
) -> (axum::http::StatusCode, HeaderMap, Json<Value>) {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture.receipts.lock().await.push(json!({"path":"/token", "method":"POST", "authorization":headers.get("authorization").and_then(|value| value.to_str().ok()), "accept":headers.get("accept").and_then(|value|value.to_str().ok()),"userAgent":headers.get("user-agent").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value| value.to_str().ok()),"body":fields}));
    let control = fixture.control.lock().await;
    let mut response_headers = HeaderMap::new();
    if control
        .get("tokenRedirect")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        response_headers.insert(
            axum::http::header::LOCATION,
            axum::http::HeaderValue::from_static("/__test/reddit/leak"),
        );
    }
    (axum::http::StatusCode::from_u16(control.get("tokenStatus").and_then(Value::as_u64).unwrap_or(200).try_into().unwrap_or(500)).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),response_headers,Json(control.get("tokenResponse").cloned().unwrap_or_else(|| json!({"access_token":"fixture-reddit-access","refresh_token":"fixture-reddit-refresh","token_type":"Bearer","expires_in":3600,"scope":"identity"}))))
}
