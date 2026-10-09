//! Actual Atlassian factory with trusted local HTTP and observed provider receipts.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{AtlassianOptions, OAuthProvider};
use alibi::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi::seaorm::DatabaseConnection;
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
        "mapped",
        "implicit-disabled",
        "signup-disabled",
        "required",
        "configured-endpoint",
    ] {
        let path = format!("/__test/profiles/social-atlassian-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = AtlassianOptions::new("fixture-social-client", "fixture-social-secret");
        options.user_info_endpoint = Some(format!("{}/__test/atlassian/me", config.base_url));
        if mode == "configured" || mode == "disabled-configured" {
            options.scope = vec!["configured-scope".into(), "read:jira-user".into()];
            options.prompt = Some("consent".into());
        }
        options.disable_default_scope = mode.starts_with("disabled-");
        if mode == "configured-endpoint" {
            options.authorization_endpoint =
                Some("https://configured.example.invalid/authorize".into());
            options.redirect_uri = Some("https://configured.example.invalid/callback".into());
        }
        if mode == "mapped" {
            options.map_profile_to_user = Some(|profile| {
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
                    email: "mapped-atlassian@example.invalid".into(),
                    email_verified: true,
                    image: Some("https://images.example.invalid/mapped-atlassian.png".into()),
                })
            });
        }
        let mut provider = OAuthProvider::atlassian_with_options(options);
        provider.token_url = format!("{}/__test/atlassian/token", config.base_url);
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
                .plugin(OAuthPlugin::new().add_provider("atlassian", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/atlassian/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/atlassian/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route("/__test/atlassian/me", get(profile))
        .route(
            "/__test/atlassian/mapper-receipts",
            get(|| async {
                Json(
                    MAPPER_RECEIPTS
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                )
            }),
        )
        .route("/__test/atlassian/token", post(token))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
async fn profile(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    fixture.receipts.lock().await.push(json!({"path":"/me","method":"GET","authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"body":null}));
    let control = fixture.control.lock().await;
    (axum::http::StatusCode::from_u16(control.get("profileStatus").and_then(Value::as_u64).unwrap_or(200).try_into().unwrap_or(500)).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),Json(control.get("profile").cloned().unwrap_or_else(||json!({"account_id":"fixture-atlassian-subject","name":"Atlassian Name","email":"atlassian@example.invalid","picture":"https://images.example.invalid/atlassian.png"}))))
}
async fn token(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    body: String,
) -> (axum::http::StatusCode, Json<Value>) {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture.receipts.lock().await.push(json!({"path":"/token", "method":"POST", "authorization":headers.get("authorization").and_then(|value| value.to_str().ok()), "contentType":headers.get("content-type").and_then(|value| value.to_str().ok()),"body":fields}));
    let control = fixture.control.lock().await;
    (axum::http::StatusCode::from_u16(control.get("tokenStatus").and_then(Value::as_u64).unwrap_or(200).try_into().unwrap_or(500)).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),Json(control.get("tokenResponse").cloned().unwrap_or_else(|| json!({"access_token":"fixture-atlassian-access","refresh_token":"fixture-atlassian-refresh","token_type":"Bearer","expires_in":3600,"scope":"read:jira-user offline_access"}))))
}
