//! Actual Cognito provider using trusted local transports and observed requests.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{
    CognitoOptions, HttpOAuthJwksSource, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
static MAPPER_RECEIPTS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
#[derive(Clone, Default)]
pub(crate) struct Fixture {
    control: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
    user_info_receipts: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(crate) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts.lock().await.clear();
        self.user_info_receipts.lock().await.clear();
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
        "configured",
        "disabled-scope",
        "disabled-configured",
        "public",
        "required",
        "client-array",
        "empty-clients",
        "mapped",
        "disabled-idtoken",
        "implicit-disabled",
        "signup-disabled",
        "configured-endpoint",
        "http-domain",
        "encrypted",
        "userinfo-override",
        "query-overrides",
        "client-key",
    ] {
        let path = format!("/__test/profiles/social-cognito-{mode}/api/auth");
        let mut settings = config.clone().base_path(&path);
        settings.account.encrypt_oauth_tokens = mode == "encrypted";
        let mut options = CognitoOptions::new(
            "fixture-social-client",
            (!["public", "required"].contains(&mode)).then(|| "fixture-social-secret".into()),
            if mode == "http-domain" {
                "http://fixture-cognito.example.invalid"
            } else {
                "https://fixture-cognito.example.invalid"
            },
            "fixture-region",
            "fixture-pool",
        );
        options.require_client_secret = mode == "required";
        if mode == "client-key" {
            options.client_key = Some("fixture-cognito-client-key".into());
        }
        options.jwks_source = Some(Arc::new(HttpOAuthJwksSource::new(format!(
            "{}/__test/cognito/keys",
            config.base_url
        ))));
        options.user_info_endpoint = Some(format!("{}/__test/cognito/userinfo", config.base_url));
        if mode == "client-array" {
            options.client_ids.push("fixture-cognito-secondary".into());
        }
        if mode == "empty-clients" {
            options.client_ids.clear();
        }
        if ["configured", "disabled-configured"].contains(&mode) {
            options.scope = ["configured-scope", "openid", "punctuation-!~*'()"]
                .map(String::from)
                .to_vec();
            options.prompt = Some("login".into());
            options.identity_provider = Some("ConfiguredIdentity".into());
        }
        options.disable_default_scope = ["disabled-scope", "disabled-configured"].contains(&mode);
        if mode == "configured-endpoint" {
            options.authorization_endpoint =
                Some("https://alternate-cognito.example.invalid/authorize?retained=value".into());
            options.redirect_uri = Some("https://client.example.invalid/cognito-return".into());
        }
        if mode == "query-overrides" {
            options.authorization_endpoint=Some("https://alternate-cognito.example.invalid/authorize?response_type=stale&client_id=stale&state=stale&state=stale2&scope=stale&redirect_uri=stale&code_challenge=stale&code_challenge_method=stale&identity_provider=stale&custom=stale&retained=value".into());
        }
        if mode == "mapped" {
            options.map_profile_to_user = Some(|profile| {
                MAPPER_RECEIPTS
                    .lock()
                    .expect("mapper receipt lock")
                    .push(profile.clone());
                let name = ["name", "given_name", "username"]
                    .into_iter()
                    .filter_map(|key| profile.get(key))
                    .find(|value| !value.is_null())
                    .map(|value| {
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), String::from)
                    })
                    .unwrap_or_default();
                Ok(OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: "cannot-replace-raw-subject".into(),
                    name: Some(format!("Mapped {name}")),
                    email: "mapped-cognito@example.invalid".into(),
                    email_verified: false,
                    image: Some("https://images.example.invalid/mapped-cognito.png".into()),
                })
            });
        }
        let mut provider = OAuthProvider::cognito(options).map_err(AuthError::config)?;
        if mode == "userinfo-override" {
            provider.get_user_info = Some(Arc::new(ApplicationUserInfo(fixture.clone())));
        }
        provider.token_url = format!("{}/__test/cognito/token", config.base_url);
        provider.disable_id_token_sign_in = mode == "disabled-idtoken";
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        provider.disable_sign_up = mode == "signup-disabled";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("cognito", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/cognito/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/cognito/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/cognito/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/__test/cognito/keys", get(keys))
        .route(
            "/__test/cognito/userinfo-profile-receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.user_info_receipts.lock().await.clone())
            }),
        )
        .route("/__test/cognito/token", post(token))
        .route("/__test/cognito/userinfo", get(profile))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
struct ApplicationUserInfo(Fixture);
#[async_trait::async_trait]
impl OAuthUserInfoHandler for ApplicationUserInfo {
    async fn get_user_info(
        &self,
        _request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let profile = self
            .0
            .control
            .lock()
            .await
            .get("profile")
            .cloned()
            .ok_or("Missing application profile")?;
        self.0.user_info_receipts.lock().await.push(profile.clone());
        Ok(OAuthUserInfoResponse {
            user_output: None,
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id: "cannot-replace-raw-subject".into(),
                name: Some("Application Cognito User".into()),
                email: profile
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                email_verified: true,
                image: None,
            },
            data: profile,
        })
    }
}
fn receipt(path: &str, method: &str, headers: &HeaderMap, body: Option<Value>) -> Value {
    json!({"path":path,"method":method,"authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"body":body})
}
async fn keys(State(fixture): State<Fixture>, headers: HeaderMap) -> Json<Value> {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/keys", "GET", &headers, None));
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
async fn profile(State(fixture): State<Fixture>, headers: HeaderMap) -> impl IntoResponse {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt("/userinfo", "GET", &headers, None));
    let control = fixture.control.lock().await;
    (endpoint_status(&control, "userInfoStatus"), Json(control.get("profile").cloned().unwrap_or_else(||json!({"sub":"fixture-cognito-subject","name":"Cognito User","email":"cognito@example.invalid","email_verified":true,"picture":"https://images.example.invalid/cognito.png"}))))
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
        .push(receipt("/token", "POST", &headers, Some(json!(fields))));
    let control = fixture.control.lock().await;
    (endpoint_status(&control, "tokenStatus"), Json(control.get("tokenResponse").cloned().unwrap_or_else(||{
        let mut value = json!({"access_token":"fixture-cognito-access","refresh_token":"fixture-cognito-refresh","token_type":"Bearer","expires_in":3600});
        if let Some(token)=control.get("idToken").filter(|value|!value.is_null()) {value["id_token"]=token.clone();}
        value
    })))
}
fn endpoint_status(control: &Value, key: &str) -> axum::http::StatusCode {
    control
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .and_then(|value| axum::http::StatusCode::from_u16(value).ok())
        .unwrap_or(axum::http::StatusCode::OK)
}
