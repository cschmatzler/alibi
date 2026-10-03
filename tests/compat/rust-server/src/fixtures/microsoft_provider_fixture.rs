//! Microsoft's real public factory with application-owned network destinations.
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
    HttpOAuthJwksSource, MicrosoftOptions, MicrosoftProfilePhotoSize, OAuthClientAssertion,
    OAuthClientAssertionContext, OAuthClientAssertionGetter, OAuthProvider, OAuthUserInfo,
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
    assertions: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(crate) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts.lock().await.clear();
        self.assertions.lock().await.clear();
        MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clear();
    }
}
struct Assertion(Fixture);
#[async_trait::async_trait]
impl OAuthClientAssertionGetter for Assertion {
    async fn get_client_assertion(
        &self,
        context: OAuthClientAssertionContext,
    ) -> Result<String, String> {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let grant = match context.grant_type {
            better_auth::plugins::oauth::OAuthTokenGrant::AuthorizationCode => "authorization_code",
            better_auth::plugins::oauth::OAuthTokenGrant::RefreshToken => "refresh_token",
        };
        self.0.assertions.lock().await.push(json!({"clientId":context.client_id,"tokenEndpoint":context.token_endpoint,"grantType":grant}));
        Ok(format!("fixture-assertion-{grant}"))
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let fixture = Fixture::default();
    let mut incompatible = MicrosoftOptions::new(
        "fixture-social-client",
        Some("fixture-social-secret".into()),
    );
    incompatible.client_assertion =
        Some(OAuthClientAssertion(Arc::new(Assertion(fixture.clone()))));
    let constructor_error = OAuthProvider::microsoft(incompatible).err();
    let mut router = Router::new();
    for mode in [
        "default",
        "configured",
        "disabled-scope",
        "disabled-configured",
        "public",
        "client-array",
        "empty-clients",
        "mapped",
        "client-key",
        "assertion",
        "organizations",
        "consumers",
        "fixed-tenant",
        "authority-slashes",
        "photo64",
        "no-photo",
        "implicit-disabled",
        "signup-disabled",
        "disabled-idtoken",
    ] {
        let path = format!("/__test/profiles/social-microsoft-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut options = MicrosoftOptions::new(
            "fixture-social-client",
            (!["public", "assertion"].contains(&mode)).then(|| "fixture-social-secret".into()),
        );
        let tenant = if ["organizations", "consumers"].contains(&mode) {
            mode
        } else if mode == "fixed-tenant" {
            "fixture-tenant"
        } else {
            "common"
        };
        options.tenant_id = Some(tenant.into());
        options.authority = Some(if mode == "default" {
            "https://login.microsoftonline.com".into()
        } else {
            format!(
                "{}{}",
                config.base_url,
                if mode == "authority-slashes" {
                    "///"
                } else {
                    ""
                }
            )
        });
        options.jwks_source = Some(Arc::new(HttpOAuthJwksSource::new(format!(
            "{}/{tenant}/discovery/v2.0/keys",
            config.base_url
        ))));
        options.profile_photo_endpoint = Some(format!(
            "{}/photo/{}",
            config.base_url,
            if mode == "photo64" { "64x64" } else { "48x48" }
        ));
        options.profile_photo_size = if mode == "photo64" {
            MicrosoftProfilePhotoSize::Size64
        } else {
            MicrosoftProfilePhotoSize::Size48
        };
        options.disable_profile_photo = mode == "no-photo";
        if mode == "client-array" {
            options
                .client_ids
                .push("fixture-microsoft-secondary".into());
        }
        if mode == "empty-clients" {
            options.client_ids.clear();
        }
        if ["configured", "disabled-configured"].contains(&mode) {
            options.scope = ["configured-scope", "openid", "punctuation-!~*'()"]
                .map(String::from)
                .to_vec();
            options.prompt = Some("login".into());
        }
        options.disable_default_scope = mode.starts_with("disabled-");
        if mode == "client-key" {
            options.client_key = Some("fixture-microsoft-client-key".into());
        }
        if mode == "assertion" {
            options.client_assertion =
                Some(OAuthClientAssertion(Arc::new(Assertion(fixture.clone()))));
        }
        if mode == "mapped" {
            options.map_profile_to_user = Some(|profile| {
                MAPPER_RECEIPTS
                    .lock()
                    .expect("mapper receipt lock")
                    .push(profile.clone());
                Ok(OAuthUserInfo {
                    additional_fields: [(
                        "microsoftMapped".into(),
                        json!({"oid":profile.get("oid")}),
                    )]
                    .into_iter()
                    .collect(),
                    id: "cannot-replace-raw-oid".into(),
                    name: Some(format!(
                        "Mapped {}",
                        profile
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                    )),
                    email: "mapped-microsoft@example.invalid".into(),
                    email_verified: false,
                    image: Some("https://images.example.invalid/mapped-microsoft.png".into()),
                })
            });
        }
        let mut provider = OAuthProvider::microsoft(options).map_err(AuthError::config)?;
        provider.token_url = format!("{}/{tenant}/oauth2/v2.0/token", config.base_url);
        provider.disable_id_token_sign_in = mode == "disabled-idtoken";
        provider.disable_implicit_sign_up = mode == "implicit-disabled";
        // The pinned Microsoft factory does not forward disableSignUp.
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("microsoft", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let mut controls = Router::new()
        .route(
            "/__test/microsoft/constructor",
            get(move || {
                let error = constructor_error.clone();
                async move { Json(json!({"error":error})) }
            }),
        )
        .route(
            "/__test/microsoft/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/microsoft/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route(
            "/__test/microsoft/assertion-receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.assertions.lock().await.clone())
            }),
        )
        .route(
            "/__test/microsoft/mapper-receipts",
            get(|| async { Json(MAPPER_RECEIPTS.lock().expect("mapper receipt lock").clone()) }),
        )
        .route("/photo/48x48", get(photo))
        .route("/photo/64x64", get(photo));
    for tenant in ["common", "organizations", "consumers", "fixture-tenant"] {
        controls = controls
            .route(&format!("/{tenant}/oauth2/v2.0/token"), post(token))
            .route(&format!("/{tenant}/discovery/v2.0/keys"), get(keys));
    }
    Ok((router.merge(controls.with_state(fixture.clone())), fixture))
}
fn receipt(path: &str, method: &str, headers: &HeaderMap, body: Option<Value>) -> Value {
    json!({"path":path,"method":method,"authorization":headers.get("authorization").and_then(|v|v.to_str().ok()),"contentType":headers.get("content-type").and_then(|v|v.to_str().ok()),"body":body})
}
async fn keys(
    State(fixture): State<Fixture>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Json<Value> {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt(uri.path(), "GET", &headers, None));
    Json(
        fixture
            .control
            .lock()
            .await
            .get("keys")
            .cloned()
            .unwrap_or_else(|| {
                serde_json::from_str(include_str!("../../../../fixtures/one-tap/jwks.json"))
                    .expect("trusted fixture JWKS")
            }),
    )
}
async fn photo(
    State(fixture): State<Fixture>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    fixture
        .receipts
        .lock()
        .await
        .push(receipt(uri.path(), "GET", &headers, None));
    (
        status(&*fixture.control.lock().await, "photoStatus"),
        [("content-type", "image/jpeg")],
        vec![0xff, 0xd8, 0, 65, 0xff, 0xd9],
    )
}
async fn token(
    State(fixture): State<Fixture>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture
        .receipts
        .lock()
        .await
        .push(receipt(uri.path(), "POST", &headers, Some(json!(fields))));
    let control = fixture.control.lock().await;
    if let Some(location) = control.get("tokenRedirect").and_then(Value::as_str) {
        return (axum::http::StatusCode::FOUND, [("location", location)]).into_response();
    }
    (status(&control,"tokenStatus"),Json(control.get("tokenResponse").cloned().unwrap_or_else(||{let mut value=json!({"access_token":"fixture-microsoft-access","refresh_token":"fixture-microsoft-refresh","token_type":"Bearer","expires_in":3600});if let Some(token)=control.get("idToken"){value["id_token"]=token.clone();}value}))).into_response()
}
fn status(control: &Value, key: &str) -> axum::http::StatusCode {
    control
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .and_then(|v| axum::http::StatusCode::from_u16(v).ok())
        .unwrap_or(axum::http::StatusCode::OK)
}
