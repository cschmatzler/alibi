//! Actual PayPal factory with trusted local HTTP and observed provider receipts.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{OAuthProvider, PayPalEnvironment, PayPalOptions};
use alibi::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::DatabaseConnection;
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
        "live",
        "configured",
        "disabled-scope",
        "disabled-configured",
        "public",
        "empty-client",
        "encoded",
        "mapped",
        "implicit-disabled",
        "signup-disabled",
        "required",
        "configured-endpoint",
        "client-key",
        "shipping",
        "prompt",
        "empty-prompt",
    ] {
        let path = format!("/__test/profiles/social-paypal-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let (client_id, secret) = if mode == "encoded" {
            ("client :+!*'()", "secret :+!*'()")
        } else {
            ("fixture-social-client", "fixture-social-secret")
        };
        let mut options = PayPalOptions::new(
            if mode == "empty-client" {
                ""
            } else {
                client_id
            },
            if mode == "public" { "" } else { secret },
        );
        if mode == "live" {
            options.environment = PayPalEnvironment::Live;
        }
        if mode == "prompt" || mode == "empty-prompt" {
            options.prompt = Some(if mode == "prompt" { "consent" } else { "" }.into());
        }

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
                    email: "mapped-paypal@example.invalid".into(),
                    email_verified: true,
                    image: Some("https://images.example.invalid/mapped-paypal.png".into()),
                })
            });
        }
        // Rewrite the endpoints produced by the real factory, retaining their
        // destination in actual HTTP receipts. A wrong environment or endpoint
        // must not silently become the fixture's expected destination.
        let original = OAuthProvider::paypal_with_options(options.clone());
        options.user_info_endpoint = Some(local_endpoint(
            original.user_info_url.as_deref().unwrap(),
            &config.base_url,
        ));
        let mut provider = OAuthProvider::paypal_with_options(options);
        provider.token_url = local_endpoint(&original.token_url, &config.base_url);
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
                .plugin(OAuthPlugin::new().add_provider("paypal", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/paypal/control",
            post(
                |State(fixture): State<Fixture>, Json(value): Json<Value>| async move {
                    *fixture.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/paypal/receipts",
            get(|State(fixture): State<Fixture>| async move {
                Json(fixture.receipts.lock().await.clone())
            }),
        )
        .route("/__test/paypal/sandbox/user", get(profile))
        .route("/__test/paypal/live/user", get(profile))
        .route(
            "/__test/paypal/mapper-receipts",
            get(|| async {
                Json(
                    MAPPER_RECEIPTS
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                )
            }),
        )
        .route("/__test/paypal/sandbox/token", post(token))
        .route("/__test/paypal/live/token", post(token))
        .route("/__test/paypal/leak", post(leak))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
async fn profile(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    axum::extract::Query(query): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> (axum::http::StatusCode, Json<Value>) {
    fixture.receipts.lock().await.push(json!({"path":"/user","destination":destination(&uri, "user"),"method":"GET","authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"contentType":headers.get("content-type").and_then(|value|value.to_str().ok()),"body":null,"accept":headers.get("accept").and_then(|value|value.to_str().ok()),"query":query}));
    let control = fixture.control.lock().await;
    (axum::http::StatusCode::from_u16(control.get("profileStatus").and_then(Value::as_u64).unwrap_or(200).try_into().unwrap_or(500)).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),Json(control.get("profile").cloned().unwrap_or_else(||json!({"user_id":"fixture-paypal-subject","name":"PayPal Name","email":"paypal@example.invalid","email_verified":true}))))
}
async fn leak(State(fixture): State<Fixture>, headers: HeaderMap, body: String) -> Json<Value> {
    fixture.receipts.lock().await.push(json!({"path":"/leak","authorization":headers.get("authorization").and_then(|value|value.to_str().ok()),"body":body}));
    Json(json!({"access_token":"leaked-access","refresh_token":"leaked-refresh"}))
}
async fn token(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: String,
) -> (axum::http::StatusCode, HeaderMap, Json<Value>) {
    let fields: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    fixture.receipts.lock().await.push(json!({"path":"/token", "destination":destination(&uri, "token"), "method":"POST", "authorization":headers.get("authorization").and_then(|value| value.to_str().ok()), "contentType":headers.get("content-type").and_then(|value| value.to_str().ok()),"body":fields,"accept":headers.get("accept").and_then(|value|value.to_str().ok()),"query":{}}));
    let control = fixture.control.lock().await;
    let mut response_headers = HeaderMap::new();
    if control
        .get("tokenRedirect")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        response_headers.insert(
            axum::http::header::LOCATION,
            axum::http::HeaderValue::from_static("/__test/paypal/leak"),
        );
    }
    (axum::http::StatusCode::from_u16(control.get("tokenStatus").and_then(Value::as_u64).unwrap_or(200).try_into().unwrap_or(500)).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),response_headers,Json(control.get("tokenResponse").cloned().unwrap_or_else(|| json!({"access_token":"fixture-paypal-access","refresh_token":"fixture-paypal-refresh","token_type":"Bearer","expires_in":3600,"scope":"user-details.read"}))))
}

fn local_endpoint(endpoint: &str, base: &str) -> String {
    let suffix = match endpoint {
        "https://api-m.sandbox.paypal.com/v1/oauth2/token" => "sandbox/token",
        "https://api-m.paypal.com/v1/oauth2/token" => "live/token",
        "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo" => "sandbox/user",
        "https://api-m.paypal.com/v1/identity/oauth2/userinfo" => "live/user",
        other => panic!("Unexpected real PayPal endpoint: {other}"),
    };
    format!("{base}/__test/paypal/{suffix}")
}
fn destination(uri: &axum::http::Uri, operation: &str) -> String {
    let host = if uri.path().contains("/live/") {
        "api-m.paypal.com"
    } else {
        "api-m.sandbox.paypal.com"
    };
    let path = if operation == "token" {
        "/v1/oauth2/token"
    } else {
        "/v1/identity/oauth2/userinfo"
    };
    format!("https://{host}{path}")
}
