//! Real discovery and provider HTTP authority for the generic SDK owner.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{
    GenericOAuthConfig, OAuthProfileMapper, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::DatabaseConnection;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
#[derive(Clone, Default)]
pub(crate) struct Fixture {
    control: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
    base: String,
}
impl Fixture {
    pub(crate) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts
            .lock()
            .await
            .retain(|row| row["path"] == "/metadata");
    }
}
struct Mapper;
#[async_trait::async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(
        &self,
        _: Value,
    ) -> Result<alibi_core::field_policy::FieldOutput, String> {
        Ok([
            ("id".into(), json!("mapped-id")),
            ("name".into(), json!("Mapped Name")),
        ]
        .into_iter()
        .collect())
    }
}
struct Custom(Fixture);
#[async_trait::async_trait]
impl OAuthUserInfoHandler for Custom {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        self.0.receipts.lock().await.push(json!({"path":"/custom"}));
        let raw = self.0.control.lock().await["profile"].clone();
        Ok(OAuthUserInfoResponse {
            user_output: None,
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id: raw["id"].as_str().unwrap_or_default().into(),
                email: raw["email"].as_str().unwrap_or_default().into(),
                name: raw["name"].as_str().map(str::to_owned),
                image: None,
                email_verified: raw["emailVerified"].as_bool().unwrap_or(false),
            },
            data: raw,
        })
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| alibi::AuthError::internal("Fixture listener failed"))?;
    let fixture = Fixture {
        base: format!(
            "http://{}",
            listener
                .local_addr()
                .map_err(|_| alibi::AuthError::internal("Fixture address failed"))?
        ),
        ..Default::default()
    };
    let transport = Router::new()
        .route(
            "/metadata/keys",
            get(|| async {
                Json(
                    serde_json::from_str::<Value>(include_str!(
                        "../../../../fixtures/one-tap/jwks.json"
                    ))
                    .unwrap(),
                )
            }),
        )
        .route("/metadata/{mode}", get(metadata))
        .route("/token/{kind}", post(token))
        .route("/user/{kind}", get(user))
        .with_state(fixture.clone());
    tokio::spawn(async move {
        let _result = axum::serve(listener, transport).await;
    });
    let mut router = Router::new();
    for mode in [
        "success",
        "response-type",
        "expiry-positive",
        "expiry-zero",
        "expiry-negative",
        "custom-token",
        "custom-token-error",
        "override",
        "failed",
        "fallback",
        "invalid-issuer",
        "invalid-jwks",
        "required",
        "oidc",
        "mapped",
        "logout",
        "logout-configured",
        "logout-disabled",
        "logout-invalid",
        "logout-no-return",
    ] {
        let path = format!("/__test/profiles/generic-discovery-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut generic = GenericOAuthConfig::new("discovery-client", "discovery-secret");
        generic.discovery_url = Some(format!("{}/metadata/{mode}", fixture.base));
        generic.discovery_headers = vec![("x-discovery".into(), "configured-header".into())];
        if ["override", "fallback", "invalid-issuer"].contains(&mode) {
            generic.authorization_url = Some("https://configured.example.invalid/authorize".into());
            generic.token_url = Some(format!("{}/token/configured", fixture.base));
            generic.user_info_url = Some(format!("{}/user/configured", fixture.base));
        }
        generic.disable_provider_logout = !mode.starts_with("logout") || mode == "logout-disabled";
        if mode.starts_with("logout") && mode != "logout-no-return" {
            generic.post_logout_redirect_uri = Some("/signed-out".into());
        }
        if mode == "logout-configured" {
            generic.end_session_endpoint = Some("https://configured.example.invalid/logout?keep=1&id_token_hint=old&id_token_hint=duplicate".into());
        }
        if mode == "logout-invalid" {
            generic.end_session_endpoint = Some("http://[bad".into());
        }
        generic.require_id_token_verification = mode == "required";
        generic.provider.scopes = vec!["profile".into()];
        let policy = generic.provider.authorization.as_mut().unwrap();
        if mode == "response-type" {
            policy.response_type = "token".into();
        }
        policy
            .authorization_code_params
            .insert("resource".into(), "discovery-resource".into());
        policy
            .refresh_token_params
            .insert("resource".into(), "refresh-resource".into());
        policy.authorization_code_headers = vec![("x-grant".into(), "configured-grant".into())];
        if mode == "oidc" {
            generic.provider.get_user_info = Some(Arc::new(Custom(fixture.clone())));
        }
        if mode == "mapped" {
            generic.map_profile = Some(Arc::new(Mapper));
        }
        if mode.starts_with("expiry-") || mode.starts_with("custom-token") {
            generic.access_token_expires_in = Some(if mode == "expiry-zero" {
                0.0
            } else if mode == "expiry-negative" {
                -60.0
            } else {
                17.0
            });
            if mode.starts_with("custom-token") {
                generic
                    .provider
                    .authorization
                    .as_mut()
                    .expect("generic authorization policy")
                    .authorization_code =
                    Some(alibi::plugins::oauth::OAuthAuthorizationCodeCallback(
                        Arc::new(CustomCode {
                            fixture: fixture.clone(),
                            denied: mode == "custom-token-error",
                        }),
                    ));
            }
        }
        let mut plugin = OAuthPlugin::new();
        if let Some(resolved) = generic
            .resolve()
            .await
            .map_err(|e| alibi::AuthError::config(e.to_string()))?
        {
            if mode == "logout" {
                for (id, endpoint) in [
                    ("invalid", "http://[bad"),
                    ("backup", "https://backup.example.invalid/logout"),
                ] {
                    let mut provider = resolved.provider.clone();
                    provider
                        .authorization
                        .as_mut()
                        .unwrap()
                        .end_session
                        .as_mut()
                        .unwrap()
                        .endpoint = endpoint.into();
                    plugin = plugin.add_provider(id, provider);
                }
            }
            plugin = plugin.add_provider("discovery", resolved.provider);
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(
                    settings,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(plugin)
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/generic-discovery/control",
            post(
                |State(f): State<Fixture>, Json(v): Json<Value>| async move {
                    *f.control.lock().await = v;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/generic-discovery/receipts",
            get(|State(f): State<Fixture>| async move { Json(f.receipts.lock().await.clone()) }),
        )
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
async fn metadata(
    State(f): State<Fixture>,
    Path(mode): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    f.receipts.lock().await.push(json!({"path":"/metadata","mode":mode,"header":headers.get("x-discovery").and_then(|v|v.to_str().ok())}));
    if ["failed", "fallback", "required"].contains(&mode.as_str()) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"metadata failed"})),
        );
    }
    let mut document = json!({"authorization_endpoint":"https://discovered.example.invalid/authorize","token_endpoint":format!("{}/token/discovered",f.base),"userinfo_endpoint":format!("{}/user/discovered",f.base),"end_session_endpoint":"https://discovered.example.invalid/logout"});
    if mode == "invalid-issuer" {
        document["issuer"] = json!("not a url");
    }
    if mode == "invalid-jwks" {
        document["issuer"] = json!("https://issuer.example.invalid");
        document["jwks_uri"] = json!("http://[bad");
    }
    if mode == "oidc" {
        document["issuer"] = json!("https://issuer.example.invalid");
        document["jwks_uri"] = json!("keys");
        document["id_token_signing_alg_values_supported"] = json!(["RS256"]);
    }
    (StatusCode::OK, Json(document))
}
async fn token(
    State(f): State<Fixture>,
    Path(kind): Path<String>,
    headers: HeaderMap,
    raw: String,
) -> (StatusCode, Json<Value>) {
    let body: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect();
    f.receipts.lock().await.push(json!({"path":format!("/token/{kind}"),"authorization":headers.get("authorization").and_then(|v|v.to_str().ok()),"grantHeader":headers.get("x-grant").and_then(|v|v.to_str().ok()),"body":body,"raw":raw}));
    let control = f.control.lock().await;
    (status(&control,"tokenStatus"),Json(control.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"discovery-access","refresh_token":"discovery-refresh","token_type":"Bearer","expires_in":3600,"scope":"profile"}))))
}
async fn user(
    State(f): State<Fixture>,
    Path(kind): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    f.receipts.lock().await.push(json!({"path":format!("/user/{kind}"),"authorization":headers.get("authorization").and_then(|v|v.to_str().ok())}));
    let control = f.control.lock().await;
    (status(&control,"userStatus"),Json(control.get("profile").cloned().unwrap_or_else(||json!({"id":"discovery-subject","sub":"oidc-subject","email":"discovery@example.invalid","email_verified":true,"name":"Discovery Name"}))))
}
fn status(value: &Value, key: &str) -> StatusCode {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .and_then(|v| StatusCode::from_u16(v).ok())
        .unwrap_or(StatusCode::OK)
}

struct CustomCode {
    fixture: Fixture,
    denied: bool,
}
#[async_trait::async_trait]
impl alibi::plugins::oauth::OAuthAuthorizationCodeHandler for CustomCode {
    async fn validate_authorization_code(
        &self,
        data: alibi::plugins::oauth::OAuthAuthorizationCodeContext,
    ) -> Result<alibi::plugins::oauth::OAuthTokenSet, String> {
        tokio::task::yield_now().await;
        self.fixture.receipts.lock().await.push(json!({"kind":"custom-token","code":data.code,"redirectURI":data.redirect_uri,"codeVerifier":data.code_verifier}));
        if self.denied {
            return Err("custom token callback denied".into());
        }
        Ok(alibi::plugins::oauth::OAuthTokenSet {
            access_token: Some("custom-access".into()),
            refresh_token: Some("custom-refresh".into()),
            scopes: vec!["custom-scope".into()],
            ..Default::default()
        })
    }
}
