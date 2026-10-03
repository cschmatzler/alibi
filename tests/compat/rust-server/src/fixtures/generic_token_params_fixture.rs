//! Generic provider token configuration exercised through real HTTP grants.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{
    GenericOAuthConfig, OAuthAuthorizationPolicy, OAuthProvider, OAuthRefreshContext,
    OAuthRefreshTokenHandler, OAuthRefreshTokenParams, OAuthRefreshTokenParamsResolver,
    OAuthTokenEndpointAuth, OAuthTokenSet, OAuthUserInfo,
};
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::DatabaseConnection;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
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
fn params(mode: &str, refresh: bool) -> BTreeMap<String, String> {
    if let Some(base) = mode.strip_prefix("refresh-") {
        return params(
            if refresh {
                base
            } else {
                base.strip_suffix("-secret").unwrap_or(base)
            },
            refresh,
        );
    }
    let mut result: BTreeMap<_, _> = [
        (
            "audience",
            "https://resource.example.invalid/a?x=1&y=two words",
        ),
        ("resource", "tenant :+&=/%é"),
        ("client_id", "extra-client"),
        ("grant_type", "extra-grant"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    if refresh {
        result.insert("refresh_token".into(), "extra-refresh".into());
        result.insert("scope".into(), "rotated scope".into());
        for k in ["__proto__", "constructor", "prototype"] {
            result.insert(k.into(), "blocked".into());
        }
    } else {
        for (k, v) in [
            ("code", "extra-code"),
            ("redirect_uri", "https://wrong.example.invalid"),
            ("code_verifier", "extra-verifier"),
        ] {
            result.insert(k.into(), v.into());
        }
    }
    if ["post", "basic-secret", "none-secret"].contains(&mode) {
        result.insert("client_secret".into(), "extra-secret".into());
    }
    if ["manual", "incomplete", "conflict"].contains(&mode) {
        result.insert("client_assertion".into(), "trusted-assertion".into());
        if mode != "incomplete" {
            result.insert(
                "client_assertion_type".into(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            );
        }
    }
    result
}
struct DynamicParams {
    fixture: Fixture,
    mode: String,
}
#[async_trait::async_trait]
impl OAuthRefreshTokenParamsResolver for DynamicParams {
    async fn resolve(
        &self,
        context: Option<OAuthRefreshContext<'_>>,
    ) -> Result<Option<BTreeMap<String, String>>, String> {
        tokio::task::yield_now().await;
        let req = context.map(|ctx| ctx.request);
        let tenant = req.and_then(|r| r.headers.get("x-refresh-tenant"));
        let cookie = req.and_then(|r| r.headers.get("cookie")).and_then(|c| {
            c.split(';')
                .map(str::trim)
                .find_map(|part| part.strip_prefix("refresh_meta="))
        });
        self.fixture.receipts.lock().await.push(json!({"kind":"params", "tenant":tenant, "cookie":cookie, "method":req.map(|r| format!("{:?}", r.method).to_uppercase()), "path":req.and_then(|r| r.url()).map(url::Url::path)}));
        if self.mode == "dynamic-error" {
            return Err("refresh policy rejected".into());
        }
        if self.mode == "dynamic-none" {
            return Ok(None);
        }
        let tenant = tenant
            .filter(|t| ["allowed-one", "allowed-two"].contains(&t.as_str()))
            .ok_or("tenant not allowed")?;
        Ok(Some(
            [
                ("resource", format!("tenant {tenant} :+&=/%é")),
                ("scope", format!("profile {tenant}")),
                ("client_id", "wrong-client".into()),
                ("client_secret", "wrong-secret".into()),
                ("grant_type", "wrong-grant".into()),
                ("refresh_token", "wrong-refresh".into()),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
        ))
    }
}
struct CustomRefresh(Fixture);
#[async_trait::async_trait]
impl OAuthRefreshTokenHandler for CustomRefresh {
    async fn refresh_access_token(&self, _token: &str) -> Result<OAuthTokenSet, String> {
        Err("request context missing".into())
    }
    async fn refresh_access_token_with_context(
        &self,
        token: &str,
        context: Option<OAuthRefreshContext<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        tokio::task::yield_now().await;
        let req = context.map(|ctx| ctx.request);
        let tenant = req.and_then(|r| r.headers.get("x-refresh-tenant"));
        let cookie = req.and_then(|r| r.headers.get("cookie")).and_then(|c| {
            c.split(';')
                .map(str::trim)
                .find_map(|part| part.strip_prefix("refresh_meta="))
        });
        self.0.receipts.lock().await.push(json!({"kind":"custom", "refreshToken":token, "tenant":tenant, "cookie":cookie, "method":req.map(|r| format!("{:?}", r.method).to_uppercase()), "path":req.and_then(|r| r.url()).map(url::Url::path)}));
        Ok(OAuthTokenSet {
            access_token: Some("custom-access".into()),
            refresh_token: Some("custom-refresh".into()),
            access_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            scopes: vec!["custom-scope".into()],
            ..Default::default()
        })
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let fixture = Fixture::default();
    let mut router = Router::new();
    for mode in [
        "post",
        "basic",
        "none",
        "manual",
        "default-none",
        "default-post",
        "basic-secret",
        "none-secret",
        "incomplete",
        "conflict",
        "refresh-basic-secret",
        "refresh-none-secret",
        "dynamic",
        "dynamic-none",
        "dynamic-error",
        "dynamic-custom",
    ] {
        let path = format!("/__test/profiles/generic-token-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let configured_mode = if mode.starts_with("dynamic") {
            "post"
        } else {
            mode.strip_prefix("refresh-").unwrap_or(mode)
        };
        let secret = if ["post", "basic", "basic-secret", "default-post"].contains(&configured_mode)
        {
            "secret :+&"
        } else {
            ""
        };
        let policy = OAuthAuthorizationPolicy {
            token_endpoint_auth: match configured_mode {
                "manual" | "incomplete" | "default-none" | "default-post" => None,
                "post" => Some(OAuthTokenEndpointAuth::ClientSecretPost),
                "basic" | "basic-secret" => Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                _ => Some(OAuthTokenEndpointAuth::None),
            },
            authorization_code_params: params(mode, false),
            refresh_token_params: params(mode, true),
            refresh_token_params_resolver: mode.starts_with("dynamic").then(|| {
                OAuthRefreshTokenParams(Arc::new(DynamicParams {
                    fixture: fixture.clone(),
                    mode: mode.into(),
                }))
            }),
            ..Default::default()
        };
        let provider = OAuthProvider {
            client_id: "client :+&".into(),
            client_secret: secret.into(),
            auth_url: "https://generic.example.invalid/authorize".into(),
            token_url: format!("{}/__test/generic-token/token", config.base_url),
            user_info_url: Some(format!("{}/__test/generic-token/user", config.base_url)),
            scopes: vec!["profile".into()],
            authorization: Some(policy),
            authorization_params: Vec::new(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            account_subject: None,
            map_user_info: Some(|raw| {
                Ok(OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: raw["id"].as_str().unwrap_or_default().into(),
                    email: raw["email"].as_str().unwrap_or_default().into(),
                    name: raw["name"].as_str().map(str::to_owned),
                    image: None,
                    email_verified: raw["email_verified"].as_bool().unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: (mode == "dynamic-custom").then(|| {
                Arc::new(CustomRefresh(fixture.clone())) as Arc<dyn OAuthRefreshTokenHandler>
            }),
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        };
        let provider = if mode.starts_with("dynamic") {
            let mut generic = GenericOAuthConfig::new("client :+&", secret);
            generic.authorization_url = Some(provider.auth_url.clone());
            generic.token_url = Some(provider.token_url.clone());
            generic.user_info_url = provider.user_info_url.clone();
            generic.provider = provider;
            generic
                .resolve()
                .await
                .map_err(|e| better_auth::AuthError::config(e.to_string()))?
                .ok_or_else(|| better_auth::AuthError::config("Generic fixture unavailable"))?
                .provider
        } else {
            provider
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(
                    settings,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("generic", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Router::new()
        .route(
            "/__test/generic-token/control",
            post(
                |State(f): State<Fixture>, Json(v): Json<Value>| async move {
                    *f.control.lock().await = v;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/generic-token/receipts",
            get(|State(f): State<Fixture>| async move { Json(f.receipts.lock().await.clone()) }),
        )
        .route("/__test/generic-token/token", post(token))
        .route("/__test/generic-token/user", get(user))
        .with_state(fixture.clone());
    Ok((router.merge(controls), fixture))
}
async fn token(State(f): State<Fixture>, headers: HeaderMap, body: String) -> Json<Value> {
    let entries: Vec<_> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    f.receipts.lock().await.push(json!({"path":"/token","authorization":headers.get("authorization").and_then(|v|v.to_str().ok()),"contentType":headers.get("content-type").and_then(|v|v.to_str().ok()),"body":entries,"raw":body}));
    Json(f.control.lock().await.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"generic-access","refresh_token":"generic-refresh","token_type":"Bearer","expires_in":3600,"scope":"profile"})))
}
async fn user(State(f): State<Fixture>) -> Json<Value> {
    Json(f.control.lock().await.get("profile").cloned().unwrap_or_else(||json!({"id":"generic-subject","email":"generic@example.invalid","name":"Generic Name","email_verified":true})))
}
