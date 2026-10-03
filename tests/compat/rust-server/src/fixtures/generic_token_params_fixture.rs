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
    GenericOAuthConfig, OAuthAuthorizationPolicy, OAuthPrivateKeyJwtOptions, OAuthProvider,
    OAuthRefreshContext, OAuthRefreshTokenHandler, OAuthRefreshTokenParams,
    OAuthRefreshTokenParamsResolver, OAuthTokenEndpointAuth, OAuthTokenSet, OAuthUserInfo,
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
struct SubjectKey {
    fixture: Fixture,
    mode: String,
}
#[async_trait::async_trait]
impl better_auth::plugins::oauth::OAuthAccountKeyResolver for SubjectKey {
    async fn resolve(
        &self,
        context: better_auth::plugins::oauth::OAuthAccountKeyContext,
    ) -> Result<Value, String> {
        tokio::task::yield_now().await;
        let tokens = json!({"accessToken":context.tokens.access_token,"refreshToken":context.tokens.refresh_token,"accessTokenExpiresAt":context.tokens.access_token_expires_at.map(|v| v.to_rfc3339_opts(chrono::SecondsFormat::Millis,true)),"scopes":context.tokens.scopes});
        self.fixture
            .receipts
            .lock()
            .await
            .push(json!({"kind":"subject","tokens":tokens,"profile":context.profile}));
        if self.mode == "subject-error" {
            return Err("subject resolver denied".into());
        }
        if self.mode == "subject-invalid" {
            return Ok(self.fixture.control.lock().await["subject"].clone());
        }
        Ok(json!(format!(
            "{}:{}:{}",
            context.tokens.access_token.unwrap_or_default(),
            context.profile["id"].as_str().unwrap(),
            context.profile["raw_claim"].as_str().unwrap()
        )))
    }
}
struct SubjectMapper;
#[async_trait::async_trait]
impl better_auth::plugins::oauth::OAuthProfileMapper for SubjectMapper {
    async fn map_profile(&self, _: Value) -> Result<serde_json::Map<String, Value>, String> {
        Ok(json!({"id":"mapped-id-must-not-own-account"})
            .as_object()
            .unwrap()
            .clone())
    }
}
struct CustomCode {
    fixture: Fixture,
    denied: bool,
}
#[async_trait::async_trait]
impl better_auth::plugins::oauth::OAuthAuthorizationCodeHandler for CustomCode {
    async fn validate_authorization_code(
        &self,
        data: better_auth::plugins::oauth::OAuthAuthorizationCodeContext,
    ) -> Result<OAuthTokenSet, String> {
        tokio::task::yield_now().await;
        self.fixture.receipts.lock().await.push(json!({"kind":"custom-token","code":data.code,"redirectURI":data.redirect_uri,"codeVerifier":data.code_verifier}));
        if self.denied {
            return Err("custom token callback denied".into());
        }
        Ok(OAuthTokenSet {
            access_token: Some("custom-access".into()),
            refresh_token: Some("custom-refresh".into()),
            scopes: vec!["custom-scope".into()],
            ..Default::default()
        })
    }
}
struct DeniedAssertion;
#[async_trait::async_trait]
impl better_auth::plugins::oauth::OAuthClientAssertionGetter for DeniedAssertion {
    async fn get_client_assertion(
        &self,
        _: better_auth::plugins::oauth::OAuthClientAssertionContext,
    ) -> Result<String, String> {
        Err("assertion getter denied".into())
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
    let mut profiles = std::collections::HashMap::new();
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
        "override",
        "expiry-positive",
        "expiry-zero",
        "expiry-negative",
        "custom-token",
        "custom-token-error",
        "jwt-RS256",
        "jwt-RS384",
        "jwt-RS512",
        "jwt-PS256",
        "jwt-PS384",
        "jwt-PS512",
        "jwt-ES256",
        "jwt-ES384",
        "jwt-ES512",
        "jwt-EdDSA",
        "jwt-pem",
        "jwt-pem-ES256",
        "jwt-pem-ES384",
        "jwt-pem-ES512",
        "jwt-pem-EdDSA",
        "jwt-both",
        "jwt-empty-kid",
        "jwt-fractional",
        "subject-key",
        "subject-error",
        "subject-invalid",
        "subject-default",
        "jwt-embedded",
        "jwt-expired",
        "jwt-bad-key",
        "jwt-padded",
        "jwt-missing-crt",
        "jwt-duplicate-ops",
        "jwt-invalid-ext",
        "jwt-secret",
        "jwt-manual",
        "jwt-getter-error",
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
        let keys: Value =
            serde_json::from_str(include_str!("../../../fixtures/client-assertion-keys.json"))
                .unwrap();
        let algorithm = mode
            .strip_prefix("jwt-pem-")
            .or_else(|| mode.strip_prefix("jwt-"))
            .filter(|a| keys.get(*a).is_some())
            .unwrap_or("RS256");
        let mut jwk = keys[algorithm]["private"].clone();
        jwk["kid"] = json!("embedded-kid");
        if mode == "jwt-embedded" {
            jwk["alg"] = json!("RS256");
        }
        if mode == "jwt-bad-key" {
            jwk["kty"] = json!("EC");
        }
        if mode == "jwt-padded" {
            jwk["n"] = json!(format!("{}==", jwk["n"].as_str().unwrap()));
        }
        if mode == "jwt-missing-crt" {
            for name in ["dp", "dq", "qi"] {
                jwk.as_object_mut().unwrap().remove(name);
            }
        }
        if mode == "jwt-duplicate-ops" {
            jwk["key_ops"] = json!(["sign", "sign"]);
        }
        if mode == "jwt-invalid-ext" {
            jwk["ext"] = json!("true");
        }
        let assertion = mode.starts_with("jwt-").then(|| {
            OAuthPrivateKeyJwtOptions {
                private_key_jwk: (!mode.starts_with("jwt-pem")).then_some(jwk),
                private_key_pem: if mode == "jwt-both" {
                    Some("invalid PEM ignored".into())
                } else {
                    mode.starts_with("jwt-pem")
                        .then(|| keys[algorithm]["pem"].as_str().unwrap().to_owned())
                },
                algorithm: (!matches!(mode, "jwt-embedded" | "jwt-pem"))
                    .then(|| algorithm.to_owned()),
                kid: (mode != "jwt-embedded").then(|| {
                    if mode == "jwt-empty-kid" {
                        ""
                    } else {
                        "configured-kid"
                    }
                    .into()
                }),
                expires_in: if mode == "jwt-expired" {
                    Some(-1.0)
                } else if mode == "jwt-fractional" {
                    Some(17.5)
                } else {
                    None
                },
            }
            .into_assertion()
            .unwrap()
        });
        let policy = OAuthAuthorizationPolicy {
            authorization_code: mode.starts_with("custom-token").then(|| {
                better_auth::plugins::oauth::OAuthAuthorizationCodeCallback(Arc::new(CustomCode {
                    fixture: fixture.clone(),
                    denied: mode == "custom-token-error",
                }))
            }),
            client_assertion: if mode == "jwt-getter-error" {
                Some(better_auth::plugins::oauth::OAuthClientAssertion(Arc::new(
                    DeniedAssertion,
                )))
            } else {
                assertion
            },
            token_endpoint_auth: if mode.starts_with("jwt-") {
                Some(OAuthTokenEndpointAuth::PrivateKeyJwt)
            } else {
                match configured_mode {
                    "manual" | "incomplete" | "default-none" | "default-post" => None,
                    "post" => Some(OAuthTokenEndpointAuth::ClientSecretPost),
                    "basic" | "basic-secret" => Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                    _ => Some(OAuthTokenEndpointAuth::None),
                }
            },
            authorization_code_params: if mode == "jwt-secret" {
                [("client_secret".into(), "forbidden-secret".into())].into()
            } else if mode == "jwt-manual" {
                [
                    ("client_assertion".into(), "manual".into()),
                    ("client_assertion_type".into(), "manual".into()),
                ]
                .into()
            } else {
                params(mode, false)
            },
            refresh_token_params: if mode == "jwt-secret" {
                [("client_secret".into(), "forbidden-secret".into())].into()
            } else if mode == "jwt-manual" {
                [
                    ("client_assertion".into(), "manual".into()),
                    ("client_assertion_type".into(), "manual".into()),
                ]
                .into()
            } else {
                params(mode, true)
            },
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
                    image: raw["picture"].as_str().map(str::to_owned),
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
            override_user_info_on_sign_in: mode == "override",
        };
        let provider = if mode.starts_with("dynamic")
            || mode == "none"
            || mode.starts_with("subject-")
            || mode.starts_with("expiry-")
            || mode.starts_with("custom-token")
        {
            let mut generic = GenericOAuthConfig::new("client :+&", secret);
            generic.authorization_url = Some(provider.auth_url.clone());
            generic.token_url = Some(provider.token_url.clone());
            generic.user_info_url = provider.user_info_url.clone();
            generic.provider = provider;
            if mode.starts_with("subject-") && mode != "subject-default" {
                generic.account_key = Some(better_auth::plugins::oauth::OAuthAccountKey(Arc::new(
                    SubjectKey {
                        fixture: fixture.clone(),
                        mode: mode.into(),
                    },
                )));
                generic.map_profile = Some(Arc::new(SubjectMapper));
            }
            generic.access_token_expires_in =
                if mode.starts_with("expiry-") || mode.starts_with("custom-token") {
                    Some(match mode {
                        "expiry-zero" => 0.0,
                        "expiry-negative" => -60.0,
                        _ => 17.0,
                    })
                } else {
                    None
                };
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
        profiles.insert(mode.to_owned(), auth.clone());
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let db = database.clone();
    router = router.route(
        "/__test/generic-token/orphan",
        post(move |Json(body): Json<Value>| {
            let db = db.clone();
            async move {
                let mut conn = db.get_sqlite_connection_pool().acquire().await.unwrap();
                sqlx::query(sqlx::AssertSqlSafe("PRAGMA foreign_keys=OFF"))
                    .execute(&mut *conn)
                    .await
                    .unwrap();
                let result = sqlx::query(sqlx::AssertSqlSafe(
                    "UPDATE accounts SET user_id='missing-owner' WHERE id=?",
                ))
                .bind(body["accountId"].as_str().unwrap())
                .execute(&mut *conn)
                .await;
                sqlx::query(sqlx::AssertSqlSafe("PRAGMA foreign_keys=ON"))
                    .execute(&mut *conn)
                    .await
                    .unwrap();
                result.unwrap();
                Json(json!({"status":true}))
            }
        }),
    );
    router = router.route(
        "/__test/generic-token/server-api",
        post(move |Json(body): Json<Value>| {
            let auth = profiles["none"].clone();
            async move {
                use axum::response::IntoResponse;
                use better_auth::plugins::oauth::{OAuthAccountApi, OAuthAccountSelection};
                let user = body["userId"].as_str().unwrap_or_default();
                let selection = OAuthAccountSelection::Id(
                    body["accountId"].as_str().unwrap_or_default().to_owned(),
                );
                let result = match body["operation"].as_str().unwrap_or_default() {
                    "get-access-token" => {
                        OAuthAccountApi::get_access_token(user, selection, auth.context()).await
                    }
                    "refresh-token" => {
                        OAuthAccountApi::refresh_token(user, selection, auth.context()).await
                    }
                    _ => OAuthAccountApi::account_info(user, selection, auth.context()).await,
                };
                let mut result = match result {
                    Ok(response) => {
                        let mut output = (
                            axum::http::StatusCode::from_u16(response.status).unwrap(),
                            response.body,
                        )
                            .into_response();
                        for (name, value) in response.headers.iter() {
                            output.headers_mut().insert(
                                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                                axum::http::HeaderValue::from_str(value).unwrap(),
                            );
                        }
                        output
                    }
                    Err(error) => error.into_response(),
                };
                result.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                result
            }
        }),
    );
    router = router.route(
        "/__test/generic-token/assertion-options",
        post(|Json(body): Json<Value>| async move {
            let mode = body["mode"].as_str().unwrap_or_default();
            let keys: Value =
                serde_json::from_str(include_str!("../../../fixtures/client-assertion-keys.json"))
                    .unwrap();
            let mut jwk = keys["RS256"]["private"].clone();
            if mode == "jwk-alg" {
                jwk["alg"] = json!("HS256");
            }
            if mode == "conflicting-alg" {
                jwk["alg"] = json!("RS384");
            }
            let options = OAuthPrivateKeyJwtOptions {
                private_key_jwk: (mode != "missing-key").then_some(jwk),
                algorithm: match mode {
                    "unsupported-alg" => Some("HS256".into()),
                    "conflicting-alg" => Some("RS256".into()),
                    _ => None,
                },
                ..Default::default()
            };
            Json(json!({"accepted":options.into_assertion().is_ok()}))
        }),
    );
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
