//! Application-owned verifier and BotID callbacks around real CAPTCHA admission.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::Path,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::captcha::{
    BotIdConfig, BotIdVerification, CaptchaConfig, CaptchaPlugin, CaptchaProvider, CheckBotId,
    RecaptchaConfig, SiteKeyCaptchaConfig, TurnstileConfig, ValidateBotIdRequest,
};
use better_auth::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, BeforeRequestAction,
};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

const PROFILES: &[&str] = &[
    "captcha-turnstile",
    "captcha-turnstile-configured",
    "captcha-turnstile-custom",
    "captcha-turnstile-wildcard",
    "captcha-turnstile-globstar",
    "captcha-turnstile-empty",
    "captcha-turnstile-disabled",
    "captcha-turnstile-no-secret",
    "captcha-turnstile-ip-disabled",
    "captcha-turnstile-ip-custom",
    "captcha-google",
    "captcha-google-configured",
    "captcha-google-zero",
    "captcha-hcaptcha",
    "captcha-hcaptcha-sitekey",
    "captcha-captchafox",
    "captcha-captchafox-sitekey",
    "captcha-botid",
    "captcha-botid-denied",
    "captcha-botid-custom",
    "captcha-botid-throw",
    "captcha-botid-validator-throw",
    "captcha-botid-timeout",
];
type Events = Arc<Mutex<Vec<Value>>>;
struct Observer {
    name: String,
    kind: &'static str,
    events: Events,
}
#[async_trait]
impl AuthPlugin<TestSchema> for Observer {
    fn name(&self) -> &'static str {
        self.kind
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_http_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.kind != "before" {
            self.events.lock().await.push(json!({"profile":self.name,"kind":self.kind,"path":request.url().map_or(request.path(),url::Url::path),"method":format!("{:?}",request.method()).to_uppercase()}));
        }
        Ok(None)
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.kind == "before" {
            self.events
                .lock()
                .await
                .push(json!({"profile":self.name,"kind":"before","path":request.path()}));
        }
        Ok(None)
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
struct BotApplication {
    name: String,
    events: Events,
}
#[async_trait]
impl CheckBotId for BotApplication {
    async fn check(&self) -> AuthResult<BotIdVerification> {
        self.events
            .lock()
            .await
            .push(json!({"profile":self.name,"kind":"bot-check"}));
        if self.name == "captcha-botid-timeout" {
            tokio::time::sleep(std::time::Duration::from_secs(11)).await;
            self.events
                .lock()
                .await
                .push(json!({"profile":self.name,"kind":"bot-finished"}));
        }
        if self.name.ends_with("-throw") && !self.name.ends_with("validator-throw") {
            return Err(AuthError::internal("application bot check failed"));
        }
        Ok(BotIdVerification {
            is_bot: self.name != "captcha-botid",
            is_verified_bot: Some(self.name.contains("custom")),
            verified_bot_name: Some("fixture-bot".into()),
            verified_bot_category: None,
        })
    }
}
#[async_trait]
impl ValidateBotIdRequest for BotApplication {
    async fn validate(
        &self,
        request: &AuthRequest,
        verification: &BotIdVerification,
    ) -> AuthResult<bool> {
        self.events.lock().await.push(json!({"profile":self.name,"kind":"bot-validator","path":request.url().map_or(request.path(),url::Url::path),"verification":verification}));
        if self.name.ends_with("validator-throw") {
            return Err(AuthError::internal("application bot validator failed"));
        }
        Ok(verification.is_verified_bot == Some(true)
            && request.header("x-allow-verified").map(String::as_str) == Some("yes"))
    }
}

pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    port: u16,
) -> AuthResult<Router> {
    let events: Events = Arc::default();
    let mut router = Router::new();
    for &name in PROFILES {
        let provider_name = if name.contains("turnstile") {
            "cloudflare-turnstile"
        } else if name.contains("google") {
            "google-recaptcha"
        } else if name.contains("hcaptcha") {
            "hcaptcha"
        } else if name.contains("captchafox") {
            "captchafox"
        } else {
            "vercel-botid"
        };
        let url = url::Url::parse(&format!(
            "http://localhost:{port}/__test/captcha-verify/{provider_name}"
        ))
        .map_err(|error| AuthError::internal(error.to_string()))?;
        let secret = if name.ends_with("-no-secret") {
            ""
        } else {
            "fixture-captcha-secret"
        };
        let provider = match provider_name {
            "cloudflare-turnstile" => {
                let mut options = TurnstileConfig::new(secret);
                options.http.site_verify_url = Some(url);
                if name.ends_with("-configured") {
                    options.expected_action = Some("login".into());
                    options.allowed_hostnames = vec!["app.fixture.test".into()];
                }
                CaptchaProvider::CloudflareTurnstile(options)
            }
            "google-recaptcha" => {
                let mut options = RecaptchaConfig::new(secret);
                options.http.site_verify_url = Some(url);
                if name.ends_with("-configured") {
                    options.expected_action = Some("login".into());
                    options.allowed_hostnames = vec!["app.fixture.test".into()];
                }
                if name.ends_with("-zero") {
                    options.min_score = 0.0;
                }
                CaptchaProvider::GoogleRecaptcha(options)
            }
            "hcaptcha" | "captchafox" => {
                let mut options = SiteKeyCaptchaConfig::new(secret);
                options.http.site_verify_url = Some(url);
                if name.ends_with("-sitekey") {
                    options.site_key = Some("fixture-site-key".into());
                }
                if provider_name == "hcaptcha" {
                    CaptchaProvider::HCaptcha(options)
                } else {
                    CaptchaProvider::CaptchaFox(options)
                }
            }
            _ => {
                let application = Arc::new(BotApplication {
                    name: name.into(),
                    events: events.clone(),
                });
                CaptchaProvider::VercelBotId(BotIdConfig {
                    check_bot_id: application.clone(),
                    validate_request: (name.contains("custom")
                        || name.ends_with("validator-throw"))
                    .then(|| application as Arc<dyn ValidateBotIdRequest>),
                })
            }
        };
        let mut captcha = CaptchaConfig::new(provider);
        captcha.endpoints = match name {
            "captcha-turnstile-custom" => vec!["/ok".into()],
            "captcha-turnstile-wildcard" => vec!["/sign-in/*".into()],
            "captcha-turnstile-globstar" => vec!["/sign-in/**".into()],
            _ => Vec::new(),
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name.ends_with("-disabled") && name != "captcha-turnstile-ip-disabled" {
            config.disabled_paths = vec!["/sign-in/email".into()];
        }
        config.advanced.ip_address.disable_ip_tracking = name.ends_with("-ip-disabled");
        if name.ends_with("-ip-custom") {
            config.advanced.ip_address.headers = vec!["x-fixture-ip".into()];
        }
        let observer = |kind| Observer {
            name: name.into(),
            kind,
            events: events.clone(),
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::new(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(PasswordManagementPlugin::new())
                .plugin(observer("early-a"))
                .plugin(CaptchaPlugin::new(captcha))
                .plugin(observer("early-b"))
                .plugin(observer("before"))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let control = events.clone();
    let verifier = events.clone();
    Ok(router
        .route(
            "/__test/captcha-events",
            get(move || {
                let events = control.clone();
                async move { Json(std::mem::take(&mut *events.lock().await)) }
            }),
        )
        .route(
            "/__test/captcha-verify/{provider}",
            post(
                move |Path(provider): Path<String>, headers: HeaderMap, body: Bytes| {
                    verifier_response(verifier.clone(), provider, headers, body)
                },
            ),
        ))
}

async fn verifier_response(
    events: Events,
    provider: String,
    headers: HeaderMap,
    bytes: Bytes,
) -> axum::response::Response {
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let body: Value = if content_type.contains("application/json") {
        serde_json::from_str(&raw).unwrap()
    } else {
        Value::Object(
            url::form_urlencoded::parse(raw.as_bytes())
                .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                .collect(),
        )
    };
    events.lock().await.push(json!({"kind":"provider","provider":provider,"method":"POST","contentType":content_type,"rawBody":raw,"body":body}));
    let token = body["response"].as_str().unwrap_or_default();
    if token == "slow-body" {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
        tokio::spawn(async move {
            if sender
                .send(Ok(Bytes::from_static(b"{\"success\":")))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(11)).await;
            let _ = sender.send(Ok(Bytes::from_static(b"true}"))).await;
        });
        let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|chunk| (chunk, receiver))
        });
        return (
            [("content-type", "application/json")],
            axum::body::Body::from_stream(stream),
        )
            .into_response();
    }
    match token {
        "http-failure" => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(json!({"error":"fixture service failure"})),
            )
                .into_response();
        }
        "invalid-json" => {
            return ([("content-type", "application/json")], "invalid").into_response();
        }
        "null" => return Json(Value::Null).into_response(),
        "blob-json" => {
            return (
                [("content-type", "application/octet-stream")],
                "{\"success\":true}",
            )
                .into_response();
        }
        "empty-text" => return ([("content-type", "text/plain")], "").into_response(),
        "timeout" => tokio::time::sleep(std::time::Duration::from_secs(11)).await,
        _ => {}
    }
    let mut data = json!({"success":if token=="truthy-success" {json!("false")} else {json!(token!="denied")}});
    if token != "missing-action" {
        data["action"] = json!(if token == "wrong-action" {
            "logout"
        } else {
            "login"
        });
    }
    if token != "missing-host" {
        data["hostname"] = json!(if token == "wrong-host" {
            "foreign.fixture.test"
        } else {
            "app.fixture.test"
        });
    }
    if token != "v2" {
        data["score"] = match token {
            "score-text" => json!("0.1"),
            "score-null" => Value::Null,
            "low-score" => json!(0.1),
            _ => json!(0.9),
        };
    }
    Json(data).into_response()
}
