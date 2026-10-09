//! CAPTCHA admission before endpoint parsing and authentication side effects.
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    utils::{
        json::{JsValue, parse_value},
        wildcard,
    },
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_ENDPOINTS: &[&str] = &[
    "/sign-up/email",
    "/sign-in/email",
    "/request-password-reset",
];

/// Trusted application configuration for a remote verification service.
#[derive(Clone, Debug)]
pub struct CaptchaHttpOptions {
    pub secret_key: String,
    /// Override the provider endpoint, for example with an application-owned proxy.
    pub site_verify_url: Option<url::Url>,
}
impl CaptchaHttpOptions {
    #[must_use]
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            site_verify_url: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TurnstileConfig {
    pub http: CaptchaHttpOptions,
    pub expected_action: Option<String>,
    pub allowed_hostnames: Vec<String>,
}
impl TurnstileConfig {
    #[must_use]
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            http: CaptchaHttpOptions::new(secret_key),
            expected_action: None,
            allowed_hostnames: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecaptchaConfig {
    pub http: CaptchaHttpOptions,
    pub min_score: f64,
    pub expected_action: Option<String>,
    pub allowed_hostnames: Vec<String>,
}
impl RecaptchaConfig {
    #[must_use]
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            http: CaptchaHttpOptions::new(secret_key),
            min_score: 0.5,
            expected_action: None,
            allowed_hostnames: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SiteKeyCaptchaConfig {
    pub http: CaptchaHttpOptions,
    pub site_key: Option<String>,
}
impl SiteKeyCaptchaConfig {
    #[must_use]
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            http: CaptchaHttpOptions::new(secret_key),
            site_key: None,
        }
    }
}

/// Full `BotID` result retained for an application's trusted validation callback.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotIdVerification {
    pub is_bot: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_verified_bot: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_bot_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_bot_category: Option<String>,
}

#[async_trait]
pub trait CheckBotId: Send + Sync {
    async fn check(&self) -> AuthResult<BotIdVerification>;
}

#[async_trait]
pub trait ValidateBotIdRequest: Send + Sync {
    async fn validate(
        &self,
        request: &AuthRequest,
        verification: &BotIdVerification,
    ) -> AuthResult<bool>;
}

#[derive(Clone)]
pub struct BotIdConfig {
    pub check_bot_id: Arc<dyn CheckBotId>,
    pub validate_request: Option<Arc<dyn ValidateBotIdRequest>>,
}

#[derive(Clone)]
pub enum CaptchaProvider {
    CloudflareTurnstile(TurnstileConfig),
    GoogleRecaptcha(RecaptchaConfig),
    HCaptcha(SiteKeyCaptchaConfig),
    CaptchaFox(SiteKeyCaptchaConfig),
    VercelBotId(BotIdConfig),
}

#[derive(Clone)]
pub struct CaptchaConfig {
    pub provider: CaptchaProvider,
    /// An empty list protects the default signup, sign-in and password reset paths.
    /// Patterns containing `*` support segment wildcards and `**` for descendants.
    pub endpoints: Vec<String>,
}
impl CaptchaConfig {
    #[must_use]
    pub fn new(provider: CaptchaProvider) -> Self {
        Self {
            provider,
            endpoints: Vec::new(),
        }
    }
}

pub struct CaptchaPlugin {
    config: CaptchaConfig,
    client: reqwest::Client,
}
impl CaptchaPlugin {
    #[must_use]
    pub fn new(config: CaptchaConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Configure transport, proxy and TLS policy for the verification service.
    #[must_use]
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// The verdict once verification completed, or `None` when it could not.
    async fn verify(&self, request: &AuthRequest) -> Option<bool> {
        if let CaptchaProvider::VercelBotId(options) = &self.config.provider {
            return verify_bot_id(options.clone(), request.clone()).await;
        }
        let (http, endpoint) = match &self.config.provider {
            CaptchaProvider::CloudflareTurnstile(options) => (
                &options.http,
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            ),
            CaptchaProvider::GoogleRecaptcha(options) => (
                &options.http,
                "https://www.google.com/recaptcha/api/siteverify",
            ),
            CaptchaProvider::HCaptcha(options) => {
                (&options.http, "https://api.hcaptcha.com/siteverify")
            }
            CaptchaProvider::CaptchaFox(options) => {
                (&options.http, "https://api.captchafox.com/siteverify")
            }
            CaptchaProvider::VercelBotId(_) => return None,
        };
        let token = request.header("x-captcha-response")?;
        let policy = request
            .extensions()
            .get::<alibi_core::config::IpAddressConfig>();
        let ip = policy
            .map_or_else(
                || alibi_core::config::IpAddressConfig::default().resolve_ip(&request.headers),
                |policy| policy.resolve_ip(&request.headers),
            )
            .filter(|ip| !ip.is_empty());
        let endpoint = http
            .site_verify_url
            .as_ref()
            .map_or(endpoint, url::Url::as_str);
        let builder = self.client.post(endpoint);
        let builder = match &self.config.provider {
            CaptchaProvider::CloudflareTurnstile(_) => {
                #[derive(Serialize)]
                struct Body<'a> {
                    secret: &'a str,
                    response: &'a str,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    remoteip: Option<&'a str>,
                }
                builder.json(&Body {
                    secret: &http.secret_key,
                    response: token,
                    remoteip: ip.as_deref(),
                })
            }
            CaptchaProvider::GoogleRecaptcha(_)
            | CaptchaProvider::HCaptcha(_)
            | CaptchaProvider::CaptchaFox(_) => {
                let mut fields = vec![("secret", http.secret_key.as_str()), ("response", token)];
                if let CaptchaProvider::HCaptcha(options) | CaptchaProvider::CaptchaFox(options) =
                    &self.config.provider
                    && let Some(site_key) =
                        options.site_key.as_deref().filter(|key| !key.is_empty())
                {
                    fields.push(("sitekey", site_key));
                }
                if let Some(ip) = ip.as_deref() {
                    let name = if matches!(self.config.provider, CaptchaProvider::CaptchaFox(_)) {
                        "remoteIp"
                    } else {
                        "remoteip"
                    };
                    fields.push((name, ip));
                }
                builder.form(&fields)
            }
            CaptchaProvider::VercelBotId(_) => return None,
        };
        // betterFetch's abort deadline ends when response headers arrive;
        // body decoding follows independently of that timer.
        let response = tokio::time::timeout(VERIFY_TIMEOUT, builder.send())
            .await
            .ok()?
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap_or_default());
        let media_type = content_type
            .and_then(|value| value.split(';').next())
            .unwrap_or_default();
        let json_media = media_type.to_ascii_lowercase();
        let json = json_media
            .strip_prefix("application/")
            .is_some_and(|subtype| {
                subtype == "json"
                    || subtype.strip_suffix("+json").is_some_and(|prefix| {
                        prefix.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"_!#$%&*.^`~-".contains(&byte)
                        })
                    })
            });
        let text_media = media_type.starts_with("text/")
            || [
                "image/svg",
                "application/xml",
                "application/xhtml",
                "application/html",
            ]
            .contains(&media_type);
        if content_type.is_some() && !json && !text_media {
            // betterFetch returns a Blob for binary media; it cannot supply a
            // verification success field even if its bytes happen to be JSON.
            return Some(false);
        }
        let text = response.text().await.ok()?;
        // betterFetch retains invalid JSON as text, so a truthy malformed reply
        // fails verification rather than becoming a transport error.
        let data = parse_value(&text).unwrap_or_else(|_| JsValue::String(text));
        if !truthy(&data) {
            return None;
        }
        if !data.get("success").is_some_and(truthy) {
            return Some(false);
        }
        let (action, hostnames) = match &self.config.provider {
            CaptchaProvider::CloudflareTurnstile(options) => {
                (&options.expected_action, &options.allowed_hostnames)
            }
            CaptchaProvider::GoogleRecaptcha(options) => {
                if data
                    .get("score")
                    .and_then(JsValue::as_f64)
                    .is_some_and(|score| score < options.min_score)
                {
                    return Some(false);
                }
                (&options.expected_action, &options.allowed_hostnames)
            }
            CaptchaProvider::HCaptcha(_) | CaptchaProvider::CaptchaFox(_) => return Some(true),
            CaptchaProvider::VercelBotId(_) => return None,
        };
        if action
            .as_deref()
            .filter(|action| !action.is_empty())
            .is_some_and(|action| data.get("action").and_then(JsValue::as_str) != Some(action))
        {
            return Some(false);
        }
        Some(
            hostnames.is_empty()
                || data
                    .get("hostname")
                    .and_then(JsValue::as_str)
                    .is_some_and(|hostname| hostnames.iter().any(|allowed| allowed == hostname)),
        )
    }
}

async fn verify_bot_id(options: BotIdConfig, request: AuthRequest) -> Option<bool> {
    // Source races the promise without cancelling it. A detached task
    // allows a trusted application callback to finish after the deadline.
    let task = tokio::spawn(async move {
        let verification = options.check_bot_id.check().await?;
        match options.validate_request {
            Some(callback) => callback.validate(&request, &verification).await,
            None => Ok(!verification.is_bot),
        }
    });
    tokio::time::timeout(VERIFY_TIMEOUT, task)
        .await
        .ok()?
        .ok()?
        .ok()
}

fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

fn unknown_error() -> AuthResponse {
    error_response(500, "Something went wrong", "UNKNOWN_ERROR")
}

fn error_response(status: u16, message: &str, code: &str) -> AuthResponse {
    AuthResponse::text(
        status,
        format!("{{\"message\":\"{message}\",\"code\":\"{code}\"}}"),
    )
    .with_header("content-type", "application/json")
}

fn normalized_path(path: &str, base: &str) -> String {
    let path = path.strip_prefix(base).unwrap_or(path);
    let mut result = String::from("/");
    for character in path.chars() {
        if character != '/' || !result.ends_with('/') {
            result.push(character);
        }
    }
    if result.len() > 1 && result.ends_with('/') {
        _ = result.pop();
    }
    result
}

fn path_matches(pattern: &str, path: &str) -> Result<bool, regex::Error> {
    if !pattern.contains('*') {
        return Ok(pattern == path);
    }
    wildcard::compile(pattern).map(|compiled| compiled.is_match(path))
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for CaptchaPlugin {
    route_openapi_metadata!(S);

    fn name(&self) -> &'static str {
        "captcha"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_http_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let path = normalized_path(
            request.url().map_or_else(|| request.path(), url::Url::path),
            &context.config.base_path,
        );
        let protected = if self.config.endpoints.is_empty() {
            DEFAULT_ENDPOINTS.iter().any(|endpoint| *endpoint == path)
        } else {
            let mut matched = false;
            for endpoint in &self.config.endpoints {
                match path_matches(endpoint, &path) {
                    Ok(true) => {
                        matched = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(_) => return Ok(Some(unknown_error())),
                }
            }
            matched
        };
        if !protected {
            return Ok(None);
        }
        let secret = match &self.config.provider {
            CaptchaProvider::CloudflareTurnstile(options) => Some(&options.http.secret_key),
            CaptchaProvider::GoogleRecaptcha(options) => Some(&options.http.secret_key),
            CaptchaProvider::HCaptcha(options) | CaptchaProvider::CaptchaFox(options) => {
                Some(&options.http.secret_key)
            }
            CaptchaProvider::VercelBotId(_) => None,
        };
        if secret.is_some_and(String::is_empty) {
            return Ok(Some(unknown_error()));
        }
        if secret.is_some()
            && request
                .header("x-captcha-response")
                .is_none_or(String::is_empty)
        {
            return Ok(Some(error_response(
                400,
                "Missing CAPTCHA response",
                "MISSING_RESPONSE",
            )));
        }
        Ok(match self.verify(request).await {
            Some(true) => None,
            Some(false) => Some(error_response(
                403,
                "Captcha verification failed",
                "VERIFICATION_FAILED",
            )),
            None => Some(unknown_error()),
        })
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
