mod cloudflare;
pub use cloudflare::CloudflareOptions;

mod cognito;
pub use cognito::CognitoOptions;

mod dropbox;
pub use dropbox::{DropboxAccessType, DropboxOptions};
mod figma;
pub use figma::FigmaOptions;

mod facebook;
pub use facebook::FacebookOptions;

mod atlassian;
pub use atlassian::AtlassianOptions;

mod apple;
pub use apple::AppleOptions;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for the OAuth plugin, containing all registered providers.
#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProvider>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthTokenSet {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
}

/// User information extracted from an OAuth provider's user info endpoint.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    /// Trusted mapped application values; writes select initialized declared input fields.
    pub additional_fields: better_auth_core::field_policy::FieldOutput,
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
}

impl OAuthUserInfo {
    /// Original mapped public values. This is output, never account authority.
    #[must_use]
    pub fn public_profile(&self, include_id: bool) -> better_auth_core::field_policy::FieldOutput {
        let mut output = self.additional_fields.clone();
        drop(output.insert("email".into(), Value::String(self.email.clone())));
        drop(output.insert("emailVerified".into(), Value::Bool(self.email_verified)));
        if include_id {
            drop(output.insert("id".into(), Value::String(self.id.clone())));
        }
        if let Some(name) = &self.name {
            drop(output.insert("name".into(), Value::String(name.clone())));
        }
        if let Some(image) = &self.image {
            drop(output.insert("image".into(), Value::String(image.clone())));
        }
        output
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthCallbackUserPayload {
    pub name: Option<OAuthCallbackUserName>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthCallbackUserName {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthUserInfoRequest {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
    pub user: Option<OAuthCallbackUserPayload>,
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfoResponse {
    /// Original mapped public profile, captured before raw account-subject resolution.
    pub user_output: Option<better_auth_core::field_policy::FieldOutput>,
    pub user: OAuthUserInfo,
    pub data: Value,
}

/// Resolve a provider's stable account identity from its original profile.
pub type OAuthAccountSubject = fn(&Value) -> Result<String, String>;

#[async_trait]
pub trait OAuthUserInfoHandler: Send + Sync {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String>;
}

#[async_trait]
pub trait OAuthRefreshTokenHandler: Send + Sync {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String>;
}

#[async_trait]
pub trait OAuthIdTokenVerifier: Send + Sync {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String>;
}

#[derive(Debug, Deserialize)]
struct GitHubEmailAddress {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Clone)]
struct GitHubUserInfoHandler {
    user_url: String,
    emails_url: String,
}

impl GitHubUserInfoHandler {
    const fn new(user_url: String, emails_url: String) -> Self {
        Self {
            user_url,
            emails_url,
        }
    }

    async fn fetch_json<T: DeserializeOwned>(
        &self,
        client: &reqwest::Client,
        url: &str,
        access_token: &str,
    ) -> Result<T, String> {
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .header("User-Agent", "better-auth")
            .send()
            .await
            .map_err(|error| format!("Failed to fetch GitHub user info: {error}"))?;

        if !response.status().is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_owned());
            return Err(format!("GitHub user info request failed: {body}"));
        }

        response
            .json()
            .await
            .map_err(|error| format!("Failed to parse GitHub user info: {error}"))
    }
}

#[async_trait]
impl OAuthUserInfoHandler for GitHubUserInfoHandler {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .as_deref()
            .ok_or("Missing access token for user-info lookup")?;

        let client = reqwest::Client::new();
        let mut profile: Value = self
            .fetch_json(&client, &self.user_url, access_token)
            .await?;
        let emails = self
            .fetch_json::<Vec<GitHubEmailAddress>>(&client, &self.emails_url, access_token)
            .await
            .unwrap_or_default();

        let resolved_email = profile
            .get("email")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| {
                emails
                    .iter()
                    .find(|record| record.primary)
                    .or_else(|| emails.first())
                    .map(|record| record.email.clone())
            })
            .unwrap_or_default();

        if let Some(profile_object) = profile.as_object_mut()
            && profile_object
                .get("email")
                .and_then(Value::as_str)
                .is_none()
            && !resolved_email.is_empty()
        {
            drop(profile_object.insert("email".to_owned(), Value::String(resolved_email.clone())));
        }

        let email_verified = emails
            .iter()
            .find(|record| record.email == resolved_email)
            .is_some_and(|record| record.verified);

        let id = profile
            .get("id")
            .and_then(|value| value.as_i64().map(|value| value.to_string()))
            .or_else(|| profile.get("id").and_then(Value::as_str).map(String::from))
            .ok_or("missing id")?;

        let login = profile
            .get("login")
            .and_then(Value::as_str)
            .map(String::from);

        Ok(OAuthUserInfoResponse {
            user_output: None,
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id,
                email: resolved_email,
                name: profile
                    .get("name")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or(login),
                image: profile
                    .get("avatar_url")
                    .and_then(Value::as_str)
                    .map(String::from),
                email_verified,
            },
            data: profile,
        })
    }
}

/// Configuration for a single OAuth provider.
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Preserve independent public provider policy switches"
)]
pub struct OAuthProvider {
    pub client_id: String,
    /// Additional Google client IDs accepted when verifying ID tokens.
    pub additional_client_ids: Vec<String>,
    /// Google Workspace domain restriction, independently of authorization parameters.
    pub hosted_domain: Option<String>,
    /// Require a verified provider email before creating the authentication session.
    pub require_email_verification: bool,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: Option<String>,
    pub scopes: Vec<String>,
    /// Built-in authorization behavior. `None` preserves custom-provider behavior.
    /// `scopes` remains the provider's base scope list; this policy adds configured
    /// and request scopes in the provider's published order.
    pub authorization: Option<OAuthAuthorizationPolicy>,
    pub authorization_params: Vec<(String, String)>,
    /// Selects the factory account subject from the original provider profile.
    pub account_subject: Option<OAuthAccountSubject>,
    pub map_user_info: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    pub get_user_info: Option<Arc<dyn OAuthUserInfoHandler>>,
    pub refresh_access_token: Option<Arc<dyn OAuthRefreshTokenHandler>>,
    /// Application override takes precedence over the trusted built-in JWKS policy.
    pub verify_id_token: Option<Arc<dyn OAuthIdTokenVerifier>>,
    pub id_token: Option<super::id_token::OAuthIdTokenConfig>,
    /// Disable the complete ID-token branch, including an application verifier override.
    pub disable_id_token_sign_in: bool,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub override_user_info_on_sign_in: bool,
}

/// Ordering of configured and per-request additions to a provider's base scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthScopeOrder {
    ConfiguredThenRequested,
    RequestedThenConfigured,
}

/// Encoding of the scope query value required by a provider's authorization endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OAuthScopeEncoding {
    #[default]
    Form,
    UriComponent,
}

/// OAuth token-endpoint credential transport selected by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthTokenEndpointAuth {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

/// Immutable authorization configuration used by the built-in social providers.
/// Scope entries retain their original order and whitespace; providers may
/// opt into removing exact duplicates.
#[derive(Debug, Clone)]
pub struct OAuthAuthorizationPolicy {
    pub configured_scopes: Vec<String>,
    pub scope_encoding: OAuthScopeEncoding,
    /// Retain the first occurrence of each scope, as Cloudflare requires.
    pub deduplicate_scopes: bool,
    pub require_client_id: bool,
    /// `None` preserves the existing generic provider credential transport.
    pub token_endpoint_auth: Option<OAuthTokenEndpointAuth>,
    /// Optional application client key sent in authorization-code forms only.
    pub authorization_code_client_key: Option<String>,
    pub response_type: String,
    /// Application callback URI overrides the generated provider callback.
    pub redirect_uri: Option<String>,
    pub response_mode: Option<String>,
    pub require_client_secret: bool,
    pub login_hint: bool,
    pub disable_default_scopes: bool,
    pub scope_order: OAuthScopeOrder,
    pub pkce: bool,
    pub prompt: Option<String>,
    /// Used when `prompt` is absent or empty; Discord defaults to `none`.
    pub default_prompt: Option<String>,
    /// Discord emits this JS number only when the effective scopes contain `bot`.
    pub discord_permissions: Option<f64>,
}

impl Default for OAuthAuthorizationPolicy {
    fn default() -> Self {
        Self {
            configured_scopes: Vec::new(),
            scope_encoding: OAuthScopeEncoding::Form,
            deduplicate_scopes: false,
            require_client_id: false,
            token_endpoint_auth: None,
            authorization_code_client_key: None,
            response_type: "code".into(),
            redirect_uri: None,
            response_mode: None,
            require_client_secret: false,
            login_hint: true,
            disable_default_scopes: false,
            scope_order: OAuthScopeOrder::ConfiguredThenRequested,
            pkce: true,
            prompt: None,
            default_prompt: None,
            discord_permissions: None,
        }
    }
}

impl OAuthProvider {
    /// GitLab.com social login with the published `read_user` scope and PKCE.
    #[must_use]
    pub fn gitlab(client_id: &str, client_secret: &str) -> Self {
        Self::gitlab_with_issuer(client_id, client_secret, "https://gitlab.com")
    }

    /// GitLab social login hosted at an application-configured issuer.
    ///
    /// The issuer may include a deployment path. Repeated path slashes follow
    /// the pinned provider's endpoint construction rather than URL resolution.
    pub fn gitlab_with_issuer(client_id: &str, client_secret: &str, issuer: &str) -> Self {
        let issuer = if issuer.is_empty() {
            "https://gitlab.com"
        } else {
            issuer
        };
        Self {
            client_id: client_id.into(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.into(),
            auth_url: gitlab_endpoint(issuer, "/oauth/authorize"),
            token_url: gitlab_endpoint(issuer, "/oauth/token"),
            user_info_url: Some(gitlab_endpoint(issuer, "/api/v4/user")),
            scopes: vec!["read_user".into()],
            authorization: Some(OAuthAuthorizationPolicy::default()),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: Some(gitlab_user_info),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

    #[must_use]
    pub fn with_client_ids(mut self, client_ids: Vec<String>) -> Self {
        if let Some(policy) = self.id_token.as_mut() {
            policy.client_ids = Some(client_ids.clone());
        }
        let mut ids = client_ids.into_iter();
        self.client_id = ids.next().unwrap_or_default();
        self.additional_client_ids = ids.collect();
        self
    }

    #[must_use]
    pub fn with_hosted_domain(mut self, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        self.authorization_params.retain(|(key, _)| key != "hd");
        self.authorization_params
            .push(("hd".into(), domain.clone()));
        self.hosted_domain = Some(domain);
        self
    }

    #[must_use]
    pub const fn require_email_verification(mut self, required: bool) -> Self {
        self.require_email_verification = required;
        self
    }

    #[must_use]
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.to_owned(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_url: "https://oauth2.googleapis.com/token".to_owned(),
            user_info_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_owned()),
            scopes: vec![
                "email".to_owned(),
                "profile".to_owned(),
                "openid".to_owned(),
            ],
            authorization: Some(OAuthAuthorizationPolicy {
                require_client_secret: true,
                ..Default::default()
            }),
            authorization_params: vec![("include_granted_scopes".to_owned(), "true".to_owned())],
            account_subject: None,
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: v
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .ok_or("missing sub")?
                        .to_owned(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    name: v.get("name").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("picture").and_then(|v| v.as_str()).map(String::from),
                    email_verified: v
                        .get("email_verified")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
            }),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(super::id_token::OAuthIdTokenConfig::google()),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

    #[must_use]
    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self::github_with_endpoints(
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            "https://api.github.com/user/emails",
        )
    }

    /// Construct a GitHub provider using custom endpoints.
    ///
    /// This keeps the built-in GitHub semantics while allowing local test
    /// harnesses or GitHub Enterprise-style deployments to override the URLs.
    #[must_use]
    pub fn github_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        user_info_url: &str,
        user_emails_url: &str,
    ) -> Self {
        Self {
            client_id: client_id.to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.to_owned(),
            auth_url: auth_url.to_owned(),
            token_url: token_url.to_owned(),
            user_info_url: Some(user_info_url.to_owned()),
            scopes: vec!["read:user".to_owned(), "user:email".to_owned()],
            authorization: Some(OAuthAuthorizationPolicy::default()),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: None,
            get_user_info: Some(Arc::new(GitHubUserInfoHandler::new(
                user_info_url.to_owned(),
                user_emails_url.to_owned(),
            ))),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }

    #[must_use]
    pub fn discord(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.to_owned(),
            auth_url: "https://discord.com/api/oauth2/authorize".to_owned(),
            token_url: "https://discord.com/api/oauth2/token".to_owned(),
            user_info_url: Some("https://discord.com/api/users/@me".to_owned()),
            scopes: vec!["identify".to_owned(), "email".to_owned()],
            authorization: Some(OAuthAuthorizationPolicy {
                scope_order: OAuthScopeOrder::RequestedThenConfigured,
                pkce: false,
                default_prompt: Some("none".into()),
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: Some(discord_user_info),
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProvider").finish_non_exhaustive()
    }
}

fn gitlab_endpoint(issuer: &str, suffix: &str) -> String {
    format!("{issuer}{suffix}")
        .split("://")
        .map(|part| {
            let mut previous_slash = false;
            part.chars()
                .filter(|character| {
                    let slash = *character == '/';
                    let retain = !slash || !previous_slash;
                    previous_slash = slash;
                    retain
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("://")
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Match the public provider callback type, which owns its JSON profile"
)]
fn gitlab_user_info(profile: Value) -> Result<OAuthUserInfo, String> {
    let locked = profile.get("locked").is_some_and(|value| match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    });
    if profile.get("state").and_then(Value::as_str) != Some("active") || locked {
        return Err("GitLab account is inactive or locked".into());
    }
    let id = match profile.get("id") {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value)
            .map_err(|error| error.to_string())?,
        _ => return Err("Missing GitLab account ID".into()),
    };
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id,
        email: profile
            .get("email")
            .and_then(Value::as_str)
            .ok_or("Missing GitLab email")?
            .into(),
        name: Some(
            profile
                .get("name")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("username").filter(|value| !value.is_null()))
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        ),
        image: profile
            .get("avatar_url")
            .and_then(Value::as_str)
            .map(String::from),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Discord's normalized user fields for its declared string profile schema.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Match the public provider callback type, which owns its JSON profile"
)]
fn discord_user_info(profile: Value) -> Result<OAuthUserInfo, String> {
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing id")?;
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .ok_or("missing email")?;
    let image = if profile.get("avatar").is_some_and(Value::is_null) {
        let discriminator = profile
            .get("discriminator")
            .and_then(Value::as_str)
            .ok_or("missing discriminator")?;
        let index = if discriminator == "0" {
            // Source converts the shifted BigInt to Number before remainder.
            // This must retain f64 rounding and overflow, rather than exact mod.
            if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid Discord decimal snowflake".to_owned());
            }
            let snowflake =
                rsa::BigUint::parse_bytes(id.as_bytes(), 10).ok_or("invalid Discord snowflake")?;
            let shifted = (snowflake >> 22usize)
                .to_str_radix(10)
                .parse::<f64>()
                .map_err(|_error| "invalid Discord snowflake number")?;
            shifted % 6.0
        } else {
            // Discord's declared discriminator consists of decimal digits.
            discriminator
                .parse::<f64>()
                .map_err(|_error| "invalid Discord discriminator")?
                % 5.0
        };
        format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
    } else {
        let avatar = profile
            .get("avatar")
            .and_then(Value::as_str)
            .ok_or("missing avatar")?;
        let format = if avatar.starts_with("a_") {
            "gif"
        } else {
            "png"
        };
        format!("https://cdn.discordapp.com/avatars/{id}/{avatar}.{format}")
    };
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: id.to_owned(),
        email: email.to_owned(),
        name: Some(
            profile
                .get("global_name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .or_else(|| profile.get("username").and_then(Value::as_str))
                .unwrap_or_default()
                .to_owned(),
        ),
        image: Some(image),
        email_verified: profile
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

mod huggingface;
mod kakao;
mod kick;
mod line;
pub use huggingface::HuggingFaceOptions;
pub use kakao::KakaoOptions;
pub use kick::KickOptions;
pub use line::LineOptions;

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    async fn start_github_mock_server(
        profile: Value,
        emails: Value,
    ) -> (String, String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = std::sync::Arc::clone(&requests);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let profile = profile.clone();
                let emails = emails.clone();
                let requests_2 = std::sync::Arc::clone(&captured_requests);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(
                        (buffer)
                            .get(..read)
                            .expect("fixture contains the requested index"),
                    )
                    .to_string();
                    requests_2.lock().await.push(request.clone());

                    let (status, body) = if request.contains("/user/emails") {
                        ("200 OK", emails.to_string())
                    } else if request.contains("/user") {
                        ("200 OK", profile.to_string())
                    } else {
                        (
                            "404 Not Found",
                            serde_json::json!({ "error": "not found" }).to_string(),
                        )
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );

                    drop(stream.write_all(response.as_bytes()).await);
                    drop(stream.flush().await);
                });
            }
        });

        let base_url = format!("http://127.0.0.1:{}", addr.port());
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        (
            format!("{base_url}/user"),
            format!("{base_url}/user/emails"),
            requests,
        )
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().createAuthorizationURL default scope list.
    #[test]
    fn github_provider_uses_ts_default_scopes() {
        let provider = OAuthProvider::github("github-client-id", "github-client-secret");

        assert_eq!(
            provider.scopes,
            vec!["read:user".to_owned(), "user:email".to_owned()]
        );
        assert!(provider.get_user_info.is_some());
        assert!(provider.map_user_info.is_none());
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo fallback from profile.email to /user/emails, login fallback for name, and request headers.
    #[tokio::test]
    async fn github_provider_get_user_info_uses_email_fallback_and_login_name() {
        let (user_url, emails_url, requests) = start_github_mock_server(
            serde_json::json!({
                "id": 42,
                "login": "octocat",
                "name": null,
                "email": null,
                "avatar_url": "https://avatars.githubusercontent.com/u/42?v=4",
            }),
            serde_json::json!([
                {
                    "email": "octocat@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                },
                {
                    "email": "secondary@example.com",
                    "primary": false,
                    "verified": false,
                    "visibility": "private"
                }
            ]),
        )
        .await;

        let provider = OAuthProvider::github_with_endpoints(
            "github-client-id",
            "github-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        );
        let handler = provider.get_user_info.as_ref().unwrap();

        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(response.user.id, "42");
        assert_eq!(response.user.email, "octocat@example.com");
        assert_eq!(response.user.name.as_deref(), Some("octocat"));
        assert_eq!(
            response.user.image.as_deref(),
            Some("https://avatars.githubusercontent.com/u/42?v=4")
        );
        assert!(response.user.email_verified);
        assert_eq!(
            (*(response.data)
                .get("email")
                .expect("fixture contains the requested index")),
            serde_json::json!("octocat@example.com")
        );

        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            let lowered = request.to_ascii_lowercase();
            assert!(lowered.contains("authorization: bearer github-access-token"));
            assert!(lowered.contains("user-agent: better-auth"));
        }
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo keeps profile.email when present and resolves verified status from the matching email record.
    #[tokio::test]
    async fn github_provider_get_user_info_keeps_inline_email() {
        let (user_url, emails_url, _) = start_github_mock_server(
            serde_json::json!({
                "id": "github-inline-email",
                "login": "octocat",
                "name": "Octo Cat",
                "email": "public@example.com",
                "avatar_url": null,
            }),
            serde_json::json!([
                {
                    "email": "primary@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                },
                {
                    "email": "public@example.com",
                    "primary": false,
                    "verified": false,
                    "visibility": "public"
                }
            ]),
        )
        .await;

        let provider = OAuthProvider::github_with_endpoints(
            "github-client-id",
            "github-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        );
        let handler = provider.get_user_info.as_ref().unwrap();

        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(response.user.email, "public@example.com");
        assert_eq!(response.user.name.as_deref(), Some("Octo Cat"));
        assert!(!response.user.email_verified);
    }
}
// LCOV_EXCL_STOP

mod linkedin;
pub use linkedin::LinkedInOptions;
mod linear;
pub use linear::LinearOptions;
