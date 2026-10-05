//! Compromised-password policy at initialized password hashing.
use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, PasswordHashContext, PasswordHashHook,
};
use sha1::{Digest, Sha1};
use std::sync::Arc;

const DEFAULT_MESSAGE: &str =
    "The password you entered has been compromised. Please choose a different password.";
const RETRY_MESSAGE: &str = "Failed to check password. Please try again later.";
const RANGE_API: &str = "https://api.pwnedpasswords.com/range/";
const DEFAULT_PATHS: &[&str] = &[
    "/sign-up/email",
    "/change-password",
    "/reset-password",
    "/email-otp/reset-password",
    "/phone-number/reset-password",
    "/admin/create-user",
    "/admin/set-user-password",
];

/// HTTP range service. Its endpoint is trusted application configuration;
/// requests contain only five uppercase SHA-1 characters, never the password.
#[derive(Clone, Debug)]
pub struct PwnedPasswordClient {
    client: reqwest::Client,
    range_api: Option<url::Url>,
}

impl Default for PwnedPasswordClient {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            range_api: None,
        }
    }
}

impl PwnedPasswordClient {
    /// Use an application-owned range service and HTTP client.
    #[must_use]
    pub fn new(client: reqwest::Client, mut range_api: url::Url) -> Self {
        if !range_api.path().ends_with('/') {
            range_api.set_path(&format!("{}/", range_api.path()));
        }
        Self {
            client,
            range_api: Some(range_api),
        }
    }

    /// Check the original UTF-8 password before password-hash normalization.
    ///
    /// # Errors
    /// Returns the published provider status or generic retry error when the
    /// response cannot be checked, including a malformed matching count.
    pub async fn is_password_compromised(&self, password: &str) -> AuthResult<bool> {
        let digest = Sha1::digest(password.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        let (prefix, suffix) = digest.split_at(5);
        let endpoint = self
            .range_api
            .as_ref()
            .map_or_else(
                || url::Url::parse(&format!("{RANGE_API}{prefix}")),
                |base| base.join(prefix),
            )
            .map_err(|_| retry_error())?;
        let response = self
            .client
            .get(endpoint)
            .header("Add-Padding", "true")
            .header("User-Agent", "BetterAuth Password Checker")
            .send()
            .await
            .map_err(|_| retry_error())?;
        if !response.status().is_success() {
            return Err(AuthError::Api {
                status: 500,
                code: None,
                message: format!(
                    "Failed to check password. Status: {}",
                    response.status().as_u16()
                ),
            });
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default();
        // betterFetch reads JSON and text media through its JSON-or-text
        // parser. Other media becomes a blob and cannot supply suffix lines.
        if !text_response_type(content_type) {
            return Err(retry_error());
        }
        let text = response.text().await.map_err(|_| retry_error())?;
        let text = response_text(text)?;
        compromise_count(&text, suffix).map(|count| count > 0)
    }
}

fn response_text(text: String) -> AuthResult<String> {
    match better_auth_core::utils::json::parse_value(&text) {
        Ok(better_auth_core::utils::json::JsValue::String(value)) => Ok(value),
        Ok(_) => Err(retry_error()),
        Err(_) if serde_json::from_str::<serde::de::IgnoredAny>(&text).is_ok() => {
            // JavaScript permits escaped unpaired UTF-16 surrogates in JSON.
            // They cannot match the ASCII suffix/count grammar, but preceding
            // valid lines still own the result. Preserve those lines rather
            // than treating the quoted JSON envelope as a raw range response.
            let quoted = text.trim_matches([' ', '\t', '\r', '\n']);
            if !quoted.starts_with('"') {
                return Err(retry_error());
            }
            let mut units = Vec::new();
            let mut chars = quoted[1..quoted.len() - 1].chars();
            while let Some(character) = chars.next() {
                let character = if character == '\\' {
                    match chars.next().ok_or_else(retry_error)? {
                        'u' => {
                            let mut unit = 0u16;
                            for _ in 0..4 {
                                let digit = chars
                                    .next()
                                    .and_then(|digit| digit.to_digit(16))
                                    .ok_or_else(retry_error)?;
                                unit =
                                    unit * 16 + u16::try_from(digit).map_err(|_| retry_error())?;
                            }
                            units.push(unit);
                            continue;
                        }
                        'b' => '\u{8}',
                        'f' => '\u{c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        character @ ('"' | '\\' | '/') => character,
                        _ => return Err(retry_error()),
                    }
                } else {
                    character
                };
                units.extend(character.encode_utf16(&mut [0; 2]).iter().copied());
            }
            Ok(String::from_utf16_lossy(&units))
        }
        Err(_) => Ok(text),
    }
}

/// Check against the published range service without installing a plugin.
///
/// # Errors
/// Returns a provider/parsing error when the password cannot be checked.
pub async fn is_password_compromised(password: &str) -> AuthResult<bool> {
    PwnedPasswordClient::default()
        .is_password_compromised(password)
        .await
}

fn text_response_type(content_type: &str) -> bool {
    let json = content_type
        .split_once('/')
        .filter(|(media, _)| media.eq_ignore_ascii_case("application"))
        .is_some_and(|(_, subtype)| {
            subtype.eq_ignore_ascii_case("json")
                || subtype
                    .to_ascii_lowercase()
                    .strip_suffix("+json")
                    .is_some_and(|prefix| {
                        prefix.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"_!#$%&*.^`~-".contains(&byte)
                        })
                    })
        });
    content_type.is_empty()
        || json
        || content_type.starts_with("text/")
        || matches!(
            content_type,
            "image/svg" | "application/xml" | "application/xhtml" | "application/html"
        )
}

fn compromise_count(response: &str, suffix: &str) -> AuthResult<u64> {
    let matching = format!("{suffix}:");
    for line in response.split_inclusive('\n') {
        let line = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        let Some(prefix) = line.get(..matching.len()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case(&matching) {
            continue;
        }
        let count = &line[matching.len()..];
        if count.is_empty()
            || !count.bytes().all(|byte| byte.is_ascii_digit())
            || count.len() > 1 && count.starts_with('0')
        {
            return Err(retry_error());
        }
        let count: u64 = count.parse().map_err(|_| retry_error())?;
        if count > 9_007_199_254_740_991 {
            return Err(retry_error());
        }
        return Ok(count);
    }
    Ok(0)
}

fn retry_error() -> AuthError {
    AuthError::Api {
        status: 500,
        code: None,
        message: RETRY_MESSAGE.into(),
    }
}

/// Published enabled, exact-path and compromised-message settings.
#[derive(Clone, Debug)]
pub struct HaveIBeenPwnedConfig {
    pub enabled: bool,
    pub paths: Option<Vec<String>>,
    pub custom_password_compromised_message: Option<String>,
    pub client: PwnedPasswordClient,
}

impl Default for HaveIBeenPwnedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: None,
            custom_password_compromised_message: None,
            client: PwnedPasswordClient::default(),
        }
    }
}

/// Installs a password hash policy; it contributes no HTTP routes.
#[derive(Clone, Debug, Default)]
pub struct HaveIBeenPwnedPlugin {
    config: HaveIBeenPwnedConfig,
}

impl HaveIBeenPwnedPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: HaveIBeenPwnedConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PasswordHashHook for HaveIBeenPwnedPlugin {
    async fn before_hash(
        &self,
        password: &str,
        context: Option<&PasswordHashContext>,
    ) -> AuthResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let context = context.ok_or_else(|| {
            AuthError::internal("Password hashing requires an auth endpoint context")
        })?;
        let Some(path) = context.path.as_deref().filter(|path| !path.is_empty()) else {
            return Ok(());
        };
        let included = self.config.paths.as_ref().map_or_else(
            || DEFAULT_PATHS.contains(&path),
            |paths| paths.iter().any(|included| included == path),
        );
        if included && self.config.client.is_password_compromised(password).await? {
            return Err(AuthError::Api {
                status: 400,
                code: Some("PASSWORD_COMPROMISED".into()),
                message: self
                    .config
                    .custom_password_compromised_message
                    .as_deref()
                    .filter(|message| !message.is_empty())
                    .unwrap_or(DEFAULT_MESSAGE)
                    .into(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for HaveIBeenPwnedPlugin {
    fn static_openapi_metadata(&self) -> better_auth_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            &<Self as better_auth_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &better_auth_core::AuthInitContext<S>,
    ) -> better_auth_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            &<Self as better_auth_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn name(&self) -> &'static str {
        "have-i-been-pwned"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.register_password_hash_hook(Arc::new(self.clone()));
        Ok(())
    }

    async fn on_request(
        &self,
        _request: &AuthRequest,
        _context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
