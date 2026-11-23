//! One-time discovery from trusted application configuration, matching genericOAuth.
use super::OAuthTokenEndpointAuth::{
    ClientSecretBasic, ClientSecretPost, None as Public, PrivateKeyJwt,
};
use super::{
    OAuthAuthorizationPolicy, OAuthIdTokenVerifier, OAuthProfileMapper, OAuthProvider,
    OAuthScopeOrder, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::id_token::{CLOCK_TOLERANCE_SECS, REQUIRED_CLAIMS};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use crate::oauth::{HttpOAuthJwksSource, OAuthJwksSource};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Discovery is an operator-configured authority, never a request-selected URL.
/// Resolve once before registering the provider with `OAuthPlugin`, or register
/// the configuration with `OAuthPlugin::add_generic_provider` to retry discovery
/// that fails at startup.
#[derive(Clone)]
pub struct GenericOAuthConfig {
    pub provider: OAuthProvider,
    pub discovery_url: Option<String>,
    /// Sent on the discovery request, and on the JWKS request when `jwks_uri`
    /// has the discovery URL's origin. When set, discovery follows redirects
    /// only within that origin and fails on a redirect to another origin.
    pub discovery_headers: Vec<(String, String)>,
    /// Sent on token endpoint requests: the authorization code exchange and
    /// token refresh. Client authentication replaces a same-named header.
    pub authorization_headers: Vec<(String, String)>,
    /// `None` permits discovery; `Some`, including empty, retains the override.
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub user_info_url: Option<String>,
    pub end_session_endpoint: Option<String>,
    /// Default return URI, resolved against the auth base URL at sign-out.
    pub post_logout_redirect_uri: Option<String>,
    /// Keep local sign-out without a provider logout URL.
    pub disable_provider_logout: bool,
    pub require_id_token_verification: bool,
    pub disable_id_token_nonce_binding: bool,
    pub map_profile: Option<Arc<dyn OAuthProfileMapper>>,
    /// Fallback expiry in seconds when a default or custom grant omits it.
    pub access_token_expires_in: Option<f64>,
    pub account_key: Option<super::OAuthAccountKey>,
}
/// Metadata retained independently from the chosen endpoint overrides.
#[derive(Debug, Clone, Default)]
pub struct GenericOAuthMetadata {
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
    pub signing_algorithms: Vec<String>,
    pub end_session_endpoint: Option<String>,
}
pub struct GenericOAuthResolved {
    pub provider: OAuthProvider,
    pub metadata: GenericOAuthMetadata,
}
/// Configuration failures contain no operator endpoints or transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericOAuthError {
    RequiredVerificationUnavailable,
    InvalidTokenAuthentication,
}
impl std::fmt::Display for GenericOAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RequiredVerificationUnavailable => {
                "Generic OAuth requires discovery ID-token verification metadata"
            }
            Self::InvalidTokenAuthentication => {
                "Generic OAuth token authentication conflicts with configured credentials"
            }
        })
    }
}
impl std::error::Error for GenericOAuthError {}
impl GenericOAuthConfig {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            provider: OAuthProvider {
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                additional_client_ids: Vec::new(),
                hosted_domain: None,
                require_email_verification: false,
                auth_url: String::new(),
                token_url: String::new(),
                user_info_url: None,
                scopes: Vec::new(),
                authorization: Some(OAuthAuthorizationPolicy {
                    scope_order: OAuthScopeOrder::RequestedThenConfigured,
                    ..Default::default()
                }),
                allowed_request_params: Vec::new(),
                authorization_params: Vec::new(),
                account_subject: None,
                map_user_info: None,
                get_user_info: None,
                refresh_access_token: None,
                get_account_fields: None,
                verify_id_token: None,
                id_token: None,
                disable_id_token_sign_in: false,
                disable_implicit_sign_up: false,
                disable_sign_up: false,
                allow_idp_initiated: false,
                override_user_info_on_sign_in: false,
            },
            discovery_url: None,
            discovery_headers: Vec::new(),
            authorization_headers: Vec::new(),
            authorization_url: None,
            token_url: None,
            user_info_url: None,
            end_session_endpoint: None,
            post_logout_redirect_uri: None,
            disable_provider_logout: false,
            require_id_token_verification: false,
            disable_id_token_nonce_binding: false,
            map_profile: None,
            access_token_expires_in: None,
            account_key: None,
        }
    }
    /// Failed discovery falls back to configured endpoints. `Ok(None)` skips an
    /// unusable discovered provider, as the published initialization does.
    pub async fn resolve(self) -> Result<Option<GenericOAuthResolved>, GenericOAuthError> {
        self.resolve_within(None).await
    }
    async fn resolve_within(
        mut self,
        timeout: Option<Duration>,
    ) -> Result<Option<GenericOAuthResolved>, GenericOAuthError> {
        let mut metadata = GenericOAuthMetadata::default();
        let mut is_oidc = false;
        let discovered = if let Some(url) = &self.discovery_url {
            fetch_discovery(url, &self.discovery_headers, timeout).await
        } else {
            None
        };
        if let Some(document) = &discovered {
            self.authorization_url = self
                .authorization_url
                .or_else(|| string(document, "authorization_endpoint"));
            self.token_url = self
                .token_url
                .or_else(|| string(document, "token_endpoint"));
            self.user_info_url = self
                .user_info_url
                .or_else(|| string(document, "userinfo_endpoint"));
            metadata.issuer = string(document, "issuer");
            is_oidc = document
                .get("id_token_signing_alg_values_supported")
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty());
            metadata.signing_algorithms = document
                .get("id_token_signing_alg_values_supported")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            metadata.end_session_endpoint = self
                .end_session_endpoint
                .or_else(|| string(document, "end_session_endpoint"));
            if let (Some(jwks), Some(issuer)) = (string(document, "jwks_uri"), &metadata.issuer)
                && !jwks.is_empty()
                && !issuer.is_empty()
            {
                let Ok(base) = url::Url::parse(self.discovery_url.as_deref().unwrap_or_default())
                else {
                    return Ok(None);
                };
                let Ok(url) = base.join(&jwks) else {
                    return Ok(None);
                };
                metadata.jwks_url = Some(url.to_string());
                // The JWKS fetch refuses redirects, so these headers stay on the discovery origin.
                let mut keys = HttpOAuthJwksSource::new(url.to_string());
                if url.origin() == base.origin() {
                    keys = keys.with_headers(self.discovery_headers.clone());
                }
                self.provider.verify_id_token = Some(Arc::new(DiscoveryVerifier {
                    keys: Arc::new(keys),
                    issuer: issuer.clone(),
                    audience: self.provider.client_id.clone(),
                    algorithms: is_oidc.then(|| metadata.signing_algorithms.clone()),
                }));
            }
        } else {
            metadata.end_session_endpoint = self.end_session_endpoint;
        }
        let policy = self
            .provider
            .authorization
            .get_or_insert_with(Default::default);
        if self.account_key.is_some() {
            policy.account_key = self.account_key;
        }
        policy.allow_missing_access_token = true;
        policy.default_access_token_expires_in = self.access_token_expires_in;
        policy
            .authorization_code_headers
            .extend(self.authorization_headers.iter().cloned());
        policy
            .refresh_token_headers
            .extend(std::mem::take(&mut self.authorization_headers));
        if self.discovery_url.is_some()
            && (self.authorization_url.as_ref().is_none_or(String::is_empty)
                || self.token_url.as_ref().is_none_or(String::is_empty)
                    && policy.authorization_code.is_none())
        {
            return Ok(None);
        }
        if self.require_id_token_verification && metadata.jwks_url.is_none() {
            return if self.discovery_url.is_some() {
                Ok(None)
            } else {
                Err(GenericOAuthError::RequiredVerificationUnavailable)
            };
        }
        if matches!(policy.token_endpoint_auth, Some(Public | PrivateKeyJwt))
            && !self.provider.client_secret.is_empty()
            || matches!(
                policy.token_endpoint_auth,
                Some(ClientSecretBasic | ClientSecretPost)
            ) && self.provider.client_secret.is_empty()
        {
            return Err(GenericOAuthError::InvalidTokenAuthentication);
        }
        // Generic OAuth merges request scopes before its configured scopes.
        policy.scope_order = OAuthScopeOrder::RequestedThenConfigured;
        _ = policy
            .configured_scopes
            .splice(0..0, std::mem::take(&mut self.provider.scopes));
        policy.end_session = if self.disable_provider_logout {
            None
        } else {
            metadata
                .end_session_endpoint
                .clone()
                .map(|endpoint| super::OAuthEndSessionConfig {
                    endpoint,
                    post_logout_redirect_uri: self.post_logout_redirect_uri,
                })
        };
        policy.issuer.clone_from(&metadata.issuer);
        policy.verify_grant_id_token = metadata.jwks_url.is_some();
        policy.id_token_nonce_binding =
            policy.verify_grant_id_token && !self.disable_id_token_nonce_binding;
        policy.discovery_openid_scope = is_oidc;
        policy.source_profile_exceptions = true;
        policy.require_client_id = true;
        policy.preserve_raw_profile_scalars = true;
        policy.preserve_raw_email_errors = true;
        self.provider.auth_url = self.authorization_url.unwrap_or_default();
        self.provider.token_url = self.token_url.unwrap_or_default();
        self.provider.user_info_url.clone_from(&self.user_info_url);
        if self.provider.account_subject.is_none() {
            self.provider.account_subject = Some(if policy.discovery_openid_scope {
                oidc_subject
            } else {
                oauth_subject
            });
        }
        {
            let custom = self.provider.get_user_info.take();
            self.provider.get_user_info = Some(Arc::new(GenericUserInfo {
                url: self.user_info_url,
                mapper: self.map_profile,
                custom,
                verified_oidc: metadata.jwks_url.is_some(),
            }));
        }
        Ok(Some(GenericOAuthResolved {
            provider: self.provider,
            metadata,
        }))
    }
}
/// A request waits on a discovery retry, so bound it.
const DISCOVERY_RETRY_TIMEOUT: Duration = Duration::from_secs(10);

/// A generic provider skipped because its startup discovery left it unusable.
pub(crate) struct DeferredDiscovery {
    config: GenericOAuthConfig,
    provider: OnceLock<OAuthProvider>,
}
impl Clone for DeferredDiscovery {
    fn clone(&self) -> Self {
        let clone = Self::new(self.config.clone());
        if let Some(provider) = self.provider.get() {
            _ = clone.provider.set(provider.clone());
        }
        clone
    }
}
impl DeferredDiscovery {
    pub(crate) fn new(config: GenericOAuthConfig) -> Self {
        Self {
            config,
            provider: OnceLock::new(),
        }
    }
    pub(crate) fn provider(&self) -> Option<&OAuthProvider> {
        self.provider.get()
    }
    pub(crate) async fn retry(&self) {
        if self.provider.get().is_some() {
            return;
        }
        if let Ok(Some(resolved)) = self
            .config
            .clone()
            .resolve_within(Some(DISCOVERY_RETRY_TIMEOUT))
            .await
        {
            _ = self.provider.set(resolved.provider);
        }
    }
}
fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(Into::into)
}
/// Redirects followed within the discovery origin when `discoveryHeaders` are set.
const MAX_DISCOVERY_REDIRECTS: usize = 5;

async fn fetch_discovery(
    url: &str,
    headers: &[(String, String)],
    timeout: Option<Duration>,
) -> Option<Value> {
    let response = if headers.is_empty() {
        let mut request = reqwest::Client::new().get(url);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        request.send().await.ok()?
    } else {
        fetch_discovery_on_origin(url, headers, timeout).await?
    };
    if !response.status().is_success() {
        return None;
    }
    let document: Value = response.profile_json().await.ok()?;
    if let Some(issuer) = string(&document, "issuer").filter(|issuer| !issuer.is_empty())
        && url::Url::parse(&issuer).is_err()
    {
        return None;
    }
    Some(document)
}

/// An HTTP client forwards custom headers across cross-origin redirects, so
/// redirects are followed here, and only within the configured origin.
async fn fetch_discovery_on_origin(
    url: &str,
    headers: &[(String, String)],
    timeout: Option<Duration>,
) -> Option<reqwest::Response> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let mut target = url::Url::parse(url).ok()?;
    let origin = target.origin();
    let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    for hop in 0..=MAX_DISCOVERY_REDIRECTS {
        let mut request = client.get(target.clone());
        if let Some(deadline) = deadline {
            request =
                request.timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));
        }
        for (key, value) in headers {
            request = request.header(key, value);
        }
        let response = request.send().await.ok()?;
        if !response.status().is_redirection() {
            return Some(response);
        }
        // A redirect without a usable target is a failed discovery response.
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)?
            .to_str()
            .ok()?;
        let next = target.join(location).ok()?;
        if next.origin() != origin {
            tracing::error!(
                "discovery redirected to {}; with discoveryHeaders set, only same-origin redirects are followed. Set discoveryUrl to the final URL.",
                next.origin().ascii_serialization()
            );
            return None;
        }
        if hop >= MAX_DISCOVERY_REDIRECTS {
            tracing::error!(
                "discovery redirected more than {MAX_DISCOVERY_REDIRECTS} times. Set discoveryUrl to the final URL."
            );
            return None;
        }
        target = next;
    }
    None
}
fn oauth_subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
}
fn oidc_subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}
struct GenericUserInfo {
    url: Option<String>,
    mapper: Option<Arc<dyn OAuthProfileMapper>>,
    custom: Option<Arc<dyn OAuthUserInfoHandler>>,
    verified_oidc: bool,
}
#[async_trait]
impl OAuthUserInfoHandler for GenericUserInfo {
    async fn get_user_info_from_id_token(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        self.get_user_info(OAuthUserInfoRequest {
            id_token: request.id_token,
            ..Default::default()
        })
        .await
    }
    fn errors_are_exceptions(&self) -> bool {
        false
    }
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        // Grant tokens have already been verified when discovery supplies keys;
        // direct client tokens are always verified by the shared admission path.
        let claims = request
            .id_token
            .as_deref()
            .and_then(|token| super::remaining_profile::decode_grant_jwt(token).ok());
        if self.verified_oidc && request.id_token.is_some() && claims.is_none() {
            return Err("Invalid provider ID token claims".into());
        }
        let expected_sub = self
            .verified_oidc
            .then(|| {
                claims
                    .as_ref()
                    .and_then(|claims| claims.get("sub"))
                    .cloned()
            })
            .flatten();
        if let Some(custom) = &self.custom {
            let mut response = custom
                .get_user_info(request)
                .await
                .map_err(super::remaining_profile::profile_exception)?;
            if let Some(expected) = expected_sub
                && response
                    .data
                    .get("sub")
                    .filter(|sub| !sub.is_null())
                    .is_some_and(|sub| {
                        super::remaining_profile::js_string(sub).ok()
                            != expected.as_js_string().cloned()
                    })
            {
                return Err("UserInfo subject mismatch".into());
            }
            if let Some(mapper) = &self.mapper {
                let mapped = mapper
                    .map_profile(response.data.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?;
                super::apply_application_mapping(&mut response, mapped)?;
            }
            if response.user.get("image").is_some_and(Value::is_null) {
                _ = response.user.insert("image".into(), Value::Undefined);
            }
            return Ok(response);
        }
        let decoded = claims.filter(|profile| {
            profile
                .get("sub")
                .is_some_and(super::remaining_profile::truthy)
                && profile
                    .get("email")
                    .is_some_and(super::remaining_profile::truthy)
        });
        let raw = if let Some(mut profile) = decoded {
            if let Some(object) = profile.as_object_mut() {
                let id = object.get("sub").cloned().unwrap_or(Value::Null);
                _ = object.entry("id".into()).or_insert(id);
                let verified =
                    Value::Bool(super::email_verified_claim(object.get("email_verified")));
                _ = object.entry("emailVerified".into()).or_insert(verified);
                if let Some(image) = object.get("picture").cloned() {
                    _ = object.entry("image".into()).or_insert(image);
                }
            }
            profile
        } else {
            let url = self
                .url
                .as_ref()
                .ok_or("Generic OAuth user info unavailable")?;
            if !super::remaining_profile::has_access_token(&request) {
                return Err("Generic OAuth user info unavailable".into());
            }
            let access_token = super::remaining_profile::bearer_access_token(&request)?;
            let profile: Value = reqwest::Client::new()
                .get(url)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|_| "Generic OAuth user info unavailable")?
                .error_for_status()
                .map_err(|_| "Generic OAuth user info unavailable")?
                .profile_json()
                .await
                .map_err(|_| "Generic OAuth user info unavailable")?;
            if !super::remaining_profile::truthy(&profile) {
                return Err("Generic OAuth user info unavailable".into());
            }
            let mut object = super::remaining_profile::object_spread(profile.clone());
            for (source, target) in [("email", "email"), ("picture", "image"), ("name", "name")] {
                _ = object.insert(
                    target.into(),
                    profile
                        .property(source)
                        .map_err(super::remaining_profile::profile_exception)?,
                );
            }
            _ = object.insert(
                "emailVerified".into(),
                Value::Bool(super::email_verified_claim(profile.get("email_verified"))),
            );
            Value::Object(object)
        };
        if let Some(expected) = expected_sub
            && raw
                .get("sub")
                .map_or_else(
                    || Ok("undefined".into()),
                    super::remaining_profile::js_string,
                )
                .ok()
                != expected.as_js_string().cloned()
        {
            return Err("UserInfo subject mismatch".into());
        }
        let mut output: Map = ["email", "name", "image"]
            .into_iter()
            .map(|key| {
                (
                    key.into(),
                    raw.get(key).cloned().unwrap_or(Value::Undefined),
                )
            })
            .collect();
        _ = output.insert(
            "emailVerified".into(),
            Value::Bool(super::email_verified_claim(raw.get("emailVerified"))),
        );
        let mut response = OAuthUserInfoResponse {
            user: output,
            data: raw,
            account_subject: None,
        };
        if let Some(mapper) = &self.mapper {
            let mapped = mapper
                .map_profile(response.data.clone())
                .await
                .map_err(|_| {
                    format!(
                        "{}Generic OAuth mapping failed",
                        super::remaining_profile::PROFILE_EXCEPTION_PREFIX
                    )
                })?;
            super::apply_application_mapping(&mut response, mapped)?;
        }
        if response.user.get("image").is_some_and(Value::is_null) {
            _ = response.user.insert("image".into(), Value::Undefined);
        }
        Ok(response)
    }
}
struct DiscoveryVerifier {
    keys: Arc<dyn OAuthJwksSource>,
    issuer: String,
    audience: String,
    algorithms: Option<Vec<String>>,
}
#[async_trait]
impl OAuthIdTokenVerifier for DiscoveryVerifier {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String> {
        Ok(self.verify(token, nonce).await.unwrap_or(false))
    }
}
impl DiscoveryVerifier {
    async fn verify(&self, token: &str, nonce: Option<&str>) -> Option<bool> {
        let header = jsonwebtoken::decode_header(token).ok()?;
        let alg_name = serde_json::to_value(header.alg).ok()?;
        if self.algorithms.as_ref().is_some_and(|algorithms| {
            !algorithms
                .iter()
                .any(|alg| Some(alg.as_str()) == alg_name.as_str())
        }) {
            return Some(false);
        }
        // Remote discovery keys are public verification keys, never HMAC secrets.
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Some(false);
        }
        let raw_header: Value = alibi_core::utils::json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').next()?)
                .ok()?,
        )
        .ok()?;
        if let Some(critical) = raw_header.get("crit") {
            let names = critical.as_array()?;
            if names.is_empty()
                || names.iter().any(|name| name.as_str() != Some("b64"))
                || raw_header.get("b64").and_then(Value::as_bool) != Some(true)
            {
                return Some(false);
            }
        }
        let keys = self.keys.fetch_keys().await.ok()?;
        let matching: Vec<_> = keys
            .iter()
            .filter(|key| {
                header.kid.as_ref().is_none_or(|kid| {
                    key.get("kid").and_then(serde_json::Value::as_str) == Some(kid)
                }) && key.get("d").is_none()
                    && key.get("alg").is_none_or(|alg| alg == &alg_name)
                    && key
                        .get("use")
                        .is_none_or(|usage| usage.as_str() == Some("sig"))
                    && key.get("key_ops").is_none_or(|ops| {
                        ops.as_array().is_some_and(|ops| {
                            ops.iter().any(|op| op.as_str() == Some("verify"))
                                && ops.iter().enumerate().all(|(index, op)| {
                                    op.is_string()
                                        && ops.iter().take(index).all(|previous| previous != op)
                                })
                        })
                    })
                    && match header.alg {
                        Algorithm::RS256
                        | Algorithm::RS384
                        | Algorithm::RS512
                        | Algorithm::PS256
                        | Algorithm::PS384
                        | Algorithm::PS512 => {
                            key.get("kty").and_then(serde_json::Value::as_str) == Some("RSA")
                        }
                        Algorithm::ES256 | Algorithm::ES384 => {
                            key.get("kty").and_then(serde_json::Value::as_str) == Some("EC")
                        }
                        Algorithm::EdDSA => {
                            key.get("kty").and_then(serde_json::Value::as_str) == Some("OKP")
                        }
                        _ => false,
                    }
            })
            .collect();
        if matching.len() != 1 {
            return Some(false);
        }
        if matching
            .first()?
            .get("kty")
            .and_then(serde_json::Value::as_str)
            == Some("RSA")
            && !crate::oauth::id_token::remote_rsa_public_key(matching.first()?)
        {
            return Some(false);
        }
        let jwk =
            serde_json::from_value::<jsonwebtoken::jwk::Jwk>((*matching.first()?).clone()).ok()?;
        let key = DecodingKey::from_jwk(&jwk).ok()?;
        let (signed, signature) = token.rsplit_once('.')?;
        if !jsonwebtoken::crypto::verify(signature, signed.as_bytes(), &key, header.alg).ok()? {
            return Some(false);
        }
        let claims: Value = alibi_core::utils::json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1)?)
                .ok()?,
        )
        .ok()?;
        if REQUIRED_CLAIMS
            .iter()
            .any(|claim| claims.get(claim).is_none())
            || claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str())
        {
            return Some(false);
        }
        let audience = claims.get("aud")?;
        if audience.as_str() != Some(self.audience.as_str())
            && !audience.as_array().is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some(self.audience.as_str()))
            })
        {
            return Some(false);
        }
        if claims.get("iat").is_some_and(|iat| !iat.is_number()) {
            return Some(false);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs_f64();
        if let Some(exp) = claims.get("exp")
            && exp.as_f64()? <= now - CLOCK_TOLERANCE_SECS
        {
            return Some(false);
        }
        if let Some(nbf) = claims.get("nbf")
            && nbf.as_f64()? > now + CLOCK_TOLERANCE_SECS
        {
            return Some(false);
        }
        Some(
            nonce
                .filter(|nonce| !nonce.is_empty())
                .is_none_or(|nonce| claims.get("nonce").and_then(Value::as_str) == Some(nonce)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::OAuthUserInfo;

    fn id_token(claims: Value) -> String {
        format!(
            "e30.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    struct UndefinedMapper;
    #[async_trait]
    impl OAuthProfileMapper for UndefinedMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            let fields = profile.as_object().unwrap();
            for name in ["email", "image", "name"] {
                assert_eq!(fields.get(name), Some(&Value::Undefined), "{name}");
            }
            assert_eq!(fields.get("emailVerified"), Some(&Value::Bool(false)));
            assert_eq!(fields["0"], "é");
            assert_eq!(fields["1"].as_js_string().unwrap().code_units(), &[0xd83d]);
            assert_eq!(fields["2"].as_js_string().unwrap().code_units(), &[0xde00]);
            Ok([("image".into(), Value::Null)].into_iter().collect())
        }
    }
    #[tokio::test]
    async fn generic_mapper_retains_own_undefined_and_utf16_spread() {
        let handler = GenericUserInfo {
            url: Some(
                crate::test_helpers::serve_json_once(Value::String("é😀".into()).to_string())
                    .await
                    .0,
            ),
            mapper: Some(Arc::new(UndefinedMapper)),
            custom: None,
            verified_oidc: false,
        };
        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        for name in ["email", "name", "image"] {
            assert_eq!(response.user.get(name), Some(&Value::Undefined), "{name}");
        }
        let bytes = alibi_core::utils::json::stringify(&Value::Object(response.user))
            .unwrap()
            .unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert!(!wire.contains("image"));
        assert!(!wire.contains("name"));
    }

    struct CustomProfile(bool);
    #[async_trait]
    impl OAuthUserInfoHandler for CustomProfile {
        async fn get_user_info(
            &self,
            _: OAuthUserInfoRequest,
        ) -> Result<OAuthUserInfoResponse, String> {
            if self.0 {
                return Err("custom profile failed".into());
            }
            Ok(OAuthUserInfoResponse {
                account_subject: None,
                user: (OAuthUserInfo {
                    additional_fields: Map::new(),
                    id: "user".into(),
                    email: "a@example.com".into(),
                    name: None,
                    image: None,
                    email_verified: false,
                })
                .public_profile(true),
                data: crate::oauth::providers::js!({"id":"user", "email":"a@example.com"}),
            })
        }
    }
    struct ImageMapper(Value);
    #[async_trait]
    impl OAuthProfileMapper for ImageMapper {
        async fn map_profile(&self, _: Value) -> Result<Map, String> {
            Ok(Map::from_iter([("image".into(), self.0.clone())]))
        }
    }

    #[tokio::test]
    async fn generic_user_info_preserves_raw_bearer_values() {
        for token in [
            crate::oauth::providers::js!(42),
            crate::oauth::providers::js!(true),
            crate::oauth::providers::js!(["access", "token"]),
        ] {
            let (url, request) = crate::test_helpers::serve_json_capturing_request(
                r#"{"id":"subject","email":"a@example.com"}"#,
            )
            .await;
            let handler = GenericUserInfo {
                url: Some(url),
                mapper: None,
                custom: None,
                verified_oidc: false,
            };
            let response = handler
                .get_user_info(OAuthUserInfoRequest {
                    raw: Some(crate::oauth::providers::js!({"access_token":token})),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(response.user["email"], "a@example.com");
            let request = request.await.unwrap();
            let authorization = request
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("authorization"))
                        .map(|(_, value)| value.trim())
                })
                .unwrap();
            assert_eq!(
                authorization,
                format!(
                    "Bearer {}",
                    super::super::remaining_profile::js_string(&token)
                        .unwrap()
                        .to_utf8()
                        .unwrap()
                )
            );
        }
        let handler = GenericUserInfo {
            url: Some("http://127.0.0.1:1".into()),
            mapper: None,
            custom: None,
            verified_oidc: false,
        };
        assert!(
            handler
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("typed-access".into()),
                    raw: Some(crate::oauth::providers::js!({"access_token":false})),
                    ..Default::default()
                })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn generic_profiles_spread_truthy_payloads() {
        for (profile, expected) in [
            (
                crate::oauth::providers::js!(42),
                crate::oauth::providers::js!({"emailVerified":false}),
            ),
            (
                crate::oauth::providers::js!(true),
                crate::oauth::providers::js!({"emailVerified":false}),
            ),
            (
                crate::oauth::providers::js!(["a", 2]),
                crate::oauth::providers::js!({"0":"a", "1":2, "emailVerified":false}),
            ),
            (
                crate::oauth::providers::js!("ab"),
                crate::oauth::providers::js!({"0":"a", "1":"b", "emailVerified":false}),
            ),
        ] {
            let handler = GenericUserInfo {
                url: Some(
                    crate::test_helpers::serve_json_once(profile.to_string())
                        .await
                        .0,
                ),
                mapper: None,
                custom: None,
                verified_oidc: false,
            };
            let response = handler
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(
                response.data.to_json_value().unwrap(),
                expected.to_json_value().unwrap()
            );
            for field in ["email", "image", "name"] {
                assert_eq!(response.data.get(field), Some(&Value::Undefined));
            }
        }
    }

    #[tokio::test]
    async fn generic_falsy_fetched_profiles_skip_mapping() {
        for profile in [
            Value::Null,
            Value::Bool(false),
            crate::oauth::providers::js!(0),
            crate::oauth::providers::js!(""),
        ] {
            let handler = GenericUserInfo {
                url: Some(
                    crate::test_helpers::serve_json_once(profile.to_string())
                        .await
                        .0,
                ),
                mapper: Some(Arc::new(FailingMapper)),
                custom: None,
                verified_oidc: false,
            };
            let error = handler
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert_eq!(error, "Generic OAuth user info unavailable");
        }
    }

    #[tokio::test]
    async fn generic_mapped_null_images_are_omitted() {
        for custom in [false, true] {
            for image in [
                Value::Null,
                Value::Bool(false),
                Value::String(String::new().into()),
            ] {
                let handler = GenericUserInfo {
                    url: None,
                    mapper: Some(Arc::new(ImageMapper(image.clone()))),
                    custom: custom
                        .then(|| Arc::new(CustomProfile(false)) as Arc<dyn OAuthUserInfoHandler>),
                    verified_oidc: false,
                };
                let response = handler.get_user_info(OAuthUserInfoRequest {
                    id_token: Some(id_token(crate::oauth::providers::js!({"sub":"subject", "email":"a@example.com", "picture":"original"}))),
                    ..Default::default()
                }).await.unwrap();
                let output = response.user.clone();
                let expected = if image.is_null() {
                    &Value::Undefined
                } else {
                    &image
                };
                assert_eq!(output.get("image"), Some(expected));
                let wire = Value::Object(output).to_json_value().unwrap();
                assert_eq!(
                    wire.get("image"),
                    (!image.is_null())
                        .then(|| image.to_json_value().unwrap())
                        .as_ref()
                );
            }
        }
    }

    struct FailingMapper;
    #[async_trait]
    impl OAuthProfileMapper for FailingMapper {
        async fn map_profile(&self, _: Value) -> Result<Map, String> {
            Err("custom mapper failed".into())
        }
    }

    #[tokio::test]
    async fn generic_default_profiles_preserve_public_scalars_without_ids() {
        let handler = GenericUserInfo {
            url: None,
            mapper: None,
            custom: None,
            verified_oidc: false,
        };
        let response = handler.get_user_info(OAuthUserInfoRequest {
            id_token: Some(id_token(crate::oauth::providers::js!({"sub":"subject", "email":"a@example.com", "name":42, "picture":false}))),
            ..Default::default()
        }).await.unwrap();
        assert_eq!(response.user, crate::oauth::providers::js!({"email":"a@example.com", "emailVerified":false, "name":42, "image":false}).as_object().unwrap().clone());
        let provider = GenericOAuthConfig::new("client", "secret")
            .resolve()
            .await
            .unwrap()
            .unwrap()
            .provider;
        let policy = provider.authorization.unwrap();
        assert!(policy.preserve_raw_profile_scalars);
        assert!(policy.preserve_raw_email_errors);
    }

    #[tokio::test]
    async fn generic_custom_callback_failures_are_profile_exceptions() {
        for fail_profile in [true, false] {
            let mut config = GenericOAuthConfig::new("client", "secret");
            config.provider.get_user_info = Some(Arc::new(CustomProfile(fail_profile)));
            if !fail_profile {
                config.map_profile = Some(Arc::new(FailingMapper));
            }
            let provider = config.resolve().await.unwrap().unwrap().provider;
            let error = crate::oauth::handlers::fetch_user_info_from_provider(
                &provider,
                OAuthUserInfoRequest::default(),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, alibi_core::AuthError::Api { status: 500, code: Some(code), .. } if code == "OAUTH_PROFILE_EXCEPTION")
            );
        }
    }

    #[tokio::test]
    async fn generic_profile_aliases_normalize_email_verification() {
        for (value, expected) in [
            (Value::Null, false),
            (crate::oauth::providers::js!(false), false),
            (crate::oauth::providers::js!(true), true),
            (crate::oauth::providers::js!("true"), true),
            (crate::oauth::providers::js!("false"), false),
            (crate::oauth::providers::js!(1), false),
        ] {
            let profile = crate::oauth::providers::js!({"sub":"subject", "email":"a@example.com", "email_verified": value});
            let handler = GenericUserInfo {
                url: Some(
                    crate::test_helpers::serve_json_once(profile.clone().to_string())
                        .await
                        .0,
                ),
                mapper: None,
                custom: None,
                verified_oidc: false,
            };
            let fetched = handler
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let decoded = handler
                .get_user_info(OAuthUserInfoRequest {
                    id_token: Some(id_token(profile)),
                    ..Default::default()
                })
                .await
                .unwrap();
            for response in [fetched, decoded] {
                assert_eq!(response.data["emailVerified"], Value::Bool(expected));
                assert_eq!(
                    response
                        .user
                        .get("emailVerified")
                        .is_some_and(Value::is_truthy),
                    expected
                );
            }
        }
    }

    type Route = Arc<dyn Fn(&str) -> (u16, Option<String>, String) + Send + Sync>;

    async fn request_head(stream: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt as _;
        let mut head = Vec::new();
        while !head.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut buffer = [0; 1024];
            let count = stream.read(&mut buffer).await.unwrap_or(0);
            if count == 0 {
                break;
            }
            head.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8_lossy(&head).to_ascii_lowercase()
    }

    /// Serves `route` and records each request head.
    async fn recording_server(
        route: impl Fn(&str, &str) -> (u16, Option<String>, String) + Send + Sync + 'static,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let origin = base.clone();
        let route: Route = Arc::new(move |path| route(&origin, path));
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let head = request_head(&mut stream).await;
                recorded.lock().unwrap().push(head.clone());
                let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
                let (status, location, body) = route(&path);
                let location = location
                    .map(|location| format!("Location: {location}\r\n"))
                    .unwrap_or_default();
                _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Test\r\n{location}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        (base, requests)
    }

    fn document(issuer: &str, jwks: &str) -> String {
        crate::oauth::providers::js!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": jwks,
            "id_token_signing_alg_values_supported": ["RS256"],
        })
        .to_string()
    }

    fn with_header(requests: &std::sync::Mutex<Vec<String>>, path: &str) -> Vec<bool> {
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|head| head.starts_with(&format!("get {path} ")))
            .map(|head| head.contains("x-discovery: configured"))
            .collect()
    }

    async fn resolve_with_headers(discovery_url: String) -> Option<OAuthProvider> {
        let mut config = GenericOAuthConfig::new("client", "secret");
        config.discovery_url = Some(discovery_url);
        config.discovery_headers = vec![("X-Discovery".into(), "configured".into())];
        config.resolve().await.unwrap().map(|resolved| resolved.provider)
    }

    // Upstream: plugins/generic-oauth/generic-oauth.test.ts (#12179).
    #[tokio::test]
    async fn discovery_headers_reach_same_origin_keys_only() {
        // A signed-looking token whose header lets the verifier fetch the keys.
        let token = format!(
            "{}.e30.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#)
        );
        let (other, other_requests) =
            recording_server(|_, _| (200, None, r#"{"keys":[]}"#.into())).await;
        for cross_origin in [false, true] {
            let jwks = if cross_origin {
                format!("{other}/keys")
            } else {
                "/keys".into()
            };
            let (base, requests) = recording_server(move |origin, path| match path {
                "/.well-known/openid-configuration" => (200, None, document(origin, &jwks)),
                _ => (200, None, r#"{"keys":[]}"#.into()),
            })
            .await;
            let provider =
                resolve_with_headers(format!("{base}/.well-known/openid-configuration"))
                    .await
                    .unwrap();
            assert_eq!(
                with_header(&requests, "/.well-known/openid-configuration"),
                [true]
            );
            assert!(
                !provider
                    .verify_id_token
                    .as_ref()
                    .unwrap()
                    .verify_id_token(&token, None)
                    .await
                    .unwrap()
            );
            if cross_origin {
                assert_eq!(with_header(&other_requests, "/keys"), [false]);
            } else {
                assert_eq!(with_header(&requests, "/keys"), [true]);
            }
        }
    }

    #[tokio::test]
    async fn discovery_headers_follow_redirects_only_within_the_discovery_origin() {
        let (other, other_requests) = recording_server(|origin, _| {
            (200, None, document(origin, "/keys"))
        })
        .await;
        let (base, requests) = recording_server(move |origin, path| match path {
            "/start" => (302, Some("/next".into()), String::new()),
            "/next" => (307, Some(format!("{origin}/final")), String::new()),
            "/final" => (200, None, document(origin, "/keys")),
            "/away" => (302, Some(format!("{other}/final")), String::new()),
            "/loop" => (302, Some("/loop".into()), String::new()),
            _ => (404, None, String::new()),
        })
        .await;
        assert!(resolve_with_headers(format!("{base}/start")).await.is_some());
        assert_eq!(with_header(&requests, "/final"), [true]);

        assert!(resolve_with_headers(format!("{base}/away")).await.is_none());
        assert!(other_requests.lock().unwrap().is_empty());

        assert!(resolve_with_headers(format!("{base}/loop")).await.is_none());
        assert_eq!(with_header(&requests, "/loop").len(), MAX_DISCOVERY_REDIRECTS + 1);
    }

    // Upstream #12395 allows a second request to recover while the first is waiting.
    #[tokio::test]
    async fn deferred_discovery_retries_independently_and_keeps_the_first_success() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let mut config = GenericOAuthConfig::new("client", "secret");
        config.discovery_url = Some(format!("{origin}/discovery"));
        let deferred = Arc::new(DeferredDiscovery::new(config));
        let first_attempt = {
            let deferred = deferred.clone();
            tokio::spawn(async move { deferred.retry().await })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut first, _) = listener.accept().await.unwrap();
            assert!(request_head(&mut first).await.starts_with("get /discovery "));
            let respond = async {
                let (mut second, _) = listener.accept().await.unwrap();
                assert!(request_head(&mut second).await.starts_with("get /discovery "));
                let body = document(&origin, "/keys");
                second.write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes()).await.unwrap();
                second.shutdown().await.unwrap();
            };
            tokio::join!(deferred.retry(), respond);
            assert_eq!(deferred.provider().unwrap().auth_url, format!("{origin}/authorize"));
            assert!(!first_attempt.is_finished());
            let body = document(&origin, "/keys").replace("/authorize", "/late-authorize");
            first.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ).as_bytes()).await.unwrap();
            first.shutdown().await.unwrap();
            first_attempt.await.unwrap();
            assert_eq!(deferred.provider().unwrap().auth_url, format!("{origin}/authorize"));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn generic_user_info_requires_jws_claims() {
        let handler = GenericUserInfo {
            url: None,
            mapper: None,
            custom: None,
            verified_oidc: false,
        };
        let token =
            id_token(crate::oauth::providers::js!({"sub":"subject", "email":"a@example.com"}));
        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                id_token: Some(token.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!response.user.contains_key("id"));
        assert_eq!(response.data["sub"], "subject");
        for malformed in [
            token.rsplit_once('.').unwrap().0.to_owned(),
            format!("{token}.extra"),
            id_token(crate::oauth::providers::js!([])),
        ] {
            assert!(
                handler
                    .get_user_info(OAuthUserInfoRequest {
                        id_token: Some(malformed),
                        ..Default::default()
                    })
                    .await
                    .is_err()
            );
        }
    }
}
