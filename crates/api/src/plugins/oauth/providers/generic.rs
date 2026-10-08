//! One-time discovery from trusted application configuration, matching genericOAuth.
use super::{
    OAuthAuthorizationPolicy, OAuthIdTokenVerifier, OAuthProfileMapper, OAuthProvider,
    OAuthScopeOrder, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use crate::plugins::oauth::{HttpOAuthJwksSource, OAuthJwksSource};
use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use std::sync::Arc;

/// Discovery is an operator-configured authority, never a request-selected URL.
/// Resolve once before registering the provider with `OAuthPlugin`.
pub struct GenericOAuthConfig {
    pub provider: OAuthProvider,
    pub discovery_url: Option<String>,
    pub discovery_headers: Vec<(String, String)>,
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
                authorization_params: Vec::new(),
                account_subject: None,
                map_user_info: None,
                get_user_info: None,
                refresh_access_token: None,
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
    pub async fn resolve(mut self) -> Result<Option<GenericOAuthResolved>, GenericOAuthError> {
        let mut metadata = GenericOAuthMetadata::default();
        let mut is_oidc = false;
        let discovered = if let Some(url) = &self.discovery_url {
            fetch_discovery(url, &self.discovery_headers).await
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
                self.provider.verify_id_token = Some(Arc::new(DiscoveryVerifier {
                    keys: Arc::new(HttpOAuthJwksSource::new(url.to_string())),
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
        use super::OAuthTokenEndpointAuth::{
            ClientSecretBasic, ClientSecretPost, None as Public, PrivateKeyJwt,
        };
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
        drop(
            policy
                .configured_scopes
                .splice(0..0, std::mem::take(&mut self.provider.scopes)),
        );
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
        policy.verify_grant_id_token = metadata.jwks_url.is_some();
        policy.id_token_nonce_binding =
            policy.verify_grant_id_token && !self.disable_id_token_nonce_binding;
        policy.discovery_openid_scope = is_oidc;
        policy.source_profile_exceptions = true;
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
        if self.provider.get_user_info.is_none() {
            self.provider.get_user_info = Some(Arc::new(GenericUserInfo {
                url: self.user_info_url,
                mapper: self.map_profile,
            }));
        }
        Ok(Some(GenericOAuthResolved {
            provider: self.provider,
            metadata,
        }))
    }
}
fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}
async fn fetch_discovery(url: &str, headers: &[(String, String)]) -> Option<Value> {
    let mut request = reqwest::Client::new().get(url);
    for (key, value) in headers {
        request = request.header(key, value);
    }
    let document: Value = request
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    if let Some(issuer) = string(&document, "issuer").filter(|issuer| !issuer.is_empty())
        && url::Url::parse(&issuer).is_err()
    {
        return None;
    }
    Some(document)
}
fn oauth_subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
}
fn oidc_subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}
struct GenericUserInfo {
    url: Option<String>,
    mapper: Option<Arc<dyn OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for GenericUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        // Grant tokens have already been verified when discovery supplies keys;
        // direct client tokens are always verified by the shared admission path.
        let decoded = request
            .id_token
            .as_deref()
            .and_then(|token| token.split('.').nth(1))
            .and_then(|payload| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .ok()
            })
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|profile| {
                profile
                    .get("sub")
                    .is_some_and(super::remaining_profile::truthy)
                    && profile
                        .get("email")
                        .is_some_and(super::remaining_profile::truthy)
            });
        let mut raw = if let Some(mut profile) = decoded {
            if let Some(object) = profile.as_object_mut() {
                let id = object.get("sub").cloned().unwrap_or(Value::Null);
                let _entry = object.entry("id").or_insert(id);
                let verified = object.get("email_verified").cloned().unwrap_or(Value::Null);
                let _entry = object.entry("emailVerified").or_insert(verified);
                if let Some(image) = object.get("picture").cloned() {
                    let _entry = object.entry("image").or_insert(image);
                }
            }
            profile
        } else {
            let url = self
                .url
                .as_ref()
                .ok_or("Generic OAuth user info unavailable")?;
            let mut profile: Value = reqwest::Client::new()
                .get(url)
                .bearer_auth(request.access_token.as_deref().unwrap_or("undefined"))
                .send()
                .await
                .map_err(|_| "Generic OAuth user info unavailable")?
                .error_for_status()
                .map_err(|_| "Generic OAuth user info unavailable")?
                .json()
                .await
                .map_err(|_| "Generic OAuth user info unavailable")?;
            if let Some(object) = profile.as_object_mut() {
                drop(
                    object.insert(
                        "emailVerified".into(),
                        object
                            .get("email_verified")
                            .cloned()
                            .unwrap_or(Value::Bool(false)),
                    ),
                );
                if let Some(image) = object.get("picture").cloned() {
                    drop(object.insert("image".into(), image));
                } else {
                    drop(object.remove("image"));
                }
            }
            profile
        };
        let user = OAuthUserInfo {
            additional_fields: Default::default(),
            id: string(&raw, "id").unwrap_or_default(),
            email: string(&raw, "email").unwrap_or_default(),
            name: string(&raw, "name"),
            image: string(&raw, "image"),
            email_verified: raw
                .get("emailVerified")
                .is_some_and(super::remaining_profile::truthy),
        };
        let mut response = OAuthUserInfoResponse {
            user_output: None,
            user,
            data: raw.take(),
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
        let raw_header: Value = serde_json::from_slice(
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
                header
                    .kid
                    .as_ref()
                    .is_none_or(|kid| key.get("kid").and_then(Value::as_str) == Some(kid))
                    && key.get("d").is_none()
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
                        | Algorithm::PS512 => key.get("kty").and_then(Value::as_str) == Some("RSA"),
                        Algorithm::ES256 | Algorithm::ES384 => {
                            key.get("kty").and_then(Value::as_str) == Some("EC")
                        }
                        Algorithm::EdDSA => key.get("kty").and_then(Value::as_str) == Some("OKP"),
                        _ => false,
                    }
            })
            .collect();
        if matching.len() != 1 {
            return Some(false);
        }
        if matching.first()?.get("kty").and_then(Value::as_str) == Some("RSA")
            && !super::super::id_token::remote_rsa_public_key(matching.first()?)
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
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1)?)
                .ok()?,
        )
        .ok()?;
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
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
            && exp.as_f64()? <= now
        {
            return Some(false);
        }
        if let Some(nbf) = claims.get("nbf")
            && nbf.as_f64()? > now
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
