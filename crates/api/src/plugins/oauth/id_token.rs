//! Signature and claim verification for trusted OAuth JWKS authorities.
use super::providers::OAuthProvider;
use async_trait::async_trait;
use base64::Engine;
use better_auth_core::utils::json::{JsValue, parse_value};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Application-owned key transport/cache. Request claims never choose its URL.
#[async_trait]
pub trait OAuthJwksSource: Send + Sync {
    async fn fetch_keys(&self) -> Result<Vec<Value>, String>;
}

/// HTTP transport for an application-configured provider key authority.
pub struct HttpOAuthJwksSource {
    url: String,
    client: reqwest::Client,
}
impl HttpOAuthJwksSource {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }
}
#[async_trait]
impl OAuthJwksSource for HttpOAuthJwksSource {
    async fn fetch_keys(&self) -> Result<Vec<Value>, String> {
        let bytes = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .bytes()
            .await
            .map_err(|error| error.to_string())?;
        let data: Value =
            better_auth_core::utils::json::from_slice(&bytes).map_err(|error| error.to_string())?;
        data.get("keys")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| "Keys not found".into())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OAuthJwksSelection {
    /// Published social factories select the first returned matching key.
    First,
    /// Google's separately published One Tap helper retries matching keys.
    AllMatching,
    /// Apple matches the header key ID literally, without a truthiness fallback.
    ExactKid,
}
#[derive(Debug, Clone, Copy)]
pub enum OAuthNonceComparison {
    Exact,
    ExactOrSha256,
}

/// Trusted provider policy. An absent audience uses the current configured
/// primary/additional client IDs, so application builder updates remain effective.
#[derive(Clone)]
pub struct OAuthIdTokenConfig {
    pub issuers: Vec<String>,
    pub audience: Option<Vec<String>>,
    pub jwks_source: Arc<dyn OAuthJwksSource>,
    pub max_age_secs: u64,
    /// Fixed import algorithm, or the JWK's declared algorithm for Apple.
    pub algorithm: Option<Algorithm>,
    pub selection: OAuthJwksSelection,
    pub nonce_comparison: OAuthNonceComparison,
}
impl OAuthIdTokenConfig {
    #[must_use]
    pub fn google() -> Self {
        Self {
            issuers: vec![
                "https://accounts.google.com".into(),
                "accounts.google.com".into(),
            ],
            audience: None,
            jwks_source: Arc::new(HttpOAuthJwksSource::new(
                "https://www.googleapis.com/oauth2/v3/certs",
            )),
            max_age_secs: 3600,
            algorithm: Some(Algorithm::RS256),
            selection: OAuthJwksSelection::First,
            nonce_comparison: OAuthNonceComparison::Exact,
        }
    }
    #[must_use]
    pub fn apple() -> Self {
        Self {
            issuers: vec!["https://appleid.apple.com".into()],
            audience: None,
            jwks_source: Arc::new(HttpOAuthJwksSource::new(
                "https://appleid.apple.com/auth/keys",
            )),
            max_age_secs: 3600,
            algorithm: None,
            selection: OAuthJwksSelection::ExactKid,
            nonce_comparison: OAuthNonceComparison::ExactOrSha256,
        }
    }
}
impl std::fmt::Debug for OAuthIdTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthIdTokenConfig")
            .field("issuers", &self.issuers)
            .field("audience", &self.audience)
            .field("max_age_secs", &self.max_age_secs)
            .field("algorithm", &self.algorithm)
            .field("selection", &self.selection)
            .field("nonce_comparison", &self.nonce_comparison)
            .finish_non_exhaustive()
    }
}

pub(super) async fn verify_provider_token(
    provider: &OAuthProvider,
    token: &str,
    nonce: Option<&str>,
) -> bool {
    if provider.disable_id_token_sign_in {
        return false;
    }
    if let Some(verifier) = &provider.verify_id_token {
        return verifier
            .verify_id_token(token, nonce)
            .await
            .unwrap_or(false);
    }
    let Some(config) = &provider.id_token else {
        return false;
    };
    let mut audiences = vec![provider.client_id.clone()];
    audiences.extend(provider.additional_client_ids.clone());
    verify_jwks_token(
        token,
        config.audience.as_deref().unwrap_or(&audiences),
        nonce,
        config,
    )
    .await
    .is_some()
}

pub(in crate::plugins) async fn verify_jwks_token(
    token: &str,
    audiences: &[String],
    nonce: Option<&str>,
    config: &OAuthIdTokenConfig,
) -> Option<JsValue> {
    let parts: Vec<_> = token.split('.').collect();
    let [header_encoded, payload_encoded, signature] = parts.as_slice() else {
        return None;
    };
    let (signed, _) = token.rsplit_once('.')?;
    let raw_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_encoded)
        .ok()?;
    let header = parse_value(std::str::from_utf8(&raw_header).ok()?).ok()?;
    let _ignored_as_object = header.as_object()?;
    let algorithm: Algorithm =
        serde_json::from_value(header.get("alg")?.to_json_value().ok()?).ok()?;
    if config.algorithm.is_some_and(|fixed| fixed != algorithm) {
        return None;
    }
    let keys = config.jwks_source.fetch_keys().await.ok()?;
    let kid = header.get("kid");
    let mut selected: Vec<_> = keys
        .into_iter()
        .filter(|key| match config.selection {
            OAuthJwksSelection::ExactKid => match kid {
                None => key.get("kid").is_none(),
                Some(kid) => kid.to_json_value().ok().as_ref() == key.get("kid"),
            },
            OAuthJwksSelection::First | OAuthJwksSelection::AllMatching => {
                kid.filter(|kid| js_truthy(kid)).is_none_or(|kid| {
                    kid.as_str()
                        .is_some_and(|kid| key.get("kid").and_then(Value::as_str) == Some(kid))
                })
            }
        })
        .collect();
    if !matches!(config.selection, OAuthJwksSelection::AllMatching) {
        selected.truncate(1);
    }
    let mut public_keys = Vec::new();
    for key in selected {
        if config.algorithm.is_none() {
            let imported: Algorithm = serde_json::from_value(key.get("alg")?.clone()).ok()?;
            if imported != algorithm {
                return None;
            }
        }
        let key: jsonwebtoken::jwk::Jwk = serde_json::from_value(key).ok()?;
        public_keys.push(DecodingKey::from_jwk(&key).ok()?);
    }
    if let Some(crit) = header.get("crit") {
        let names = crit.as_array()?;
        if names.is_empty()
            || names.iter().any(|name| name.as_str() != Some("b64"))
            || header.get("b64").and_then(JsValue::as_bool) != Some(true)
        {
            return None;
        }
    }
    for key in public_keys {
        if jsonwebtoken::crypto::verify(signature, signed.as_bytes(), &key, algorithm).ok()
            == Some(true)
        {
            let raw_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload_encoded)
                .ok()?;
            let payload = parse_value(std::str::from_utf8(&raw_payload).ok()?).ok()?;
            if valid_claims(&payload, audiences, config) {
                if let Some(nonce) = nonce.filter(|value| !value.is_empty()) {
                    let claim = payload.get("nonce").and_then(JsValue::as_str)?;
                    if claim != nonce
                        && (!matches!(config.nonce_comparison, OAuthNonceComparison::ExactOrSha256)
                            || claim != format!("{:x}", Sha256::digest(nonce.as_bytes())))
                    {
                        return None;
                    }
                }
                return Some(payload);
            }
        }
    }
    None
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JWT numeric dates deliberately retain JavaScript floating point comparison"
)]
fn valid_claims(payload: &JsValue, audiences: &[String], config: &OAuthIdTokenConfig) -> bool {
    if !payload
        .get("iss")
        .and_then(JsValue::as_str)
        .is_some_and(|issuer| config.issuers.iter().any(|configured| issuer == configured))
    {
        return false;
    }
    let matches_audience = match payload.get("aud") {
        Some(JsValue::String(value)) => audiences.contains(value),
        Some(JsValue::Array(values)) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| audiences.iter().any(|audience| audience == value))
        }),
        _ => false,
    };
    if !matches_audience {
        return false;
    }
    let now = Utc::now().timestamp() as f64;
    let Some(iat) = payload
        .get("iat")
        .and_then(JsValue::as_f64)
        .filter(|value| value.is_finite())
    else {
        return false;
    };
    if iat > now || now - iat > config.max_age_secs as f64 {
        return false;
    }
    for (claim, lower_bound) in [("exp", true), ("nbf", false)] {
        if let Some(value) = payload.get(claim) {
            let Some(date) = value.as_f64() else {
                return false;
            };
            if lower_bound && date <= now || !lower_bound && date > now {
                return false;
            }
        }
    }
    true
}
fn js_truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}
