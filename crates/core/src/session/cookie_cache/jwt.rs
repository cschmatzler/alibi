//! Symmetric session-cache JWT authentication and typed snapshot decoding.
use super::CompactCache;
use crate::{AuthError, AuthResult, utils::json::JsValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Sha256, Sha384, Sha512};

/// Complete session payload before a configured signer adds protected claims.
///
/// # Errors
/// Returns a serialization error for an invalid application projection.
pub fn payload(
    user: &crate::UserView,
    session: &crate::SessionView,
    version: &str,
    now_ms: i64,
) -> AuthResult<Value> {
    Ok(json!({"session":session,"user":user,"updatedAt":now_ms,"version":version}))
}

/// Add issued-at and expiry claims with fractional seconds retained.
///
/// # Errors
/// Rejects nonfinite expiry or a nonobject payload.
pub fn time_claims(mut payload: Value, max_age: f64) -> AuthResult<Value> {
    let now = chrono::Utc::now().timestamp();
    let expiry = serde_json::Number::from(now)
        .as_f64()
        .ok_or_else(|| AuthError::internal("Invalid issued-at time"))?
        + max_age;
    if !expiry.is_finite() {
        return Err(AuthError::internal("Invalid cookie-cache expiration time"));
    }
    let claims = payload
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Invalid cookie-cache payload"))?;
    _ = claims.insert("iat".into(), json!(now));
    _ = claims.insert("exp".into(), json!(expiry));
    Ok(payload)
}

pub(crate) fn encode(payload: Value, secret: &str, max_age: f64) -> AuthResult<String> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(crate::utils::json::to_vec(&time_claims(payload, max_age)?)?)
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| AuthError::internal("Invalid signing key"))?;
    mac.update(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

pub(crate) fn decode(token: &str, secret: &str) -> Option<CompactCache> {
    let parts: Vec<_> = token.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return None;
    };
    let header_bytes = URL_SAFE_NO_PAD.decode(header).ok()?;
    let header_value: Value = serde_json::from_slice(&header_bytes).ok()?;
    if header_value.get("crit").is_some()
        || header_value
            .get("b64")
            .is_some_and(|value| value != &Value::Bool(true))
    {
        return None;
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let input = format!("{header}.{payload}");
    macro_rules! verify {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(input.as_bytes());
            mac.verify_slice(&signature).ok()?;
        }};
    }
    match header_value.get("alg")?.as_str()? {
        "HS256" => verify!(Sha256),
        "HS384" => verify!(Sha384),
        "HS512" => verify!(Sha512),
        _ => return None,
    }
    let claims: JsValue =
        crate::utils::json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    decode_payload(&claims, 0.0)
}

/// Parse a verified JWT/JWE snapshot and its registered time claims.
#[must_use]
pub fn decode_payload(claims: &JsValue, tolerance: f64) -> Option<CompactCache> {
    let now = serde_json::Number::from(chrono::Utc::now().timestamp()).as_f64()?;
    for name in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(name) {
            let value = value.as_f64().filter(|value| value.is_finite())?;
            if name == "exp" && value <= now - tolerance || name == "nbf" && value > now + tolerance
            {
                return None;
            }
        }
    }
    let expires_at = claims
        .get("exp")
        .and_then(JsValue::as_f64)
        .filter(|value| *value != 0.0)
        .map_or_else(
            || serde_json::Number::from(chrono::Utc::now().timestamp_millis()).as_f64(),
            |value| Some(value * 1000.0),
        )?;
    super::parse_payload(claims, expires_at)
}

/// Managed JWT plugin signing/verification for the core cookie-cache lifecycle.
#[async_trait::async_trait]
pub trait CookieCacheSigner<S: crate::AuthSchema>: Send + Sync {
    /// # Errors
    /// Propagates managed key resolution and signing failures.
    async fn sign(
        &self,
        payload: Value,
        max_age: f64,
        ctx: &crate::AuthContext<S>,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<String>;
    /// # Errors
    /// Invalid tokens and unavailable verification keys return `None`.
    async fn verify(&self, token: &str, ctx: &crate::AuthContext<S>) -> AuthResult<Option<Value>>;
}

/// A signer installed by the locally managed JWT plugin during initialization.
pub struct CookieCacheSignerHandle<S: crate::AuthSchema>(
    pub std::sync::Arc<dyn CookieCacheSigner<S>>,
);
