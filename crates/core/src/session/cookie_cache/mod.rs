//! Authenticated session cookie cache snapshots and the compact wire codec.
//!
//! The codec authenticates data; storage bypass and authoritative-read policy
//! belong to the session resolver. No database model is reconstructed here.

use crate::utils::json::JsValue;
use crate::{AdapterOutput, AdapterRecord};
pub(crate) mod date;

pub mod jwt;
pub mod runtime;

use crate::{AuthResult, AuthSession, AuthUser, SessionView, UserView};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{any::Any, fmt, sync::Arc};

/// Which actual snapshot a version callback receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheVersionSource {
    Created,
    /// Physical lookup returned genuine adapter output.
    Stored,
    Cached,
}

/// Immutable inputs to the cache version policy.
///
/// Creation exposes raw trusted adapter output. Physical findSession reads and
/// cache hits expose their already-filtered snapshots. Only the public projection
/// enters signed cookie data; cached inputs have no original database models.
#[derive(Clone)]
pub struct CacheVersionContext {
    user: UserView,
    session: SessionView,
    originals: Option<(Arc<dyn Any + Send + Sync>, Arc<dyn Any + Send + Sync>)>,
    source: CacheVersionSource,
    public_projection: Option<(UserView, SessionView)>,
    user_output: Option<AdapterOutput>,
    session_output: Option<AdapterOutput>,
}

impl fmt::Debug for CacheVersionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheVersionContext")
            .field("source", &self.source())
            .field("user", &self.user)
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl CacheVersionContext {
    /// Retain genuine stored models and their canonical view projection.
    pub fn created<U: AuthUser, T: AuthSession>(
        user: U,
        session: T,
        user_view: UserView,
        session_view: SessionView,
    ) -> Self {
        Self {
            user_output: user.adapter_snapshot().cloned(),
            session_output: session.adapter_snapshot().cloned(),
            user: user_view,
            session: session_view,
            originals: Some((Arc::new(user), Arc::new(session))),
            source: CacheVersionSource::Created,
            public_projection: None,
        }
    }
    /// A cache hit has no original database models.
    #[must_use]
    pub fn cached(user: UserView, session: SessionView) -> Self {
        Self {
            user,
            session,
            originals: None,
            source: CacheVersionSource::Cached,
            public_projection: None,
            user_output: None,
            session_output: None,
        }
    }
    pub(crate) fn stored(
        user: UserView,
        session: SessionView,
        user_output: Option<AdapterOutput>,
        session_output: Option<AdapterOutput>,
    ) -> Self {
        Self {
            user,
            session,
            originals: None,
            source: CacheVersionSource::Stored,
            public_projection: None,
            user_output,
            session_output,
        }
    }
    pub(crate) fn with_public_projection(mut self, user: UserView, session: SessionView) -> Self {
        self.public_projection = Some((user, session));
        self
    }
    pub(crate) fn public_user(&self) -> &UserView {
        self.public_projection
            .as_ref()
            .map_or(&self.user, |projection| &projection.0)
    }
    pub(crate) fn public_session(&self) -> &SessionView {
        self.public_projection
            .as_ref()
            .map_or(&self.session, |projection| &projection.1)
    }
    #[must_use]
    pub const fn source(&self) -> CacheVersionSource {
        self.source
    }
    #[must_use]
    pub const fn user(&self) -> &UserView {
        &self.user
    }
    #[must_use]
    pub const fn session(&self) -> &SessionView {
        &self.session
    }
    /// Actual callback-stage adapter values. Cache hits have no retained record;
    /// their exact values remain available through `user()` and `session()`.
    #[must_use]
    pub const fn user_output(&self) -> Option<&AdapterOutput> {
        self.user_output.as_ref()
    }
    #[must_use]
    pub const fn session_output(&self) -> Option<&AdapterOutput> {
        self.session_output.as_ref()
    }
    #[must_use]
    pub fn stored_user<T: AuthUser>(&self) -> Option<&T> {
        let original = &self.originals.as_ref()?.0;
        original.downcast_ref().or_else(|| {
            original
                .downcast_ref::<AdapterRecord<T>>()
                .map(AdapterRecord::stored)
        })
    }
    #[must_use]
    pub fn stored_session<T: AuthSession>(&self) -> Option<&T> {
        let original = &self.originals.as_ref()?.1;
        original.downcast_ref().or_else(|| {
            original
                .downcast_ref::<AdapterRecord<T>>()
                .map(AdapterRecord::stored)
        })
    }
}

/// Application-owned asynchronous cache version policy.
#[async_trait]
pub trait CookieCacheVersionResolver: Send + Sync {
    async fn resolve(&self, context: &CacheVersionContext) -> AuthResult<String>;
}

/// Immutable configured cache version; empty literals use the source default.
#[derive(Clone)]
pub enum CookieCacheVersion {
    Literal(String),
    Resolver(Arc<dyn CookieCacheVersionResolver>),
}

impl fmt::Debug for CookieCacheVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(value) => f.debug_tuple("Literal").field(value).finish(),
            Self::Resolver(_) => f.write_str("Resolver(..)"),
        }
    }
}

impl CookieCacheVersion {
    pub async fn resolve(&self, context: &CacheVersionContext) -> AuthResult<String> {
        match self {
            Self::Literal(value) => Ok(if value.is_empty() {
                "1".into()
            } else {
                value.clone()
            }),
            Self::Resolver(resolver) => resolver.resolve(context).await,
        }
    }
}

/// Verified compact cache data. The separately signed session token and both
/// expiries must still be checked before treating this as a session.
#[derive(Clone, Debug)]
pub struct CompactCache {
    pub user: UserView,
    pub session: SessionView,
    pub updated_at: f64,
    pub version: Option<String>,
    pub expires_at: f64,
}

/// Result of the authenticated envelope checks, before any storage fallback.
#[derive(Clone, Debug)]
pub enum CacheValidation {
    Invalid,
    Hit(Box<CompactCache>),
}

/// Source `maxAge || 300`, preserving fractions, negatives and infinity.
#[must_use]
pub fn effective_max_age(max_age: f64) -> f64 {
    if max_age == 0.0 || max_age.is_nan() {
        300.0
    } else {
        max_age
    }
}

/// Encode the already-filtered canonical output.
///
/// Infinite or out-of-range expiry becomes JSON null, as for an invalid
/// JavaScript Date; the reader rejects that envelope instead of pretending
/// that it expires normally.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops,
    reason = "Match JavaScript Number arithmetic and its separate rounding steps for cookie expiry"
)]
pub fn encode_compact(
    user: &UserView,
    session: &SessionView,
    version: &str,
    now_ms: i64,
    max_age: f64,
    dont_remember: bool,
    secret: &str,
) -> AuthResult<String> {
    let payload = jwt::payload(user, session, version, now_ms);
    let expiry = now_ms as f64
        + if dont_remember {
            60.0
        } else {
            effective_max_age(max_age)
        } * 1000.0;
    let expiry = if expiry.is_finite() && expiry.abs() <= 8.64e15 {
        json!(expiry.trunc())
    } else {
        Value::Null
    };
    let mut signed = payload.as_object().cloned().unwrap_or_default();
    _ = signed.insert("expiresAt".into(), expiry.clone());
    let signature = signature(secret, crate::utils::json::to_string(&signed)?.as_bytes());
    let envelope = json!({"session":payload,"expiresAt":expiry,"signature":signature});
    Ok(URL_SAFE_NO_PAD.encode(crate::utils::json::to_string(&envelope)?))
}

#[expect(clippy::expect_used, reason = "HMAC-SHA256 accepts keys of any length")]
fn signature(secret: &str, data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(data);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

// Published base64 decoding stops at the first padding byte and discards
// residual bits. It chooses one alphabet for the complete input.
pub(crate) fn decode_base64(value: &str) -> Result<Vec<u8>, &'static str> {
    let alphabet = if value.contains(['-', '_']) {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in value.bytes().take_while(|byte| *byte != b'=') {
        let digit = alphabet
            .iter()
            .position(|candidate| *candidate == byte)
            .and_then(|digit| u32::try_from(digit).ok())
            .ok_or("Invalid Base64 character")?;
        buffer = buffer.wrapping_shl(6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((buffer >> bits) & 255).map_err(|_| "Invalid Base64 byte")?);
        }
    }
    Ok(output)
}

/// Authenticate a compact envelope. Malformed data is a cache miss, allowing
/// the caller's genuine storage fallback; it never supplies an identity.
pub fn decode_compact(value: &str, secret: &str) -> Option<CompactCache> {
    decode_compact_http(value, secret).ok().flatten()
}

// HTTP preserves thrown alphabet errors; get-session maps these to its 500.
// Parse and authenticate once, before reviving the typed payload projection.
pub(crate) fn decode_compact_http(value: &str, secret: &str) -> AuthResult<Option<CompactCache>> {
    let bytes = decode_base64(value).map_err(crate::AuthError::internal)?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let Ok(parsed) = crate::utils::json::parse_value(text) else {
        return Ok(None);
    };
    let Some((payload, expires_at, signature)) = compact_envelope(&parsed) else {
        return Ok(None);
    };
    let signature = decode_base64(signature).map_err(crate::AuthError::internal)?;
    Ok(authenticate_compact(
        payload, expires_at, &signature, secret,
    ))
}

fn compact_envelope(parsed: &JsValue) -> Option<(&JsValue, f64, &str)> {
    let expires_at = parsed
        .get("expiresAt")?
        .as_f64()
        .filter(|value| value.is_finite())?;
    let signature = parsed.get("signature")?.as_str()?;
    let payload = parsed.get("session")?;
    _ = payload.as_object()?;
    Some((payload, expires_at, signature))
}

fn authenticate_compact(
    original_payload: &JsValue,
    expires_at: f64,
    signature: &[u8],
    secret: &str,
) -> Option<CompactCache> {
    let mut normalized = original_payload.clone();
    date::revive(&mut normalized);
    let mut signed = normalized.as_object()?.clone();
    _ = signed.insert("expiresAt".into(), JsValue::Number(expires_at));
    let message = crate::utils::json::to_string(&signed).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message.as_bytes());
    mac.verify_slice(signature).ok()?;
    parse_payload(original_payload, expires_at)
}

/// Validate and revive an authenticated session snapshot without granting storage authority.
pub(crate) fn parse_payload(original_payload: &JsValue, expires_at: f64) -> Option<CompactCache> {
    // Revived dates are runtime Date objects in the source. Required string
    // fields reject them even when their canonical JSON text did not change.
    for (object, required, optional) in [
        (
            original_payload.get("user")?.as_object()?,
            &["id", "email", "name"][..],
            &["image"][..],
        ),
        (
            original_payload.get("session")?.as_object()?,
            &["id", "token"][..],
            &["ipAddress", "userAgent"][..],
        ),
    ] {
        for field in required {
            let text = object.get(*field)?.as_str()?;
            if date::parse(text).is_some() {
                return None;
            }
        }
        for field in optional {
            if object
                .get(*field)
                .and_then(JsValue::as_str)
                .is_some_and(|text| date::parse(text).is_some())
            {
                return None;
            }
        }
        for field in ["createdAt", "updatedAt"] {
            if let Some(value) = object.get(field) {
                _ = date::parse(value.as_str()?)?;
            }
        }
    }
    _ = date::parse(
        original_payload
            .get("session")?
            .get("expiresAt")?
            .as_str()?,
    )?;
    if original_payload
        .get("version")
        .and_then(JsValue::as_str)
        .is_some_and(|text| date::parse(text).is_some())
    {
        return None;
    }
    let mut normalized = original_payload.clone();
    date::revive_parsed(&mut normalized);
    let payload = normalized.as_object()?;
    let updated_at = payload
        .get("updatedAt")?
        .as_f64()
        .filter(|value| value.is_finite())?;
    let version = match payload.get("version") {
        None => None,
        Some(value) => Some(value.as_str()?.to_owned()),
    };
    let mut user = payload.get("user")?.to_json_value().ok()?;
    let mut session = payload.get("session")?.to_json_value().ok()?;
    let user_id = date::coerce_id(original_payload.get("session")?.get("userId")?)?;
    _ = session
        .as_object_mut()?
        .insert("userId".into(), Value::String(user_id));
    // The source schemas supply absent creation/update dates and a false
    // emailVerified value. Producer dates are canonical JavaScript Date JSON.
    for object in [&mut user, &mut session] {
        let map = object.as_object_mut()?;
        for key in ["createdAt", "updatedAt"] {
            if !map.contains_key(key) {
                _ = map.insert(
                    key.into(),
                    json!(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
                );
            }
        }
    }
    let map = user.as_object_mut()?;
    let email = map.get("email")?.as_str()?.to_lowercase();
    _ = map.insert("email".into(), Value::String(email));
    _ = map.get("name")?.as_str()?;
    if !map.contains_key("emailVerified") {
        _ = map.insert("emailVerified".into(), Value::Bool(false));
    }
    let null_user_extensions: Vec<_> = [
        "username",
        "displayUsername",
        "twoFactorEnabled",
        "role",
        "banned",
        "banReason",
        "banExpires",
        "isAnonymous",
        "phoneNumber",
        "phoneNumberVerified",
        "lastLoginMethod",
    ]
    .into_iter()
    .filter(|name| user.get(*name).is_some_and(Value::is_null))
    .collect();
    let mut user: UserView = serde_json::from_value(user).ok()?;
    if original_payload.get("user")?.get("image").is_none() {
        _ = user.omitted_fields.insert("image".into());
    }
    for name in null_user_extensions {
        _ = user.extension_fields.insert(name.into(), Value::Null);
    }
    let null_extensions: Vec<_> = ["activeOrganizationId", "activeTeamId", "impersonatedBy"]
        .into_iter()
        .filter(|name| session.get(*name).is_some_and(Value::is_null))
        .collect();
    let mut session: SessionView = serde_json::from_value(session).ok()?;
    for name in ["ipAddress", "userAgent"] {
        if original_payload.get("session")?.get(name).is_none() {
            _ = session.omitted_fields.insert(name.into());
        }
    }
    for name in null_extensions {
        _ = session.extension_fields.insert(name.into(), Value::Null);
    }
    Some(CompactCache {
        user,
        session,
        updated_at,
        version,
        expires_at,
    })
}

/// Check the token binding, version callback, and source expiry guards.
///
/// Callback errors propagate; invalid envelopes permit storage fallback.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub async fn validate_compact(
    mut cache: CompactCache,
    token: &str,
    policy: Option<&CookieCacheVersion>,
    now_ms: i64,
) -> AuthResult<CacheValidation> {
    if cache.session.token != token {
        return Ok(CacheValidation::Invalid);
    }
    let expected = match policy {
        Some(policy) => {
            policy
                .resolve(&CacheVersionContext::cached(
                    cache.user.clone(),
                    cache.session.clone(),
                ))
                .await?
        }
        None => "1".into(),
    };
    let version = cache
        .version
        .as_deref()
        .filter(|version| !version.is_empty())
        .unwrap_or("1");
    if version != expected
        || cache.expires_at < now_ms as f64
        || cache.session.expires_at.timestamp_millis() < now_ms
    {
        return Ok(CacheValidation::Invalid);
    }
    cache.session.active = true;
    Ok(CacheValidation::Hit(Box::new(cache)))
}

/// Render a cache-related cookie using the source numeric Max-Age policy.
///
/// Negative and NaN ages omit Max-Age; nonnegative ages are floored, and
/// values above the cookie serializer's 400-day ceiling fail rather than
/// saturating. No Expires attribute is synthesized.
pub fn cookie_header(
    name: &str,
    value: &str,
    max_age: Option<f64>,
    config: &crate::AuthConfig,
) -> AuthResult<String> {
    let bases = ["session_data", "account_data"]
        .map(|logical| crate::utils::cookie_utils::related_cookie_name(config, logical));
    let base = (!bases.iter().any(|base| base == name))
        .then(|| {
            bases
                .iter()
                .find(|base| runtime::chunk_index(name, base).is_some())
        })
        .flatten();
    let encoded =
        percent_encoding::utf8_percent_encode(value, crate::utils::cookie_utils::URI_COMPONENT)
            .to_string();
    crate::utils::cookie_utils::create_numeric_cookie_header(
        name,
        base.map_or(name, String::as_str),
        &encoded,
        max_age,
        config,
    )
}
