//! Authenticated session cookie cache snapshots and the compact wire codec.
//!
//! The codec authenticates data; storage bypass and authoritative-read policy
//! belong to the session resolver. No database model is reconstructed here.

mod date;

pub mod runtime;

use crate::{AuthResult, AuthSession, AuthUser, SessionView, UserView};
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::fmt::Write;
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
/// Creation and physical reads expose trusted adapter output. Only the public
/// projection enters signed cookie data. Cached inputs contain that exact
/// authenticated public snapshot, without invented original models.
#[derive(Clone)]
pub struct CacheVersionContext {
    user: UserView,
    session: SessionView,
    originals: Option<(Arc<dyn Any + Send + Sync>, Arc<dyn Any + Send + Sync>)>,
    source: CacheVersionSource,
    public_projection: Option<(UserView, SessionView)>,
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
        }
    }
    pub(crate) fn stored(user: UserView, session: SessionView) -> Self {
        Self {
            user,
            session,
            originals: None,
            source: CacheVersionSource::Stored,
            public_projection: None,
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
    #[must_use]
    pub fn stored_user<T: AuthUser>(&self) -> Option<&T> {
        let original = &self.originals.as_ref()?.0;
        original.downcast_ref().or_else(|| {
            original
                .downcast_ref::<crate::AdapterRecord<T>>()
                .map(crate::AdapterRecord::stored)
        })
    }
    #[must_use]
    pub fn stored_session<T: AuthSession>(&self) -> Option<&T> {
        let original = &self.originals.as_ref()?.1;
        original.downcast_ref().or_else(|| {
            original
                .downcast_ref::<crate::AdapterRecord<T>>()
                .map(crate::AdapterRecord::stored)
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
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
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
/// Infinite or out-of-range
/// expiry becomes JSON null, as for an invalid JavaScript Date; the reader
/// rejects that envelope instead of pretending that it expires normally.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops,
    reason = "Match JavaScript Number arithmetic and its separate rounding steps for cookie expiry"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn encode_compact(
    user: &UserView,
    session: &SessionView,
    version: &str,
    now_ms: i64,
    max_age: f64,
    dont_remember: bool,
    secret: &str,
) -> AuthResult<String> {
    let payload = json!({"session":session,"user":user,"updatedAt":now_ms,"version":version});
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
    drop(signed.insert("expiresAt".into(), expiry.clone()));
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

/// Authenticate a compact envelope. Malformed data is a cache miss, allowing
/// the caller's genuine storage fallback; it never supplies an identity.
#[expect(
    clippy::too_many_lines,
    reason = "Keep compact authentication, shape validation, and date reviving in wire order"
)]
pub fn decode_compact(value: &str, secret: &str) -> Option<CompactCache> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let parsed = crate::utils::json::parse_value(text).ok()?;
    let expires_at = parsed
        .get("expiresAt")?
        .as_f64()
        .filter(|value_2| value_2.is_finite())?;
    let signature = parsed.get("signature")?.as_str()?;
    let payload = parsed.get("session")?.as_object()?;
    let original_payload = payload;
    let mut normalized = crate::utils::json::JsValue::Object(payload.clone());
    date::revive(&mut normalized);
    let payload_2 = normalized.as_object()?;
    let mut signed = payload_2.clone();
    drop(signed.insert(
        "expiresAt".into(),
        crate::utils::json::JsValue::Number(expires_at),
    ));
    let message = crate::utils::json::to_string(&signed).ok()?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .or_else(|_| URL_SAFE.decode(signature))
        .ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message.as_bytes());
    mac.verify_slice(&signature).ok()?;
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
            let text_2 = object.get(*field)?.as_str()?;
            if date::parse(text_2).is_some() {
                return None;
            }
        }
        for field in optional {
            if object
                .get(*field)
                .and_then(crate::utils::json::JsValue::as_str)
                .is_some_and(|text_3| date::parse(text_3).is_some())
            {
                return None;
            }
        }
        for field in ["createdAt", "updatedAt"] {
            if let Some(value_3) = object.get(field) {
                _ = date::parse(value_3.as_str()?)?;
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
        .and_then(crate::utils::json::JsValue::as_str)
        .is_some_and(|text_4| date::parse(text_4).is_some())
    {
        return None;
    }
    let updated_at = payload_2
        .get("updatedAt")?
        .as_f64()
        .filter(|value_4| value_4.is_finite())?;
    let version = match payload_2.get("version") {
        None => None,
        Some(value_5) => Some(value_5.as_str()?.to_owned()),
    };
    let mut user = payload_2.get("user")?.to_json_value().ok()?;
    let mut session = payload_2.get("session")?.to_json_value().ok()?;
    // The source schemas supply absent creation/update dates and a false
    // emailVerified value. Producer dates are canonical JavaScript Date JSON.
    for object in [&mut user, &mut session] {
        let map = object.as_object_mut()?;
        for key in ["createdAt", "updatedAt"] {
            if !map.contains_key(key) {
                drop(map.insert(
                    key.into(),
                    json!(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
                ));
            }
        }
    }
    let map = user.as_object_mut()?;
    let email = map.get("email")?.as_str()?.to_lowercase();
    drop(map.insert("email".into(), Value::String(email)));
    _ = map.get("name")?.as_str()?;
    if !map.contains_key("emailVerified") {
        drop(map.insert("emailVerified".into(), Value::Bool(false)));
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
    for name in null_user_extensions {
        drop(user.extension_fields.insert(name.into(), Value::Null));
    }
    let null_extensions: Vec<_> = ["activeOrganizationId", "activeTeamId", "impersonatedBy"]
        .into_iter()
        .filter(|name| session.get(*name).is_some_and(Value::is_null))
        .collect();
    let mut session: SessionView = serde_json::from_value(session).ok()?;
    for name in null_extensions {
        drop(session.extension_fields.insert(name.into(), Value::Null));
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
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
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

/// Reject selected formats that do not have a runtime implementation yet.
/// Disabling caching does not reject an otherwise-unused strategy setting.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn validate_config(config: &crate::CookieCacheConfig) -> AuthResult<()> {
    if config.enabled && config.strategy != crate::CookieCacheStrategy::Compact {
        return Err(crate::AuthError::config(
            "Only compact stateful session cookie caching is currently supported",
        ));
    }
    Ok(())
}

/// Render a cache-related cookie using the source numeric Max-Age policy.
///
/// Negative and NaN ages omit Max-Age; nonnegative ages are floored, and
/// values above the cookie serializer's 400-day ceiling fail rather than
/// saturating. No Expires attribute is synthesized.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn cookie_header(
    name: &str,
    value: &str,
    max_age: Option<f64>,
    config: &crate::AuthConfig,
) -> AuthResult<String> {
    const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'!')
        .remove(b'~')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');

    let session = &config.session;

    let encoded = percent_encoding::utf8_percent_encode(value, COMPONENT);
    let mut header = format!("{name}={encoded}");
    if let Some(age) = max_age.filter(|age| *age >= 0.0) {
        if age > 34_560_000.0 {
            return Err(crate::AuthError::internal(
                "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.",
            ));
        }
        _ = write!(header, "; Max-Age={}", age.floor());
    }
    header.push_str("; Path=/");
    if session.cookie_http_only {
        header.push_str("; HttpOnly");
    }
    if session.cookie_secure || name.starts_with("__Secure-") || name.starts_with("__Host-") {
        header.push_str("; Secure");
    }
    header.push_str(match session.cookie_same_site {
        crate::config::SameSite::Lax => "; SameSite=Lax",
        crate::config::SameSite::Strict => "; SameSite=Strict",
        crate::config::SameSite::None => "; SameSite=None",
    });
    Ok(header)
}
