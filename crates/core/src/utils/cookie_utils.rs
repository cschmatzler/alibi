//! Shared cookie utilities for building `Set-Cookie` headers.
//!
//! This module centralises the session cookie construction that was previously
//! duplicated across every plugin (`email_password`, `passkey`, `two_factor`,
//! `admin`, `password_management`, `session_management`, `email_verification`).

use crate::config::AuthConfig;
use base64::{Engine, engine::general_purpose::STANDARD};
use cookie::{Cookie, SameSite as CookieSameSite};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Build a `Set-Cookie` header value for an arbitrary cookie using the auth
/// config's session cookie attributes for consistency.
#[must_use]
pub fn create_cookie(name: &str, value: &str, max_age_seconds: i64, config: &AuthConfig) -> String {
    create_session_like_cookie(name, value, Some(max_age_seconds), config)
}

/// Build a `Set-Cookie` header value for a session token using the `cookie`
/// crate for correct formatting and escaping.
#[must_use]
pub fn create_session_cookie(token: &str, config: &AuthConfig) -> String {
    create_session_cookie_with_max_age(
        Some(token),
        Some(config.session.expires_in.num_seconds()),
        config,
    )
}

/// Build a `Set-Cookie` header value for a session token using the session
/// cookie attributes, optionally omitting `Max-Age` / `Expires` to create a
/// browser-session cookie.
#[must_use]
pub fn create_session_cookie_with_max_age(
    token: Option<&str>,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let signed = token
        .filter(|token| !token.is_empty())
        .map(|token| sign_cookie_value(token, &config.secret));
    create_session_like_cookie(
        &config.session.cookie_name,
        signed.as_deref().unwrap_or(""),
        max_age_seconds,
        config,
    )
}

/// Sign and URI-encode a cookie value using Better Call's HMAC-SHA256 encoding.
#[expect(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of every length"
)]
#[must_use]
#[expect(
    clippy::missing_panics_doc,
    reason = "HMAC accepts keys of every length, so key construction cannot fail"
)]
pub fn sign_cookie_value(value: &str, secret: &str) -> String {
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

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(value.as_bytes());
    let signed = format!("{value}.{}", STANDARD.encode(mac.finalize().into_bytes()));

    percent_encoding::utf8_percent_encode(&signed, COMPONENT).to_string()
}

/// Return a cookie's payload only when its signature verifies.
#[must_use]
pub fn verify_cookie_value(value: &str, secret: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .ok()?;
    let (payload, signature) = decoded.rsplit_once('.')?;
    let signature = STANDARD.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(payload.to_owned())
}

/// Build a `Set-Cookie` header value using the session cookie attributes for
/// an arbitrary cookie name.
#[must_use]
pub fn create_session_like_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<i64>,
    config: &AuthConfig,
) -> String {
    let session_config = &config.session;
    let same_site = map_same_site(&session_config.cookie_same_site);

    let mut cookie = Cookie::build((name, value))
        .path("/")
        .secure(session_config.cookie_secure)
        .http_only(session_config.cookie_http_only)
        .same_site(same_site);

    if let Some(max_age_seconds) = max_age_seconds {
        let expires_offset = cookie::time::OffsetDateTime::now_utc()
            + cookie::time::Duration::seconds(max_age_seconds);
        cookie = cookie
            .expires(expires_offset)
            .max_age(cookie::time::Duration::seconds(max_age_seconds));
    }

    // SameSite=None requires the Secure attribute per the spec
    if matches!(
        session_config.cookie_same_site,
        crate::config::SameSite::None
    ) {
        cookie = cookie.secure(true);
    }

    cookie.build().to_string()
}

/// Build a `Set-Cookie` header value that clears the session cookie.
#[must_use]
pub fn create_clear_session_cookie(config: &AuthConfig) -> String {
    create_clear_cookie(&config.session.cookie_name, config)
}

/// Build a `Set-Cookie` header value that clears an arbitrary cookie by name,
/// using the session config's cookie attributes for consistency.
///
/// Mirrors the TypeScript `expireCookie`, which clears a cookie with `Max-Age=0`
/// while preserving its attributes, and emits no `Expires`.
#[must_use]
pub fn create_clear_cookie(name: &str, config: &AuthConfig) -> String {
    let session_config = &config.session;
    let same_site = map_same_site(&session_config.cookie_same_site);

    let mut cookie = Cookie::build((name, ""))
        .path("/")
        .max_age(cookie::time::Duration::seconds(0))
        .http_only(session_config.cookie_http_only)
        .same_site(same_site);

    if session_config.cookie_secure
        || matches!(
            session_config.cookie_same_site,
            crate::config::SameSite::None
        )
    {
        cookie = cookie.secure(true);
    }

    cookie.build().to_string()
}

/// Build a Better Auth related cookie name using the configured session cookie
/// prefix. For example, `better-auth.session_token` + `session_data` becomes
/// `better-auth.session_data`.
#[must_use]
pub fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map_or_else(
            || format!("better-auth.{suffix}"),
            |prefix| format!("{prefix}{suffix}"),
        )
}

const fn map_same_site(s: &crate::config::SameSite) -> CookieSameSite {
    match s {
        crate::config::SameSite::Strict => CookieSameSite::Strict,
        crate::config::SameSite::Lax => CookieSameSite::Lax,
        crate::config::SameSite::None => CookieSameSite::None,
    }
}

/// Clear all cookies associated with the current session.
#[must_use]
pub fn delete_session_cookie_headers(config: &AuthConfig) -> Vec<String> {
    let mut cookies = vec![
        create_clear_session_cookie(config),
        create_clear_cookie(&related_cookie_name(config, "session_data"), config),
    ];

    if config.account.store_account_cookie {
        cookies.push(create_clear_cookie(
            &related_cookie_name(config, "account_data"),
            config,
        ));
    }

    if matches!(
        config.account.store_state_strategy,
        crate::config::OAuthStateStrategy::Cookie
    ) {
        cookies.push(create_clear_cookie(
            &related_cookie_name(config, "oauth_state"),
            config,
        ));
    }

    cookies.push(create_clear_cookie(
        &related_cookie_name(config, "dont_remember"),
        config,
    ));
    cookies
}
