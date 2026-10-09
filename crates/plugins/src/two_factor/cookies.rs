use super::*;
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(in crate::two_factor) fn cookie_expiry(
    seconds: f64,
) -> AuthResult<chrono::DateTime<Utc>> {
    let milliseconds = seconds.mul_add(1000.0, Utc::now().timestamp_millis() as f64);
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(AuthError::internal("Invalid two-factor cookie expiry"));
    }
    chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or_else(|| AuthError::internal("Invalid two-factor cookie expiry"))
}

pub(in crate::two_factor) fn two_factor_cookie_max_age(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> f64 {
    ctx.extensions
        .get::<TwoFactorCookiePolicy>()
        .map(|policy| policy.challenge_max_age)
        .or_else(|| {
            ctx.get_metadata(METADATA_TWO_FACTOR_COOKIE_MAX_AGE)
                .and_then(serde_json::Value::as_f64)
        })
        .unwrap_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)
}

pub(in crate::two_factor) fn trust_device_max_age(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> f64 {
    ctx.extensions
        .get::<TwoFactorCookiePolicy>()
        .map(|policy| policy.trust_max_age)
        .or_else(|| {
            ctx.get_metadata(METADATA_TRUST_DEVICE_MAX_AGE)
                .and_then(serde_json::Value::as_f64)
        })
        .unwrap_or(DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)
}

pub(in crate::two_factor) fn create_session_cookie_for_dont_remember(
    token: &str,
    dont_remember: bool,
    config: &alibi_core::AuthConfig,
) -> AuthResult<String> {
    if dont_remember {
        create_session_cookie_with_max_age(Some(token), None, config)
    } else {
        create_session_cookie(token, config)
    }
}

pub(in crate::two_factor) fn clear_cookie_header(
    config: &alibi_core::AuthConfig,
    suffix: &str,
) -> AuthResult<String> {
    create_clear_cookie(&related_cookie_name(config, suffix), config)
}

pub(in crate::two_factor) async fn create_trust_device_cookie_header(
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<String> {
    let identifier = format!("trust-device-{}", uuid::Uuid::new_v4());
    let token = sign_value(
        ctx.config.current_secret(),
        &format!("{}!{}", user.id(), identifier),
    )?;
    let value = format!("{token}!{identifier}");
    let expires_at = cookie_expiry(trust_device_max_age(ctx))?;
    drop(
        ctx.verifications()
            .create(CreateVerification {
                identifier: identifier.clone(),
                value: user.id().to_string(),
                expires_at,
            })
            .await?,
    );
    create_signed_cookie_header(
        ctx.config.current_secret(),
        &ctx.config,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &value,
        Some(trust_device_max_age(ctx)),
    )
}

pub(in crate::two_factor) fn create_signed_cookie_header(
    secret: &str,
    config: &alibi_core::AuthConfig,
    suffix: &str,
    value: &str,
    max_age_seconds: Option<f64>,
) -> AuthResult<String> {
    let cookie_name = related_cookie_name(config, suffix);
    let signed_value = sign_cookie_value(secret, value);
    alibi_core::utils::cookie_utils::create_cookie_with_max_age(
        &cookie_name,
        &signed_value,
        max_age_seconds,
        config,
    )
}

// Match Better Call's separately trimmed key, retaining the first duplicate
// even when its value is empty or invalid. Value decoding belongs to the
// signed proof reader so failed URI decoding retains the original value.
pub(in crate::two_factor) fn get_factor_cookie(
    req: &AuthRequest,
    name: &str,
) -> Option<String> {
    req.headers.get("cookie")?.split(';').find_map(|cookie| {
        let (key, value) = cookie.split_once('=')?;
        (key.trim() == name).then(|| value.to_owned())
    })
}

pub(in crate::two_factor) fn read_signed_cookie<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    suffix: &str,
    ctx: &AuthContext<S>,
) -> Option<String> {
    let cookie_name = related_cookie_name(&ctx.config, suffix);
    let raw_cookie = get_factor_cookie(req, &cookie_name)?;
    verify_factor_cookie_value(ctx.config.current_secret(), &raw_cookie)
}

// Better Call requires a nonempty payload and a 44-character padded outer
// signature, while its atob accepts unused trailing Base64 bits. Keep this
// source-specific decoder local to factor proofs; other cookie owners retain
// their shared decoder. HMAC verification remains constant-time.
pub(in crate::two_factor) fn verify_factor_cookie_value(
    secret: &str,
    signed_value: &str,
) -> Option<String> {
    use base64::engine::{GeneralPurpose, GeneralPurposeConfig};

    // Better Call trims/unwraps the first cookie and leaves the complete
    // original value unchanged when decodeURIComponent fails.
    let signed_value = signed_value.trim();
    let signed_value = if signed_value.starts_with('"') {
        signed_value.get(1..signed_value.len().checked_sub(1)?)?
    } else {
        signed_value
    };
    let decoded = decode_factor_cookie(signed_value);
    let (payload, signature) = decoded.rsplit_once('.')?;
    if payload.is_empty() || signature.len() != 44 || !signature.ends_with('=') {
        return None;
    }
    let signature = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
    .decode(signature)
    .ok()?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(payload.to_owned())
}

// decodeURIComponent rejects the whole value on either malformed escapes or
// invalid UTF-8, rather than partially decoding an authenticated payload.
pub(in crate::two_factor) fn decode_factor_cookie(
    value: &str,
) -> std::borrow::Cow<'_, str> {
    let bytes = value.as_bytes();
    let malformed = bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'%'
            && !bytes
                .get(index + 1..index + 3)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
    });
    if malformed {
        return std::borrow::Cow::Borrowed(value);
    }
    urlencoding::decode(value).unwrap_or(std::borrow::Cow::Borrowed(value))
}

pub(in crate::two_factor) fn sign_cookie_value(secret: &str, value: &str) -> String {
    alibi_core::utils::cookie_utils::sign_cookie_value(value, secret)
}

pub(in crate::two_factor) fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {error}")))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}
