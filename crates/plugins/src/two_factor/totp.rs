use super::*;
pub(in crate::two_factor) async fn get_totp_uri_core(
    body: &GetTotpUriInput,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<TotpUriOutput> {
    require_totp_enabled(config)?;
    let two_factor = load_two_factor_record(user, ctx).await?;
    let secret = decrypt_value(&ctx.config, two_factor.secret())?;
    enrollment::check_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config
            .totp_allow_passwordless
            .unwrap_or(config.allow_passwordless),
    )
    .await?;
    let issuer = config
        .totp_issuer
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&ctx.config.app_name);
    Ok(TotpUriOutput {
        totp_uri: totp_uri(
            config,
            &secret,
            issuer,
            user.email().unwrap_or("user"),
            false,
        )?,
    })
}

pub(in crate::two_factor) async fn verify_totp_core(
    req: &impl alibi_core::session::SessionRequest,
    body: &VerifyTotpInput,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<(SessionTokenResponse<UserView>, Vec<String>), TotpVerificationError> {
    require_totp_enabled(config)?;
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(&state.user(), ctx).await?;
    let pending = matches!(state, ResolvedTwoFactorState::Pending(_));
    if pending && two_factor.verified() == Some(false) {
        return Err(AuthError::bad_request("TOTP not enabled").into());
    }
    if pending {
        assert_account_not_locked(config, &two_factor, ctx).await?;
    }
    let attempt = begin_factor_attempt(&state, ctx).await?;
    let checked = (|| {
        let secret = decrypt_value(&ctx.config, two_factor.secret())?;
        let counter = totp_counter(config);
        let mut matched = false;
        // Source evaluates every window entry even after a match.
        for offset in [-1.0, 0.0, 1.0] {
            let expected = generate_totp_at(config, &secret, counter, offset)
                .map_err(|_error| TotpVerificationError::InvalidGeneration)?;
            matched |= constant_time_totp_equal(&body.code, &expected);
        }
        Ok::<_, TotpVerificationError>(matched)
    })();
    let valid = match checked {
        Ok(valid) => valid,
        Err(error) => {
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(error);
        }
    };

    if !valid {
        rearm_factor_attempt(attempt.as_ref(), true, ctx).await;
        if pending {
            record_account_failure(config, &two_factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid code").into());
    }
    if pending {
        reset_account_failures(config, &two_factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            let result = Box::pin(verify_existing_session_factor(
                user,
                *session,
                two_factor.verified() != Some(true),
                false,
                ctx,
            ))
            .await
            .map_err(|error| match error {
                ExistingSessionFactorError::SessionCreationCancelled => {
                    TotpVerificationError::SessionCreationCancelled
                }
                ExistingSessionFactorError::Auth(error) => TotpVerificationError::Auth(error),
            })?;
            mark_factor_verified(&two_factor, ctx).await?;
            Ok(result)
        }
        ResolvedTwoFactorState::Pending(pending_2) => {
            mark_factor_verified(&two_factor, ctx).await?;
            Box::pin(finalize_pending_two_factor(
                pending_2,
                req,
                body.trust_device.unwrap_or(false),
                true,
                ctx,
            ))
            .await
            .map_err(TotpVerificationError::from)
        }
    }
}

pub(in crate::two_factor) fn totp_digits(config: &TwoFactorConfig) -> f64 {
    truthy_number(config.totp_digits, DEFAULT_TOTP_DIGITS)
}

pub(in crate::two_factor) fn totp_period(config: &TwoFactorConfig) -> f64 {
    truthy_number(config.totp_period, DEFAULT_TOTP_PERIOD_SECS)
}

pub(in crate::two_factor) fn truthy_number(value: f64, default: f64) -> f64 {
    if value == 0.0 || value.is_nan() {
        default
    } else {
        value
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Source Date.now is an IEEE754 millisecond number"
)]
pub(in crate::two_factor) fn totp_counter(config: &TwoFactorConfig) -> f64 {
    (Utc::now().timestamp_millis() as f64 / (totp_period(config) * 1000.0)).floor()
}

#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "Guarded IEEE754 counter/length conversion; SHA1 is 20 bytes and every truncated digest index is in 0..=19"
)]
pub(in crate::two_factor) fn generate_totp_at(
    config: &TwoFactorConfig,
    secret: &str,
    counter: f64,
    offset: f64,
) -> AuthResult<String> {
    let digits = totp_digits(config);
    let counter = counter + offset;
    if !(1.0..=8.0).contains(&digits) || secret.is_empty() || !counter.is_finite() {
        return Err(AuthError::internal("Invalid TOTP HMAC input"));
    }
    // setBigUint64 wraps the integer BigInt modulo 2^64, including negatives.
    // Taking the signed remainder before conversion avoids f64 rounding of
    // negative small counters when adding 2^64.
    let remainder = counter % 18_446_744_073_709_551_616.0;
    let counter = if remainder < 0.0 {
        (remainder.abs() as u64).wrapping_neg()
    } else {
        remainder as u64
    };
    let decoded = totp_secret(secret)?;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(decoded.as_bytes())
        .map_err(|_error| AuthError::internal("Invalid TOTP HMAC input"))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 15);
    let truncated = u32::from_be_bytes([
        digest[offset] & 127,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    let value = f64::from(truncated) % 10.0_f64.powf(digits);
    let code = js_number_string(value);
    let padding = (digits.trunc() as usize).saturating_sub(code.len());
    Ok(format!("{}{code}", "0".repeat(padding)))
}

pub(in crate::two_factor) fn js_number_string(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value == f64::INFINITY {
        "Infinity".into()
    } else if value == f64::NEG_INFINITY {
        "-Infinity".into()
    } else {
        ryu_js::Buffer::new().format(value).to_owned()
    }
}

pub(in crate::two_factor) fn constant_time_totp_equal(input: &str, expected: &str) -> bool {
    // Source compares UTF-16 code units and includes the original lengths.
    let mut input_units = input.encode_utf16();
    let mut difference = input_units.clone().count() ^ expected.encode_utf16().count();
    for unit in expected.encode_utf16() {
        difference |= usize::from(input_units.next().unwrap_or_default() ^ unit);
    }
    difference == 0
}

pub(in crate::two_factor) fn totp_uri(
    config: &TwoFactorConfig,
    secret: &str,
    issuer: &str,
    email: &str,
    enrollment: bool,
) -> AuthResult<String> {
    let secret = totp_secret(secret)?.to_base32();
    let digits = js_number_string(totp_digits(config));
    // Enrollment forwards the configured period directly; the authenticator
    // provider and generator use the upstream truthy default for zero.
    let period = js_number_string(if enrollment {
        config.totp_period
    } else {
        totp_period(config)
    });
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &secret)
        .append_pair("issuer", issuer)
        .append_pair("digits", &digits)
        .append_pair("period", &period)
        .finish();
    Ok(format!(
        "otpauth://totp/{}:{}?{query}",
        alibi_core::utils::javascript::encode_uri_component(issuer),
        alibi_core::utils::javascript::encode_uri_component(email)
    ))
}

fn totp_secret(secret: &str) -> AuthResult<totp_rs::Secret> {
    if let Some(encoded) = secret.strip_prefix("base32:") {
        totp_rs::Secret::try_from_base32(encoded.to_uppercase())
            .map_err(|_| AuthError::internal("Invalid Base32 TOTP secret"))
    } else {
        Ok(totp_rs::Secret::new(
            secret.as_bytes().to_vec().into_boxed_slice(),
        ))
    }
}

pub(in crate::two_factor) fn generate_secret() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238, SHA-1 at Unix time 59 with an imported Base32 secret.
    #[test]
    fn imported_base32_secret_uses_decoded_hmac_bytes() {
        let config = TwoFactorConfig {
            totp_digits: 8.0,
            ..Default::default()
        };
        let imported = "base32:gezdgnbvgy3tqojqgezdgnbvgy3tqojq";
        assert_eq!(
            generate_totp_at(&config, imported, 1.0, 0.0).unwrap(),
            "94287082"
        );
        let uri = totp_uri(&config, imported, "Example", "owner@example.com", false).unwrap();
        assert_eq!(
            url::Url::parse(&uri)
                .unwrap()
                .query_pairs()
                .find(|(key, _)| key == "secret")
                .unwrap()
                .1,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert!(generate_totp_at(&config, "base32:!", 1.0, 0.0).is_err());
    }
}
