use super::*;
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(in crate::plugins::two_factor) async fn send_otp_core(
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<StatusResponse, SendOtpError> {
    let sender = config
        .send_otp
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("otp isn't configured"))?;
    let state = resolve_two_factor_state(req, ctx).await?;

    let otp =
        generate_numeric_string(config.otp_digits, true).ok_or(SendOtpError::InvalidGeneration)?;
    let stored_otp = config.otp_storage.store(&otp, &ctx.config).await?;
    let identifier = otp_verification_identifier(state.key());
    let period = if config.otp_period_minutes == 0.0 || config.otp_period_minutes.is_nan() {
        3.0
    } else {
        config.otp_period_minutes
    };
    let milliseconds = Utc::now().timestamp_millis() as f64 + period * 60.0 * 1000.0;
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(SendOtpError::InvalidGeneration);
    }
    let expires_at = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or(SendOtpError::InvalidGeneration)?;

    drop(
        ctx.verifications()
            .create(CreateVerification {
                identifier,
                value: format!("{stored_otp}:0"),
                expires_at,
            })
            .await?,
    );

    otp::deliver(
        Arc::clone(sender),
        ctx.user_view(&state.user()),
        otp,
        ctx.config.background_tasks.clone(),
    )
    .await?;

    Ok(StatusResponse { status: true })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OTP ownership, attempt limits, and successful factor consumption in protocol order"
)]
pub(in crate::plugins::two_factor) async fn verify_otp_core(
    req: &AuthRequest,
    body: &VerifyOtpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<(SessionTokenResponse<UserView>, Vec<String>), ExistingSessionFactorError> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let factor = if matches!(state, ResolvedTwoFactorState::Pending(_)) {
        let factor = ctx
            .database
            .get_two_factor_by_user_id(state.user().id().as_ref())
            .await?;
        if let Some(factor) = &factor {
            assert_account_not_locked(config, factor, ctx).await?;
        }
        factor
    } else {
        None
    };
    let identifier = otp_verification_identifier(state.key());
    let Some(verification) = ctx.verifications().consume(&identifier).await? else {
        return Err(AuthError::bad_request("OTP has expired").into());
    };

    let mut parts = verification.value()?.split(':');
    let stored_otp = parts.next().unwrap_or_default();
    let counter = parts.next().unwrap_or_default();
    // parseInt(counter, 10) accepts a signed decimal prefix and ignores its suffix.
    let trimmed = counter.trim_start_matches(|c: char| {
        matches!(
            c,
            '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    });
    let prefix_length = trimmed
        .char_indices()
        .take_while(|(index, c)| c.is_ascii_digit() || (*index == 0 && (*c == '+' || *c == '-')))
        .last()
        .map_or(0, |(index, c)| index + c.len_utf8());
    let attempts = trimmed
        .get(..prefix_length)
        .unwrap_or_default()
        .parse::<f64>()
        .unwrap_or(0.0);
    let allowed_attempts =
        if config.otp_allowed_attempts == 0.0 || config.otp_allowed_attempts.is_nan() {
            5.0
        } else {
            config.otp_allowed_attempts
        };
    if attempts >= allowed_attempts {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            message: "Too many attempts. Please request a new code.",
        }
        .into());
    }

    let is_valid = config
        .otp_storage
        .verify(stored_otp, &body.code, &ctx.config)
        .await?;

    if !is_valid {
        let next_count = attempts + 1.0;
        let next_counter = if next_count.is_infinite() {
            if next_count.is_sign_negative() {
                "-Infinity".into()
            } else {
                "Infinity".into()
            }
        } else {
            alibi_core::utils::json::number_to_string(
                &serde_json::Number::from_f64(next_count)
                    .ok_or_else(|| AuthError::internal("Invalid OTP counter"))?,
            )
            .map_err(AuthError::from)?
        };
        let next_value = format!("{stored_otp}:{next_counter}");
        let expires_at = verification.expires_at()?;
        let verification_identifier = otp_verification_identifier(state.key());
        drop(
            ctx.verifications()
                .create(CreateVerification {
                    identifier: verification_identifier,
                    value: next_value,
                    expires_at,
                })
                .await?,
        );
        if let Some(factor) = &factor {
            record_account_failure(config, factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid code").into());
    }

    if let Some(factor) = &factor {
        reset_account_failures(config, factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, *session, true, true, ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), true, ctx)
                .await
                .map_err(ExistingSessionFactorError::Auth)
        }
    }
}

pub(in crate::plugins::two_factor) fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{key}")
}
