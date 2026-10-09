use super::TwoFactorConfig;
use alibi_core::TwoFactor;
use alibi_core::entity::AuthTwoFactor;
use alibi_core::{AuthContext, AuthError, AuthResult};
use chrono::Utc;
pub(in crate::two_factor) async fn assert_account_not_locked(
    config: &TwoFactorConfig,
    factor: &TwoFactor,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    if !config.account_lockout.enabled {
        return Ok(());
    }
    if let Some(until) = factor.locked_until() {
        let now = Utc::now();
        if until.timestamp_millis() > now.timestamp_millis() {
            return Err(AuthError::Upstream {
                status: 429,
                code: "ACCOUNT_TEMPORARILY_LOCKED",
                message: "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
            });
        }
        drop(
            ctx.database
                .clear_expired_two_factor_lock(factor.id().as_ref(), now)
                .await?,
        );
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(in crate::two_factor) async fn record_account_failure(
    config: &TwoFactorConfig,
    factor: &TwoFactor,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    if !config.account_lockout.enabled {
        return Ok(());
    }
    let incremented = ctx
        .database
        .increment_two_factor_failure(factor.id().as_ref())
        .await?;
    let count = incremented
        .and_then(|factor_2| factor_2.failed_verification_count())
        .unwrap_or(0.0);
    if count >= config.account_lockout.max_failed_attempts {
        let milliseconds = config
            .account_lockout
            .duration_seconds
            .mul_add(1000.0, Utc::now().timestamp_millis() as f64);
        // JavaScript Date TimeClip rejects nonfinite/out-of-range values and
        // truncates toward zero; nullable/zero settings remain supported.
        if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
            return Err(AuthError::internal("Invalid two-factor lock date"));
        }
        let until = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
            .ok_or_else(|| AuthError::internal("Invalid two-factor lock date"))?;
        drop(
            ctx.database
                .set_two_factor_lock_if_count_at_least(
                    factor.id().as_ref(),
                    config.account_lockout.max_failed_attempts,
                    until,
                )
                .await?,
        );
    }
    Ok(())
}

pub(in crate::two_factor) async fn reset_account_failures(
    config: &TwoFactorConfig,
    factor: &TwoFactor,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    if config.account_lockout.enabled {
        ctx.database
            .reset_two_factor_failures(factor.id().as_ref())
            .await?;
    }
    Ok(())
}
