use super::*;
pub(in crate::plugins::two_factor) async fn generate_backup_codes_core(
    body: &GenerateBackupCodesRequest,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<BackupCodesResponse, BackupOperationError> {
    if !user.two_factor_enabled() {
        return Err(AuthError::bad_request("Two factor isn't enabled").into());
    }

    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config
            .backup_allow_passwordless
            .unwrap_or(config.allow_passwordless),
    )
    .await?;
    let factor = ctx
        .database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("Two factor isn't enabled"))?;

    let (backup_codes, encrypted) = generate_backup_codes(config, &ctx.config).await?;
    drop(
        ctx.database
            .update_two_factor(
                factor.id().as_ref(),
                UpdateTwoFactor {
                    backup_codes: Some(encrypted),
                    ..Default::default()
                },
            )
            .await?,
    );

    Ok(BackupCodesResponse {
        status: true,
        backup_codes,
    })
}

pub(in crate::plugins::two_factor) async fn verify_backup_code_core(
    req: &AuthRequest,
    body: &VerifyBackupCodeRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(BackupVerificationResponse, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(state.user().id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let pending = matches!(state, ResolvedTwoFactorState::Pending(_));
    if pending {
        assert_account_not_locked(config, &two_factor, ctx).await?;
    }
    let attempt = begin_factor_attempt(&state, ctx).await?;

    let codes = match config
        .backup_storage
        .load_value(two_factor.backup_codes(), &ctx.config)
        .await
    {
        Ok(codes) => codes,
        Err(error) => {
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(error);
        }
    };
    let codes = match codes {
        Some(better_auth_core::utils::json::JsValue::Array(codes)) => Some(codes),
        None => None,
        Some(value) if !backup_storage::truthy(&value) => None,
        Some(_) => {
            // Source's includes/filter calls throw for truthy non-arrays inside
            // the decode-stage try/catch. Do not turn corrupted storage into
            // a failed proof or spend the pending challenge's attempt budget.
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(AuthError::Encryption(
                "Backup code JSON is not an array".into(),
            ));
        }
    };
    let Some(mut backup_codes) = codes.filter(|codes| {
        codes.iter().any(|code| {
            code.as_str()
                .is_some_and(|text| text == body.code && backup_storage::json_date(text).is_none())
        })
    }) else {
        rearm_factor_attempt(attempt.as_ref(), true, ctx).await;
        if pending {
            record_account_failure(config, &two_factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    backup_codes.retain(|candidate| candidate.as_str() != Some(body.code.as_str()));

    let mut backup_codes = better_auth_core::utils::json::JsValue::Array(backup_codes);
    backup_storage::normalize_json_dates(&mut backup_codes);
    let encrypted = config
        .backup_storage
        .store_json(
            better_auth_core::utils::json::to_string(&backup_codes)?,
            &ctx.config,
        )
        .await?;
    if !ctx
        .database
        .compare_and_swap_two_factor_backup_codes(
            two_factor.id().as_ref(),
            two_factor.backup_codes(),
            &encrypted,
        )
        .await?
    {
        return Err(AuthError::conflict(
            "Failed to verify backup code. Please try again.",
        ));
    }
    if pending {
        reset_account_failures(config, &two_factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            if body.disable_session.unwrap_or(false) {
                Ok((
                    BackupVerificationResponse {
                        token: Some(session.token().to_owned()),
                        user: ctx.user_view(&user),
                    },
                    Vec::new(),
                ))
            } else {
                verify_existing_session_factor(user, *session, false, false, ctx)
                    .await
                    .map(|(response, headers)| (response.into(), headers))
                    .map_err(ExistingSessionFactorError::into_auth_error)
            }
        }
        ResolvedTwoFactorState::Pending(pending_2) => {
            if body.disable_session.unwrap_or(false) {
                return Ok((
                    BackupVerificationResponse {
                        token: None,
                        user: ctx.user_view(&pending_2.user),
                    },
                    Vec::new(),
                ));
            }
            finalize_pending_two_factor(
                pending_2,
                req,
                body.trust_device.unwrap_or(false),
                true,
                ctx,
            )
            .await
            .map(|(response, headers)| (response.into(), headers))
        }
    }
}

pub(in crate::plugins::two_factor) async fn view_backup_codes_core<
    S: better_auth_core::AuthSchema,
>(
    user_id: &str,
    config: &TwoFactorConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<serde_json::Value> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let Some(mut backup_codes) = config
        .backup_storage
        .load_value(two_factor.backup_codes(), &ctx.config)
        .await?
        .filter(backup_storage::truthy)
    else {
        return Err(AuthError::bad_request("Invalid backup code"));
    };
    backup_storage::normalize_json_dates(&mut backup_codes);
    Ok(backup_codes.to_json_value()?)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(in crate::plugins::two_factor) async fn generate_backup_codes(
    config: &TwoFactorConfig,
    secret: &better_auth_core::AuthConfig,
) -> Result<(Vec<String>, String), BackupOperationError> {
    let codes = if let Some(generate) = &config.custom_backup_codes_generate {
        generate()?
    } else {
        let amount = config.backup_code_amount;
        let count = if amount.is_nan() || amount <= 0.0 {
            0
        } else {
            // Array.from creates an ordinary JS array, with a 32-bit length.
            if !amount.is_finite() || amount.floor() > f64::from(u32::MAX) {
                return Err(BackupOperationError::InvalidGeneration);
            }
            amount.floor() as usize
        };
        let mut codes = Vec::new();
        codes
            .try_reserve_exact(count)
            .map_err(|_error| BackupOperationError::InvalidGeneration)?;
        for _ in 0..count {
            let code = generate_numeric_string(config.backup_code_length, false)
                .ok_or(BackupOperationError::InvalidGeneration)?;
            let split = code.len().min(5);
            let (prefix, suffix) = code
                .split_at_checked(split)
                .ok_or(BackupOperationError::InvalidGeneration)?;
            codes.push(format!("{prefix}-{suffix}"));
        }
        codes
    };
    let stored = config.backup_storage.store_codes(&codes, secret).await?;
    Ok((codes, stored))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "Finite JS random lengths round up before checked native allocation"
)]
pub(in crate::plugins::two_factor) fn generate_numeric_string(
    length: f64,
    decimal: bool,
) -> Option<String> {
    if length.is_nan() {
        return Some(String::new());
    }
    // Sub-half-character Source buffers are empty and never terminate.
    // The native API rejects them instead of reproducing that infinite loop.
    if !length.is_finite() || length < 0.5 || length.ceil() >= usize::MAX as f64 {
        return None;
    }
    let count = length.ceil() as usize;
    let mut code = String::new();
    code.try_reserve_exact(count).ok()?;
    let mut random = rand::rng();
    for _ in 0..count {
        code.push(if decimal {
            char::from(b'0' + random.random_range(0..10u8))
        } else {
            char::from(random.sample(Alphanumeric))
        });
    }
    Some(code)
}
