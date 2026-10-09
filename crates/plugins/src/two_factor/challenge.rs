use super::*;
pub(crate) async fn inspect_trusted_device(
    req: &AuthRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<TrustedDeviceCheck> {
    let cookie_name = related_cookie_name(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX);
    let Some(raw_cookie) = get_factor_cookie(req, &cookie_name) else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: Vec::new(),
        });
    };

    let clear_header = create_clear_cookie(&cookie_name, &ctx.config)?;
    let Some(signed_value) = verify_factor_cookie_value(ctx.config.current_secret(), &raw_cookie)
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: Vec::new(),
        });
    };

    // The source tests outer payload truthiness before expiring a cookie,
    // then destructures only the first two components and ignores the rest.
    let mut components = signed_value.split('!');
    let token = components.next().unwrap_or_default();
    let trust_identifier = components.next().unwrap_or_default();
    if token.is_empty() || trust_identifier.is_empty() {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    let expected_token = sign_value(
        ctx.config.current_secret(),
        &format!("{}!{}", user.id(), trust_identifier),
    )?;
    if token != expected_token {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    let Some(verification) =
        super::super::authentication_helpers::find_verification(ctx, trust_identifier).await?
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

    if verification.value()? != user.id().as_ref() || verification.expires_at()? <= Utc::now() {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    ctx.verifications().delete(trust_identifier).await?;

    let rotated_cookie = create_trust_device_cookie_header(user, ctx).await?;
    Ok(TrustedDeviceCheck {
        trusted: true,
        set_cookie_headers: vec![rotated_cookie],
    })
}

pub(crate) async fn begin_sign_in_challenge(
    user: &impl AuthUser,
    remember_me: Option<bool>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SignInTwoFactorRedirect> {
    let identifier = format!("2fa-{}", uuid::Uuid::new_v4());
    let expires_at = cookie_expiry(two_factor_cookie_max_age(ctx))?;
    _ = ctx
        .verifications()
        .create(CreateVerification {
            identifier: identifier.clone(),
            value: user.id().to_string(),
            expires_at,
        })
        .await?;
    _ = ctx
        .verifications()
        .create(CreateVerification {
            identifier: format!("2fa-attempts-{identifier}"),
            value: "0".to_owned(),
            expires_at,
        })
        .await?;

    let incoming = alibi_core::hooks::current_request_hook_context()
        .map(|request| request.headers)
        .unwrap_or_default();
    let mut headers = alibi_core::session::cookie_cache::runtime::session_cleanup_headers(
        &ctx.config,
        &incoming,
        true,
    )?;
    headers.retain(|cookie| {
        !cookie.starts_with(&format!(
            "{}=",
            related_cookie_name(&ctx.config, DONT_REMEMBER_COOKIE_SUFFIX)
        ))
    });
    headers.push(create_signed_cookie_header(
        ctx.config.current_secret(),
        &ctx.config,
        TWO_FACTOR_COOKIE_SUFFIX,
        &identifier,
        Some(two_factor_cookie_max_age(ctx)),
    )?);

    if remember_me == Some(false) {
        headers.push(create_signed_cookie_header(
            ctx.config.current_secret(),
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
            "true",
            None,
        )?);
    }

    // TOTP is per-user: only offered once the user has a stored secret. OTP is
    // server-level: offered whenever a sender is configured.
    let mut two_factor_methods = Vec::new();
    if !ctx
        .get_metadata(METADATA_TOTP_DISABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && ctx
            .database
            .get_two_factor_by_user_id(user.id().as_ref())
            .await?
            .is_some_and(|factor| factor.verified() != Some(false))
    {
        two_factor_methods.push("totp");
    }
    if ctx
        .get_metadata(METADATA_OTP_ENABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        two_factor_methods.push("otp");
    }

    Ok(SignInTwoFactorRedirect {
        response: TwoFactorRedirectResponse {
            two_factor_redirect: true,
            two_factor_methods,
        },
        set_cookie_headers: headers,
    })
}

pub(in crate::two_factor) async fn resolve_two_factor_state<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<ResolvedTwoFactorState<S>> {
    if let Ok((user, session)) = ctx.require_cached_session(req).await {
        let key = format!("{}!{}", user.id(), session.id());
        return Ok(ResolvedTwoFactorState::Session {
            user,
            session: Box::new(session),
            key,
        });
    }

    let identifier = read_signed_cookie(req, TWO_FACTOR_COOKIE_SUFFIX, ctx)
        .filter(|identifier| !identifier.is_empty())
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    // Preserve the newest lookup snapshot across optional global cleanup.
    // Expiry is enforced by the later atomic attempt/challenge consumption,
    // after the source's user lookup and factor-specific checks.
    let verification = super::super::authentication_helpers::find_verification(ctx, &identifier)
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;

    let user = ctx
        .database
        .get_user_by_id_record(verification.value()?)
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)
        .is_some_and(|value| !value.is_empty());

    Ok(ResolvedTwoFactorState::Pending(PendingTwoFactorState {
        user,
        verification,
        key: identifier,
        dont_remember,
    }))
}

pub(in crate::two_factor) async fn begin_factor_attempt<S: alibi_core::AuthSchema>(
    state: &ResolvedTwoFactorState<S>,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<FactorAttempt>> {
    let ResolvedTwoFactorState::Pending(pending) = state else {
        return Ok(None);
    };
    let identifier = format!("2fa-attempts-{}", pending.key);
    let consumed = ctx
        .verifications()
        .consume(&identifier)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let parsed = attempt_number(consumed.value()?);
    let count = if parsed.is_finite() && parsed.fract() == 0.0 && parsed >= 0.0 {
        parsed
    } else {
        5.0
    };
    if count >= 5.0 {
        if ctx.verifications().consume(&pending.key).await.is_err() {
            return Err(AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE",
                message: "Failed to invalidate two-factor challenge",
            });
        }
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            message: "Too many attempts. Please request a new code.",
        });
    }
    Ok(Some(FactorAttempt {
        identifier,
        count,
        expires_at: pending.verification.expires_at()?,
    }))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(in crate::two_factor) fn attempt_number(value: &str) -> f64 {
    let value = value.trim_matches(|character| {
        matches!(
            character,
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
    if value.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0b", 2),
        ("0B", 2),
        ("0o", 8),
        ("0O", 8),
    ] {
        if let Some(value) = value.strip_prefix(prefix) {
            return u64::from_str_radix(value, radix).map_or(f64::NAN, |count| count as f64);
        }
    }
    value.parse().unwrap_or(f64::NAN)
}

pub(in crate::two_factor) async fn rearm_factor_attempt(
    attempt: Option<&FactorAttempt>,
    failed: bool,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) {
    if let Some(attempt) = attempt {
        _ = ctx
            .verifications()
            .create(CreateVerification {
                identifier: attempt.identifier.clone(),
                value: (attempt.count + if failed { 1.0 } else { 0.0 }).to_string(),
                expires_at: attempt.expires_at,
            })
            .await;
    }
}

pub(in crate::two_factor) fn verification_error_response(
    error: AuthError,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    if matches!(
        &error,
        AuthError::Upstream {
            code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"
                | "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE"
                | "INVALID_TWO_FACTOR_COOKIE",
            ..
        }
    ) {
        Ok(error.to_auth_response().with_appended_header(
            "Set-Cookie",
            clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)?,
        ))
    } else {
        Err(error)
    }
}

pub(in crate::two_factor) async fn verify_existing_session_factor(
    user: impl AuthUser,
    session: impl AuthSession,
    enable_two_factor_if_needed: bool,
    return_updated_snapshot: bool,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<(SessionTokenResponse<UserView>, Vec<String>), ExistingSessionFactorError> {
    if enable_two_factor_if_needed && !user.two_factor_enabled() {
        let updated_user = ctx
            .database
            .update_user_record(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides_record(
            ctx,
            updated_user.id().as_ref(),
            session.ip_address().map(str::to_owned),
            session.user_agent().map(str::to_owned),
            &session,
        )
        .await
        .map_err(|error| match error.into_auth_error() {
            AuthError::SessionCreationCancelled => {
                ExistingSessionFactorError::SessionCreationCancelled
            }
            error @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::InvalidCredentials
            | AuthError::Unauthenticated
            | AuthError::AuthenticationFailed(_)
            | AuthError::SessionNotFound
            | AuthError::Forbidden(_)
            | AuthError::BannedUser(_)
            | AuthError::Unauthorized
            | AuthError::UserNotFound
            | AuthError::NotFound(_)
            | AuthError::Conflict(_)
            | AuthError::MethodNotAllowed(_)
            | AuthError::PayloadTooLarge(_)
            | AuthError::UnprocessableEntity(_)
            | AuthError::RateLimited { .. }
            | AuthError::NotImplemented(_)
            | AuthError::Config(_)
            | AuthError::Database(_)
            | AuthError::Serialization(_)
            | AuthError::Plugin { .. }
            | AuthError::CallbackFailure(_)
            | AuthError::Internal(_)
            | AuthError::Encryption(_)
            | AuthError::PasswordHash(_)
            | AuthError::UserCreationCancelled
            | AuthError::Jwt(_)) => ExistingSessionFactorError::Auth(error),
        })?;
        ctx.database.delete_session(session.token()).await?;
        return Ok((
            SessionTokenResponse {
                token: if return_updated_snapshot {
                    issued.session.token().to_owned()
                } else {
                    session.token().to_owned()
                },
                // TOTP retains its original response snapshot; OTP returns the
                // updated user and newly issued token.
                user: if return_updated_snapshot {
                    ctx.user_view(&updated_user)
                } else {
                    ctx.user_view(&user)
                },
            },
            vec![create_session_cookie(issued.session.token(), &ctx.config)?],
        ));
    }

    Ok((
        SessionTokenResponse {
            token: session.token().to_owned(),
            user: ctx.user_view(&user),
        },
        Vec::new(),
    ))
}

pub(in crate::two_factor) async fn finalize_pending_two_factor<S: alibi_core::AuthSchema>(
    pending: PendingTwoFactorState<S>,
    req: &AuthRequest,
    trust_device: bool,
    set_session_cookie: bool,
    ctx: &AuthContext<S>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let consumed = ctx.verifications().consume(&pending.key).await?;
    if consumed.is_none_or(|verification| {
        !verification
            .value()
            .is_ok_and(|value| value == pending.user.id().as_ref())
    }) {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TWO_FACTOR_COOKIE",
            message: "Invalid two factor cookie",
        });
    }
    let meta = RequestMeta::from_request(req);
    let mut config = (*ctx.config).clone();
    if pending.dont_remember {
        config.session.expires_in = Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: Arc::new(config),
        database: Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let issued = issue_user_session_record(
        &issuing_context,
        pending.user.id().as_ref(),
        meta.ip_address,
        meta.user_agent,
    )
    .await
    .map_err(|error| match error {
        SessionIssueError::Auth(AuthError::SessionCreationCancelled) => AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_CREATE_SESSION",
            message: "failed to create session",
        },
        error @ (SessionIssueError::Auth(_) | SessionIssueError::Banned { .. }) => {
            error.into_auth_error()
        }
    })?;

    let mut set_cookie_headers = vec![clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)?];
    if set_session_cookie {
        set_cookie_headers.push(create_session_cookie_for_dont_remember(
            issued.session.token(),
            pending.dont_remember,
            &ctx.config,
        )?);
        if pending.dont_remember {
            set_cookie_headers.push(create_signed_cookie_header(
                ctx.config.current_secret(),
                &ctx.config,
                DONT_REMEMBER_COOKIE_SUFFIX,
                "true",
                None,
            )?);
        }
    }
    if trust_device {
        set_cookie_headers.push(create_trust_device_cookie_header(&issued.user, ctx).await?);
        set_cookie_headers.push(clear_cookie_header(
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
        )?);
    }

    Ok((
        SessionTokenResponse {
            token: issued.session.token().to_owned(),
            user: ctx.user_view(&issued.user),
        },
        set_cookie_headers,
    ))
}

pub(in crate::two_factor) async fn load_two_factor_record(
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<TwoFactor> {
    ctx.database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("TOTP not enabled"))
}
