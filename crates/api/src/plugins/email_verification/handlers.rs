use super::token::{create_email_verification_token, decode_email_verification_token};
use super::types::{SendVerificationEmailRequest, VerifyEmailQuery, VerifyEmailResult};
use super::{EmailVerificationConfig, StatusResponse};
use crate::plugins::helpers::{
    SessionIssueError, create_user_session_record, record_completed_session_record,
    record_completed_session_user_view,
};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthContext, AuthError, AuthResult, UpdateUser};
use better_auth_core::{AuthSession, AuthUser};
use jsonwebtoken::errors::ErrorKind;

pub(in crate::plugins) fn verification_url(
    config: &better_auth_core::AuthConfig,
    token: &str,
    callback_url: Option<&str>,
) -> String {
    let callback_url = callback_url.filter(|url| !url.is_empty()).unwrap_or("/");
    let base_url = crate::plugins::helpers::auth_base_url(config);
    format!(
        "{base_url}/verify-email?token={token}&callbackURL={}",
        urlencoding::encode(callback_url),
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn send_verification_email_core<U: AuthUser>(
    body: &SendVerificationEmailRequest,
    current_user: Option<&U>,
    config: &EmailVerificationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if config.send_verification_email.is_none() && ctx.email_verification_override().is_none() {
        return Err(AuthError::bad_request("Verification email isn't enabled"));
    }

    if let Some(user) = current_user {
        let session_email = user.email().unwrap_or_default();
        if session_email.to_lowercase() != body.email.to_lowercase() {
            return Err(AuthError::bad_request("Email mismatch"));
        }
        if user.email_verified() {
            return Err(AuthError::bad_request("Email is already verified"));
        }

        let token = create_email_verification_token(
            &ctx.config.secret,
            &body.email,
            None,
            config.verification_token_expiry,
            None,
        )?;
        let url = verification_url(&ctx.config, &token, body.callback_url.as_deref());
        let user = ctx.user_view(user);
        if config.send_verification_email.is_none()
            && let Some(sender) = ctx.email_verification_override()
        {
            sender.0.send(&user, None, ctx).await?;
        } else if let Some(ref sender) = config.send_verification_email {
            sender.send(&user, &url, &token).await?;
        }
    } else {
        let start = tokio::time::Instant::now();
        let user = ctx.database.get_user_by_email_record(&body.email).await?;
        let result: AuthResult<()> = if let Some(user) = user.filter(|user| !user.email_verified())
        {
            async {
                let token = create_email_verification_token(
                    &ctx.config.secret,
                    &body.email,
                    None,
                    config.verification_token_expiry,
                    None,
                )?;
                let url = verification_url(&ctx.config, &token, body.callback_url.as_deref());
                let user = ctx.user_view(&user);
                if config.send_verification_email.is_none()
                    && let Some(sender) = ctx.email_verification_override()
                {
                    sender.0.send(&user, None, ctx).await?;
                } else if let Some(ref sender) = config.send_verification_email {
                    sender.send(&user, &url, &token).await?;
                }
                Ok(())
            }
            .await
        } else {
            // Missing and already-verified mailboxes perform the same local
            // signing work and retain the same timing floor without delivery.
            drop(create_email_verification_token(
                &ctx.config.secret,
                &body.email,
                None,
                config.verification_token_expiry,
                None,
            )?);
            Ok(())
        };
        let remaining = std::time::Duration::from_millis(500).saturating_sub(start.elapsed());
        if !remaining.is_zero() {
            tokio::time::sleep(remaining).await;
        }
        result?;
    }

    Ok(StatusResponse { status: true })
}

fn redirect_url(callback_url: &str, error: Option<&str>) -> String {
    let Some(error) = error else {
        return callback_url.to_owned();
    };
    let relative = callback_url.starts_with('/');
    let parsed = if relative {
        url::Url::parse("https://verification.invalid").and_then(|base| base.join(callback_url))
    } else {
        url::Url::parse(callback_url)
    };
    let Ok(mut parsed) = parsed else {
        return callback_url.to_owned();
    };
    let existing = parsed.query().unwrap_or_default();
    let separator = if existing.is_empty() || existing.ends_with('&') {
        ""
    } else {
        "&"
    };
    parsed.set_query(Some(&format!("{existing}{separator}error={error}")));
    if relative {
        parsed
            .as_str()
            .strip_prefix(&parsed.origin().ascii_serialization())
            .unwrap_or(parsed.as_str())
            .to_owned()
    } else {
        parsed.to_string()
    }
}

fn verification_error(
    query: &VerifyEmailQuery,
    code: &'static str,
    message: &'static str,
) -> AuthResult<VerifyEmailResult> {
    query
        .callback_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .map_or_else(
            || {
                Err(AuthError::Upstream {
                    status: 401,
                    code,
                    message,
                })
            },
            |callback| {
                Ok(VerifyEmailResult::Redirect {
                    url: redirect_url(callback, Some(code)),
                    session_token: None,
                })
            },
        )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
#[expect(
    clippy::too_many_lines,
    reason = "Keep verification ownership, account transitions, and callback ordering together"
)]
pub(super) async fn verify_email_core<A: better_auth_core::AuthSchema>(
    query: &VerifyEmailQuery,
    config: &EmailVerificationConfig,
    request: &better_auth_core::AuthRequest,
    ctx: &AuthContext<A>,
) -> AuthResult<VerifyEmailResult> {
    let meta = better_auth_core::RequestMeta::from_request(request);
    let ip_address = meta.ip_address;
    let user_agent = meta.user_agent;

    let claims = match decode_email_verification_token(&ctx.config.secret, &query.token) {
        Ok(claims) => claims,
        Err(AuthError::Jwt(error)) => {
            return if matches!(error.kind(), ErrorKind::ExpiredSignature) {
                verification_error(query, "TOKEN_EXPIRED", "Token expired")
            } else {
                verification_error(query, "INVALID_TOKEN", "Invalid token")
            };
        }
        Err(error) => return Err(error),
    };

    let Some(user) = ctx
        .database
        .get_user_by_email_record(&claims.email.to_lowercase())
        .await?
    else {
        return verification_error(query, "USER_NOT_FOUND", "User not found");
    };

    if let Some(update_to) = claims.update_to.as_deref() {
        let current_session = verification_session(request, ctx).await;
        if let Some((ref session_user, _)) = current_session
            && session_user.email().unwrap_or_default() != claims.email
        {
            return verification_error(query, "INVALID_USER", "Invalid user");
        }

        match claims.request_type.as_deref() {
            Some("change-email-confirmation") => {
                let new_token = create_email_verification_token(
                    &ctx.config.secret,
                    &claims.email,
                    Some(update_to),
                    config.verification_token_expiry,
                    Some("change-email-verification"),
                )?;
                let url = verification_url(&ctx.config, &new_token, query.callback_url.as_deref());
                let mut updated_user = ctx.user_view(&user);
                updated_user.email = Some(update_to.to_owned());
                if config.send_verification_email.is_none()
                    && let Some(sender) = ctx.email_verification_override()
                {
                    sender.0.send(&updated_user, None, ctx).await?;
                } else if let Some(ref sender) = config.send_verification_email {
                    super::super::authentication_helpers::run_notification(sender.send(
                        &updated_user,
                        &url,
                        &new_token,
                    ))
                    .await;
                }

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: None,
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({ "status": true }),
                    session_token: None,
                });
            }
            Some("change-email-verification") => {
                let (mut session_user, session): (UserView, SessionView) =
                    if let Some((user_2, session)) = current_session {
                        (user_2, session)
                    } else {
                        let session =
                            create_user_session_record(ctx, &user.id(), ip_address, user_agent)
                                .await
                                .map_err(SessionIssueError::into_auth_error)?
                                .session;
                        (ctx.user_view(&user), ctx.session_view(&session))
                    };

                let updated_user = ctx
                    .database
                    .update_user_record(
                        &user.id(),
                        UpdateUser {
                            email: Some(update_to.to_owned()),
                            email_verified: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?;

                if let Some(ref hook) = config.after_email_verification {
                    let hook_user = ctx.user_view(&updated_user);
                    hook(&hook_user).await?;
                }

                session_user.email = Some(update_to.to_owned());
                session_user.email_verified = true;
                super::super::user_management::handlers::renew_session_snapshot(
                    &session_user,
                    &session,
                    ctx,
                )
                .await?;

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: Some(session.token().to_owned()),
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({
                        "status": true,
                        "user": ctx.user_view(&updated_user),
                    }),
                    session_token: Some(session.token().to_owned()),
                });
            }
            _ => {
                let (mut session_user, session) =
                    if let Some((session_user, session)) = current_session {
                        (session_user, session)
                    } else {
                        let session =
                            create_user_session_record(ctx, &user.id(), ip_address, user_agent)
                                .await
                                .map_err(SessionIssueError::into_auth_error)?
                                .session;
                        (ctx.user_view(&user), ctx.session_view(&session))
                    };
                let updated_user = ctx
                    .database
                    .update_user_record(
                        &user.id(),
                        UpdateUser {
                            email: Some(update_to.to_owned()),
                            email_verified: Some(false),
                            ..Default::default()
                        },
                    )
                    .await?;
                let new_token = create_email_verification_token(
                    &ctx.config.secret,
                    update_to,
                    None,
                    chrono::Duration::hours(1),
                    None,
                )?;
                let url = verification_url(&ctx.config, &new_token, query.callback_url.as_deref());
                let wire_user = ctx.user_view(&updated_user);
                if config.send_verification_email.is_none()
                    && let Some(sender) = ctx.email_verification_override()
                {
                    sender.0.send(&wire_user, None, ctx).await?;
                } else if let Some(ref sender) = config.send_verification_email {
                    super::super::authentication_helpers::run_notification(
                        sender.send(&wire_user, &url, &new_token),
                    )
                    .await;
                }

                session_user.email = Some(update_to.to_owned());
                session_user.email_verified = false;
                super::super::user_management::handlers::renew_session_snapshot(
                    &session_user,
                    &session,
                    ctx,
                )
                .await?;

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: Some(session.token().to_owned()),
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({
                        "status": true,
                        "user": ctx.user_view(&updated_user),
                    }),
                    session_token: Some(session.token().to_owned()),
                });
            }
        }
    }

    if user.email_verified() {
        if let Some(callback_url) = query.callback_url.as_deref() {
            return Ok(VerifyEmailResult::Redirect {
                url: redirect_url(callback_url, None),
                session_token: None,
            });
        }

        return Ok(VerifyEmailResult::Json {
            body: serde_json::json!({ "status": true, "user": serde_json::Value::Null }),
            session_token: None,
        });
    }

    if let Some(ref hook) = config.before_email_verification {
        let hook_user = ctx.user_view(&user);
        hook(&hook_user).await?;
    }

    let updated_user = ctx
        .database
        .update_user_record(
            &user.id(),
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;

    if let Some(ref hook) = config.after_email_verification {
        let hook_user = ctx.user_view(&updated_user);
        hook(&hook_user).await?;
    }

    let session_token = if config.auto_sign_in_after_verification {
        let current_session = verification_session(request, ctx).await;
        match current_session {
            Some((session_user, session))
                if session_user.email().unwrap_or_default() == claims.email =>
            {
                let mut original_view = session_user;
                original_view.email_verified = true;
                super::super::user_management::handlers::renew_session_snapshot(
                    &original_view,
                    &session,
                    ctx,
                )
                .await?;
                Some(session.token().to_owned())
            }
            _ => {
                let issued = create_user_session_record(ctx, &user.id(), ip_address, user_agent)
                    .await
                    .map_err(SessionIssueError::into_auth_error)?;
                // Source publishes the original lookup snapshot with only the
                // verification flag changed, even though the stored row is newer.
                let mut original_view = ctx.trusted_user_view(&user);
                original_view.email_verified = true;
                better_auth_core::cache::runtime::emit_issuance_snapshot(
                    ctx,
                    better_auth_core::CacheVersionContext::created(
                        issued.user.clone(),
                        issued.session.clone(),
                        original_view.clone(),
                        ctx.session_view(&issued.session),
                    ),
                )
                .await?;
                record_completed_session_record::<A>(&issued.user, &issued.session);
                record_completed_session_user_view::<A>(&user, &issued.session, original_view);
                Some(issued.session.token().to_owned())
            }
        }
    } else {
        None
    };

    if let Some(callback_url) = query.callback_url.as_deref() {
        return Ok(VerifyEmailResult::Redirect {
            url: redirect_url(callback_url, None),
            session_token,
        });
    }

    Ok(VerifyEmailResult::Json {
        body: serde_json::json!({ "status": true, "user": serde_json::Value::Null }),
        session_token,
    })
}

async fn verification_session<S: better_auth_core::AuthSchema>(
    request: &better_auth_core::AuthRequest,
    ctx: &AuthContext<S>,
) -> Option<(UserView, SessionView)> {
    better_auth_core::cache::runtime::authenticated(ctx, request, false)
        .await
        .ok()
        .flatten()
        .map(|read| (ctx.user_view(&read.user), read.session))
}
