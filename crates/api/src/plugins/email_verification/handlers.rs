use jsonwebtoken::errors::ErrorKind;

use crate::plugins::helpers::{SessionIssueError, issue_user_session};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthContext, AuthError, AuthResult, UpdateUser};
use better_auth_core::{AuthSession, AuthUser};

use super::token::{create_email_verification_token, decode_email_verification_token};
use super::types::*;
use super::{EmailVerificationConfig, StatusResponse};

pub(crate) fn verification_url(
    config: &better_auth_core::AuthConfig,
    token: &str,
    callback_url: Option<&str>,
) -> String {
    let callback_url = callback_url.filter(|url| !url.is_empty()).unwrap_or("/");
    let origin = config.base_url.trim_end_matches('/');
    let path = config.base_path.trim_matches('/');
    let base_url = if path.is_empty() {
        origin.to_owned()
    } else {
        format!("{origin}/{path}")
    };
    format!(
        "{base_url}/verify-email?token={token}&callbackURL={}",
        urlencoding::encode(callback_url),
    )
}

pub(super) async fn send_verification_email_core<U: AuthUser>(
    body: &SendVerificationEmailRequest,
    current_user: Option<&U>,
    config: &EmailVerificationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if config.send_verification_email.is_none() {
        return Err(AuthError::bad_request("Verification email isn't enabled"));
    }

    match current_user {
        Some(user) => {
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
            if let Some(ref sender) = config.send_verification_email {
                sender.send(&user, &url, &token).await?;
            }
        }
        None => {
            let start = tokio::time::Instant::now();
            let user = ctx.database.get_user_by_email(&body.email).await?;
            let result: AuthResult<()> = if let Some(user) =
                user.filter(|user| !user.email_verified())
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
                    if let Some(ref sender) = config.send_verification_email {
                        sender.send(&user, &url, &token).await?;
                    }
                    Ok(())
                }
                .await
            } else {
                // Missing and already-verified mailboxes perform the same local
                // signing work and retain the same timing floor without delivery.
                let _ = create_email_verification_token(
                    &ctx.config.secret,
                    &body.email,
                    None,
                    config.verification_token_expiry,
                    None,
                )?;
                Ok(())
            };
            let remaining = std::time::Duration::from_millis(500).saturating_sub(start.elapsed());
            if !remaining.is_zero() {
                tokio::time::sleep(remaining).await;
            }
            result?;
        }
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
    if let Some(callback) = query.callback_url.as_deref().filter(|url| !url.is_empty()) {
        Ok(VerifyEmailResult::Redirect {
            url: redirect_url(callback, Some(code)),
            session_token: None,
        })
    } else {
        Err(AuthError::Upstream {
            status: 401,
            code,
            message,
        })
    }
}

pub(super) async fn verify_email_core<U, S>(
    query: &VerifyEmailQuery,
    current_session: Option<(U, S)>,
    config: &EmailVerificationConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<VerifyEmailResult>
where
    U: AuthUser,
    S: AuthSession,
{
    let current_session =
        current_session.map(|(user, session)| (ctx.user_view(&user), ctx.session_view(&session)));

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
        .get_user_by_email(&claims.email.to_lowercase())
        .await?
    else {
        return verification_error(query, "USER_NOT_FOUND", "User not found");
    };

    if let Some(update_to) = claims.update_to.as_deref() {
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
                updated_user.email = Some(update_to.to_string());
                if let Some(ref sender) = config.send_verification_email {
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
                let (_session_user, session): (UserView, SessionView) = match current_session {
                    Some((user, session)) => (user, session),
                    None => {
                        let session = issue_user_session(ctx, &user.id(), ip_address, user_agent)
                            .await
                            .map_err(SessionIssueError::into_auth_error)?
                            .session;
                        (ctx.user_view(&user), ctx.session_view(&session))
                    }
                };

                let updated_user = ctx
                    .database
                    .update_user(
                        &user.id(),
                        UpdateUser {
                            email: Some(update_to.to_string()),
                            email_verified: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?;

                if let Some(ref hook) = config.after_email_verification {
                    let hook_user = ctx.user_view(&updated_user);
                    hook(&hook_user).await?;
                }

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: Some(session.token().to_string()),
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({
                        "status": true,
                        "user": ctx.user_view(&updated_user),
                    }),
                    session_token: Some(session.token().to_string()),
                });
            }
            _ => {
                let session = match current_session {
                    Some((_, session)) => session,
                    None => {
                        let session = issue_user_session(ctx, &user.id(), ip_address, user_agent)
                            .await
                            .map_err(SessionIssueError::into_auth_error)?
                            .session;
                        ctx.session_view(&session)
                    }
                };
                let updated_user = ctx
                    .database
                    .update_user(
                        &user.id(),
                        UpdateUser {
                            email: Some(update_to.to_string()),
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
                if let Some(ref sender) = config.send_verification_email {
                    super::super::authentication_helpers::run_notification(
                        sender.send(&wire_user, &url, &new_token),
                    )
                    .await;
                }

                if let Some(callback_url) = query.callback_url.as_deref() {
                    return Ok(VerifyEmailResult::Redirect {
                        url: redirect_url(callback_url, None),
                        session_token: Some(session.token().to_string()),
                    });
                }

                return Ok(VerifyEmailResult::Json {
                    body: serde_json::json!({
                        "status": true,
                        "user": ctx.user_view(&updated_user),
                    }),
                    session_token: Some(session.token().to_string()),
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
        .update_user(
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
        if let Some((session_user, session)) = current_session {
            if session_user.email().unwrap_or_default() == claims.email {
                Some(session.token().to_string())
            } else {
                Some(
                    issue_user_session(ctx, &user.id(), ip_address, user_agent)
                        .await
                        .map_err(SessionIssueError::into_auth_error)?
                        .session
                        .token()
                        .to_string(),
                )
            }
        } else {
            Some(
                issue_user_session(ctx, &user.id(), ip_address, user_agent)
                    .await
                    .map_err(SessionIssueError::into_auth_error)?
                    .session
                    .token()
                    .to_string(),
            )
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
