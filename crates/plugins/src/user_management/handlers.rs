use super::UserManagementConfig;
use super::types::{ChangeEmailRequest, DeleteUserRequest};
use crate::email_password::EmailPasswordConfig;
use crate::email_verification::EmailVerificationConfig;
use crate::email_verification::handlers::verification_url;
use crate::email_verification::token::create_email_verification_token;
use alibi_core::SuccessMessageResponse;
use alibi_core::entity::{AuthAccount, AuthSession, AuthUser};
use alibi_core::utils::password as password_utils;
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResult, UpdateUser};
use chrono::{Duration, Utc};
use rand::RngExt;

/// Send an email using the configured email provider, logging on failure.
pub(super) async fn send_email_or_log(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    to: &str,
    subject: &str,
    html: &str,
    text: &str,
    action: &str,
) {
    if let Ok(provider) = ctx.email_provider() {
        if let Err(error) = provider.send(to, subject, html, text).await {
            tracing::warn!(
                plugin = "user-management",
                action = action,
                error = %error,
                "Failed to send email"
            );
        }
    } else {
        tracing::warn!(
            plugin = "user-management",
            action = action,
            "No email provider configured, skipping email"
        );
    }
}

pub(super) async fn authoritative_session<S: alibi_core::AuthSchema>(
    request: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<(S::User, SessionView)> {
    let (user, session) = ctx
        .require_authoritative_session(request)
        .await
        .map_err(|error| {
            if matches!(
                error,
                AuthError::Unauthenticated | AuthError::SessionNotFound | AuthError::UserNotFound
            ) {
                AuthError::Upstream {
                    status: 401,
                    code: "UNAUTHORIZED",
                    message: "Unauthorized",
                }
            } else {
                error
            }
        })?;
    let dont_remember = super::super::helpers::get_cookie(
        request,
        &alibi_core::utils::cookie_utils::related_cookie_name(&ctx.config, "dont_remember"),
    )
    .and_then(|value| {
        alibi_core::utils::cookie_utils::verify_cookie_value(&value, ctx.config.current_secret())
    })
    .is_some_and(|value| !value.is_empty());
    if !dont_remember
        && !ctx.session_manager().request_disables_refresh(request)
        && ctx
            .config
            .session
            .cookie_cache
            .as_ref()
            .is_some_and(|config| config.enabled)
        && let Some(stored) = ctx.database.get_session(&session.token).await?
    {
        for header in alibi_core::session::cookie_cache::runtime::stored_headers(
            ctx,
            &user,
            &stored,
            &request.headers,
            false,
        )
        .await?
        {
            request.queue_response_header("Set-Cookie", header);
        }
    }
    Ok((user, session))
}

async fn send_verification(
    user: &UserView,
    token: &str,
    callback_url: Option<&str>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    let config = ctx.extensions.get::<EmailVerificationConfig>();
    let url = verification_url(&ctx.config, token, callback_url);
    if let Some(sender) = config
        .as_ref()
        .and_then(|config| config.send_verification_email.as_ref())
    {
        super::super::authentication_helpers::run_notification(sender.send(user, &url, token))
            .await;
    } else if let Some(sender) = ctx.email_verification_override() {
        sender.0.send(user, None, ctx).await?;
    } else if let Some(provider) = &ctx.email_provider {
        let text = format!("Confirm your email change: {url}");
        let html = format!("<p><a href=\"{url}\">Confirm Email Change</a></p>");
        super::super::authentication_helpers::run_notification(provider.send(
            user.email.as_deref().unwrap_or_default(),
            "Confirm your email change",
            &html,
            &text,
        ))
        .await;
    }
    Ok(())
}

/// Return the original-session projection only when this stage renews its cookie.
pub(crate) async fn change_email_core(
    body: &ChangeEmailRequest,
    user: &impl AuthUser,
    session: &SessionView,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<Option<UserView>> {
    let new_email = body.new_email.to_lowercase();
    if user.email().is_some_and(|email| email == new_email) {
        return Err(AuthError::Api {
            status: 400,
            code: None,
            message: "Email is the same".into(),
        });
    }
    let verification = ctx.extensions.get::<EmailVerificationConfig>();
    let can_update = !user.email_verified() && config.change_email.update_without_verification;
    let can_send = verification
        .as_ref()
        .is_some_and(|config| config.send_verification_email.is_some())
        || ctx.email_verification_override().is_some()
        || ctx.email_provider.is_some();
    if !can_update && !can_send {
        return Err(AuthError::Api {
            status: 400,
            code: None,
            message: "Verification email isn't enabled".into(),
        });
    }
    let expiry = verification.as_ref().map_or_else(
        || Duration::hours(1),
        |config| config.verification_token_expiry,
    );
    if ctx
        .database
        .get_user_by_email_record(&new_email)
        .await?
        .is_some()
    {
        drop(create_email_verification_token(
            ctx.config.current_secret(),
            user.email().unwrap_or_default(),
            Some(&new_email),
            expiry,
            None,
        )?);
        return Ok(None);
    }
    let mut projection = ctx.user_view(user);
    projection.email = Some(new_email.clone());
    if can_update {
        drop(
            ctx.database
                .update_user_record(
                    &user.id(),
                    UpdateUser {
                        email: Some(new_email.clone()),
                        ..Default::default()
                    },
                )
                .await?,
        );
        renew_session_snapshot(&projection, session, ctx).await?;
        if can_send {
            let token = create_email_verification_token(
                ctx.config.current_secret(),
                &new_email,
                None,
                expiry,
                None,
            )?;
            send_verification(&projection, &token, body.callback_url.as_deref(), ctx).await?;
        }
        return Ok(Some(projection));
    }
    let can_confirm =
        user.email_verified() && config.change_email.send_change_email_confirmation.is_some();
    let request_type = if can_confirm {
        "change-email-confirmation"
    } else {
        "change-email-verification"
    };
    let token = create_email_verification_token(
        ctx.config.current_secret(),
        user.email().unwrap_or_default(),
        Some(&new_email),
        expiry,
        Some(request_type),
    )?;
    if let Some(sender) = config
        .change_email
        .send_change_email_confirmation
        .as_ref()
        .filter(|_| can_confirm)
    {
        let url = verification_url(&ctx.config, &token, body.callback_url.as_deref());
        super::super::authentication_helpers::run_notification(sender.send(
            &ctx.user_view(user),
            &new_email,
            &url,
            &token,
        ))
        .await;
    } else {
        send_verification(&projection, &token, body.callback_url.as_deref(), ctx).await?;
    }
    Ok(None)
}

pub(crate) async fn renew_session_snapshot<S: alibi_core::AuthSchema>(
    user: &UserView,
    session: &SessionView,
    ctx: &AuthContext<S>,
) -> AuthResult<()> {
    // Source renews the chosen session/user projection. It does not replace
    // callback inputs with adapter rows reread after the authenticated stage.
    alibi_core::session::cookie_cache::runtime::emit_issuance_snapshot(
        ctx,
        alibi_core::CacheVersionContext::created(
            user.clone(),
            session.clone(),
            user.clone(),
            session.clone(),
        ),
    )
    .await?;
    if let Some(stored) = ctx.database.get_session(&session.token).await?
        && stored.user_id() == user.id
        && let Some(original) = ctx.database.get_user_by_id(&user.id).await?
    {
        super::super::helpers::record_completed_session::<S>(&original, &stored);
        super::super::helpers::record_completed_session_user_view::<S>(
            &original,
            &stored,
            user.clone(),
        );
    }
    Ok(())
}

pub(crate) async fn delete_user_core(
    body: &DeleteUserRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    request: &AuthRequest,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SuccessMessageResponse> {
    let password = body.password.as_deref().filter(|value| !value.is_empty());
    if let Some(password) = password {
        let policy = ctx.extensions.get::<EmailPasswordConfig>();
        if password.encode_utf16().count()
            > policy
                .as_ref()
                .map_or(128, |policy| policy.password_max_length)
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "PASSWORD_TOO_LONG",
                message: "Password too long",
            });
        }
        let account = crate::helpers::get_credential_account(ctx, user.id())
            .await?
            .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
        let stored_hash = account
            .password()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
        if let Err(error) = password_utils::verify_password(
            policy
                .as_ref()
                .and_then(|policy| policy.password_hasher.as_ref()),
            password,
            stored_hash,
        )
        .await
        {
            return Err(if matches!(error, AuthError::InvalidCredentials) {
                AuthError::bad_request("Invalid password")
            } else {
                error
            });
        }
    }
    if let Some(token) = body.token.as_deref().filter(|value| !value.is_empty()) {
        // Source invokes the callback as a nested endpoint here, then drops
        // that endpoint's response headers while preserving its writes/errors.
        return delete_user_callback_core(token, user, request, false, config, ctx).await;
    }
    if config
        .delete_user
        .send_delete_account_verification
        .is_some()
        || config.delete_user.require_verification
    {
        let token: String = (0..32)
            .map(|_| {
                let value = rand::rng().random_range(0_u8..36);
                char::from(if value < 10 {
                    b'0' + value
                } else {
                    b'a' + value - 10
                })
            })
            .collect();
        let expiry = if config.delete_user.delete_token_expires_in == Duration::zero() {
            Duration::hours(24)
        } else {
            config.delete_user.delete_token_expires_in
        };
        drop(
            ctx.verifications()
                .create(alibi_core::CreateVerification {
                    identifier: format!("delete-account-{token}"),
                    value: user.id().into_owned(),
                    expires_at: Utc::now() + expiry,
                })
                .await?,
        );
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        let url = format!(
            "{base}/delete-user/callback?token={token}&callbackURL={}",
            urlencoding::encode(
                body.callback_url
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or("/")
            )
        );
        if let Some(sender) = &config.delete_user.send_delete_account_verification {
            super::super::authentication_helpers::run_notification(sender.send(
                &ctx.user_view(user),
                &url,
                &token,
            ))
            .await;
        } else {
            let email = user
                .email()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AuthError::bad_request(
                        "Cannot send verification email: user has no email address",
                    )
                })?;
            let html = format!("<p><a href=\"{url}\">Confirm Account Deletion</a></p>");
            let text = format!("Confirm account deletion: {url}");
            send_email_or_log(
                ctx,
                email,
                "Confirm account deletion",
                &html,
                &text,
                "delete-user",
            )
            .await;
        }
        return Ok(SuccessMessageResponse {
            success: true,
            message: "Verification email sent".into(),
        });
    }
    if password.is_none()
        && let Some(fresh_age) = ctx.config.session.fresh_age
        && fresh_age != Duration::zero()
        && session.created_at() + fresh_age <= Utc::now()
    {
        return Err(AuthError::bad_request(
            "Session expired. Re-authenticate to perform this action.",
        ));
    }
    perform_user_deletion(user, request, true, config, ctx).await?;
    Ok(SuccessMessageResponse {
        success: true,
        message: "User deleted".into(),
    })
}

pub(crate) async fn delete_user_callback_core(
    token: &str,
    user: &impl AuthUser,
    request: &AuthRequest,
    clear_cookie_errors: bool,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SuccessMessageResponse> {
    let verification = ctx
        .verifications()
        .consume(&format!("delete-account-{token}"))
        .await?
        .filter(|verification| verification.value().is_ok_and(|value| value == user.id()))
        .ok_or_else(|| AuthError::not_found("Invalid token"))?;
    drop(verification);
    perform_user_deletion(user, request, clear_cookie_errors, config, ctx).await?;
    Ok(SuccessMessageResponse {
        success: true,
        message: "User deleted".into(),
    })
}

async fn perform_user_deletion(
    user: &impl AuthUser,
    request: &AuthRequest,
    clear_cookie_errors: bool,
    config: &UserManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    let snapshot = ctx.user_view(user);
    if let Some(hook) = &config.delete_user.before_delete {
        hook.before_delete(&snapshot).await?;
    }
    ctx.database.delete_user_sessions(&user.id()).await?;
    for account in ctx.database.get_user_accounts_record(&user.id()).await? {
        ctx.database.delete_account(&account.id()).await?;
    }
    ctx.database.delete_user(&user.id()).await?;
    if let Some(hook) = &config.delete_user.after_delete
        && let Err(error) = hook.after_delete(&snapshot).await
    {
        if clear_cookie_errors {
            for cookie in
                alibi_core::utils::cookie_utils::delete_session_cookie_headers(&ctx.config)?
            {
                request.queue_response_header("Set-Cookie", cookie);
            }
        }
        return Err(error);
    }
    Ok(())
}
