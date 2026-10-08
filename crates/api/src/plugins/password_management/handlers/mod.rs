use super::types::{
    ChangePasswordRequest, ChangePasswordResponse, RequestPasswordResetRequest,
    RequestPasswordResetResponse, ResetPasswordRequest, ResetPasswordTokenQuery,
    ResetPasswordTokenResult, VerifyPasswordRequest,
};
use super::{PasswordManagementConfig, StatusResponse};
use crate::plugins::helpers::{get_credential_account, get_credential_password_hash};
use alibi_core::utils::password as password_utils;
use alibi_core::wire::UserView;
use alibi_core::{
    AuthAccount, AuthContext, AuthError, AuthResult, AuthSession, AuthUser, CreateAccount,
    RequestMeta, UpdateAccount,
};
use chrono::{Duration, Utc};
use url::Url;

const PASSWORD_RESET_SUCCESS_MESSAGE: &str =
    "If this email exists in our system, check your email for the reset link";

// ---------------------------------------------------------------------------
// Core functions (framework-agnostic business logic)
// ---------------------------------------------------------------------------

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn request_password_reset_core(
    body: &RequestPasswordResetRequest,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<RequestPasswordResetResponse> {
    if let Some(redirect_to) = &body.redirect_to {
        validate_redirect_target(redirect_to, ctx, "Invalid redirectURL")?;
    }

    let sender = config
        .send_reset_password
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("Reset password isn't enabled"))?;

    let success = RequestPasswordResetResponse {
        status: true,
        message: PASSWORD_RESET_SUCCESS_MESSAGE.to_owned(),
    };

    let Some(user) = ctx.database.get_user_by_email_record(&body.email).await? else {
        drop(alibi_core::utils::id::generate_id(24));
        drop(ctx.verifications().find("dummy-verification-token").await?);
        tracing::warn!("Reset Password: User not found");
        return Ok(success);
    };

    let reset_token = alibi_core::utils::id::generate_id(24);
    let expires_at = Utc::now()
        + config
            .reset_token_expiry
            .filter(|duration| !duration.is_zero())
            .unwrap_or_else(|| Duration::hours(config.reset_token_expiry_hours));

    drop(
        ctx.verifications()
            .create(alibi_core::CreateVerification {
                identifier: format!("reset-password:{reset_token}"),
                value: user.id().to_string(),
                expires_at,
            })
            .await?,
    );

    let callback_url = body
        .redirect_to
        .as_deref()
        .map(urlencoding::encode)
        .unwrap_or_default();
    let auth_url = crate::plugins::helpers::auth_base_url(&ctx.config);
    let reset_url = format!("{auth_url}/reset-password/{reset_token}?callbackURL={callback_url}");

    let user_value = password_utils::serialize_to_value(&ctx.user_view(&user))?;
    let sender = std::sync::Arc::clone(sender);
    crate::plugins::authentication_helpers::run_owned_notification(
        ctx,
        async move { sender.send(&user_value, &reset_url, &reset_token).await },
        ctx.config.awaited_notification_errors,
    )
    .await?;

    Ok(success)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn reset_password_core(
    body: &ResetPasswordRequest,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let token = body.token.as_deref().unwrap_or("");
    if token.is_empty() {
        return Err(AuthError::bad_request("Invalid token"));
    }

    let (minimum, maximum) = crate::plugins::email_password::password_length_limits(ctx);
    password_utils::validate_password(&body.new_password, minimum, maximum, ctx)?;
    let policy = ctx.extensions.get::<crate::plugins::EmailPasswordConfig>();

    let verification = ctx
        .verifications()
        .consume(&format!("reset-password:{token}"))
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid token"))?;
    let user_id = verification.value()?.to_owned();
    let user = ctx
        .database
        .get_user_by_id_record(&user_id)
        .await?
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "USER_NOT_FOUND",
            message: "User not found",
        })?;

    let hasher = policy
        .as_ref()
        .and_then(|policy| policy.password_hasher.as_ref())
        .or(config.password_hasher.as_ref());
    let password_hash = ctx.hash_password(hasher, &body.new_password).await?;

    if let Some(account) = get_credential_account(ctx, &user_id).await? {
        drop(
            ctx.database
                .update_account_record(
                    &account.id(),
                    UpdateAccount {
                        password: Some(password_hash),
                        ..Default::default()
                    },
                )
                .await?,
        );
    } else {
        drop(
            ctx.database
                .create_account_record(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user_id.clone(),
                    account_id: user_id.clone(),
                    provider_id: "credential".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash),
                })
                .await?,
        );
    }

    if let Some(callback) = &config.on_password_reset {
        callback(password_utils::serialize_to_value(&ctx.user_view(&user))?).await?;
    }

    if config.revoke_sessions_on_password_reset {
        ctx.database.delete_user_sessions(&user_id).await?;
    }

    Ok(StatusResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn reset_password_token_core(
    token: &str,
    query: &ResetPasswordTokenQuery,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<ResetPasswordTokenResult> {
    if let Some(callback_url) = &query.callback_url {
        validate_redirect_target(callback_url, ctx, "Invalid callbackURL")?;
    }

    if token.is_empty() || query.callback_url.is_none() {
        return Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
            &ctx.config.base_url,
            query.callback_url.as_deref(),
            &[("error", "INVALID_TOKEN")],
        )?));
    }

    let verification = ctx
        .verifications()
        .find(&format!("reset-password:{token}"))
        .await?;

    if verification
        .as_ref()
        .is_none_or(|verification| verification.is_expired())
    {
        return Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
            &ctx.config.base_url,
            query.callback_url.as_deref(),
            &[("error", "INVALID_TOKEN")],
        )?));
    }

    Ok(ResetPasswordTokenResult::Redirect(build_redirect_url(
        &ctx.config.base_url,
        query.callback_url.as_deref(),
        &[("token", token)],
    )?))
}

/// Change the user's password. Returns the response and an optional new session token.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn change_password_core<S: alibi_core::AuthSchema>(
    body: &ChangePasswordRequest,
    user: &alibi_core::AdapterRecord<S::User>,
    config: &PasswordManagementConfig,
    meta: &RequestMeta,
    ctx: &AuthContext<S>,
) -> AuthResult<(ChangePasswordResponse<UserView>, Option<String>)> {
    let credential_account = get_credential_account(ctx, user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Credential account not found"))?;
    let stored_hash = if config.require_current_password {
        Some(
            credential_account
                .password()
                .ok_or_else(|| AuthError::bad_request("Credential account not found"))?
                .to_owned(),
        )
    } else {
        None
    };

    let (minimum, maximum) = crate::plugins::email_password::password_length_limits(ctx);
    password_utils::validate_password(&body.new_password, minimum, maximum, ctx)?;

    let password_hash = ctx
        .hash_password(config.password_hasher.as_ref(), &body.new_password)
        .await?;

    if let Some(stored_hash) = stored_hash {
        password_utils::verify_password(
            config.password_hasher.as_ref(),
            &body.current_password,
            &stored_hash,
        )
        .await
        .map_err(|_error| AuthError::bad_request("Invalid password"))?;
    }

    drop(
        ctx.database
            .update_account_record(
                &credential_account.id(),
                UpdateAccount {
                    password: Some(password_hash),
                    ..Default::default()
                },
            )
            .await?,
    );

    let new_token = if body.revoke_other_sessions == Some(true) {
        ctx.database.delete_user_sessions(&user.id()).await?;
        let session = ctx
            .session_manager()
            .create_session_record(user, meta.ip_address.clone(), meta.user_agent.clone())
            .await?;
        let user = ctx.filter_user_record(user.clone());
        alibi_core::session::cookie_cache::runtime::emit_issuance(ctx, &user, &session).await?;
        crate::plugins::helpers::record_completed_session_record::<S>(&user, &session);
        Some(session.token().to_owned())
    } else {
        None
    };

    let response = ChangePasswordResponse {
        token: new_token.clone(),
        user: ctx.user_view(user),
    };

    Ok((response, new_token))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn verify_password_core(
    body: &VerifyPasswordRequest,
    user: &impl AuthUser,
    config: &PasswordManagementConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let (_, maximum) = crate::plugins::email_password::password_length_limits(ctx);
    if body.password.encode_utf16().count() > maximum {
        return Err(AuthError::bad_request("Password too long"));
    }
    let policy = ctx.extensions.get::<crate::plugins::EmailPasswordConfig>();
    let hasher = policy
        .as_ref()
        .and_then(|policy| policy.password_hasher.as_ref())
        .or(config.password_hasher.as_ref());
    let stored_hash = get_credential_password_hash(ctx, user)
        .await?
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;

    password_utils::verify_password(hasher, &body.password, &stored_hash)
        .await
        .map_err(|error| match error {
            error if error.status_code() != 500 => error,
            AuthError::Api { .. } | AuthError::Upstream { .. } | AuthError::CallbackFailure(_) => {
                error
            }
            error => AuthError::CallbackFailure(Box::new(error)),
        })
        .map_err(|error| match error {
            AuthError::InvalidCredentials => AuthError::bad_request("Invalid password"),
            other @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::Unauthenticated
            | AuthError::AuthenticationFailed(_)
            | AuthError::SessionNotFound
            | AuthError::Forbidden(_)
            | AuthError::UserCreationCancelled
            | AuthError::SessionCreationCancelled
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
            | AuthError::Jwt(_)) => other,
        })?;

    Ok(StatusResponse { status: true })
}

fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.current_origin_check_disabled() {
        return Ok(());
    }
    if ctx.config.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_owned()))
    }
}

fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    let base = Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {error}")))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url).map_err(|error| {
            // Upstream sends the bare message so the response carries the
            // INVALID_CALLBACK_URL code; keep the parse detail in the log.
            tracing::warn!(error = %error, callback_url, "Invalid callbackURL");
            AuthError::bad_request("Invalid callbackURL")
        })?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {error}")))?
    };

    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    for (key, value) in params {
        let mut replaced = false;
        pairs.retain_mut(|(name, previous)| {
            if name != key {
                return true;
            }
            if replaced {
                return false;
            }
            *previous = (*value).to_owned();
            replaced = true;
            true
        });
        if !replaced {
            pairs.push(((*key).to_owned(), (*value).to_owned()));
        }
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);

    Ok(url.to_string())
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck respects ctx.context.skipOriginCheck.
    #[tokio::test]
    async fn validate_redirect_target_respects_disable_origin_check() {
        let config = test_helpers::create_test_config().disable_origin_check(true);
        let ctx = test_helpers::create_test_context_with_config(config).await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid redirectURL").is_ok()
        );
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck rejects untrusted origins by default.
    #[tokio::test]
    async fn validate_redirect_target_rejects_untrusted_by_default() {
        let ctx = test_helpers::create_test_context().await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid redirectURL")
                .is_err()
        );
    }
}
// LCOV_EXCL_STOP
