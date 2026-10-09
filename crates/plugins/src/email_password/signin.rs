use super::EmailVerificationPlugin;
use super::types::{SignInCoreResult, SignInRequest, SignInUsernameFailure, SignInUsernameRequest};
use super::{
    EmailPasswordConfig, finalize_sign_in_with_user_core, send_required_sign_in_verification,
    verify_user_password,
};
use crate::authentication_helpers::is_valid_email;
use alibi_core::entity::{AuthAccount, AuthUser};
use alibi_core::utils::password as password_utils;
use alibi_core::wire::UserView;
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResult, RequestMeta};
pub(crate) async fn sign_in_core(
    req: &AuthRequest,
    body: &SignInRequest,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    if !config.enabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "EMAIL_PASSWORD_DISABLED",
            message: "Email and password is not enabled",
        });
    }
    if !is_valid_email(&body.email) {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_EMAIL",
            message: "Invalid email",
        });
    }
    if body.password.encode_utf16().count() > config.effective_max_length() {
        return Err(AuthError::bad_request("Password too long"));
    }
    let user = ctx
        .database
        .get_user_by_email_record(&body.email.to_lowercase())
        .await?;
    let Some(user) = user else {
        drop(
            ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                .await?,
        );
        return Err(AuthError::InvalidCredentials);
    };
    let credential = ctx
        .database
        .get_user_accounts_record(&user.id())
        .await?
        .into_iter()
        .find(|account| {
            account.provider_id() == "credential" && account.account_id() == user.id().as_ref()
        });
    let Some(current_password) = credential
        .as_ref()
        .and_then(AuthAccount::password)
        .filter(|password| !password.is_empty())
    else {
        drop(
            ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                .await?,
        );
        return Err(AuthError::InvalidCredentials);
    };
    password_utils::verify_password(
        config.password_hasher.as_ref(),
        &body.password,
        current_password,
    )
    .await?;

    if config.require_email_verification && !user.email_verified() {
        send_required_sign_in_verification(
            &user,
            body.callback_url.as_deref(),
            email_verification,
            ctx,
        )
        .await?;
        return Err(AuthError::Upstream {
            status: 403,
            code: "EMAIL_NOT_VERIFIED",
            message: "Email not verified",
        });
    }

    finalize_sign_in_with_user_core(
        req,
        user,
        body.remember_me,
        email_verification,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
}

/// Core sign-in by username.
pub(crate) async fn sign_in_username_core(
    req: &AuthRequest,
    body: &SignInUsernameRequest,
    normalized_username: &str,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<SignInCoreResult<UserView>, SignInUsernameFailure> {
    let Some(user) = ctx
        .database
        .get_user_by_username_record(normalized_username)
        .await
        .map_err(SignInUsernameFailure::Auth)?
    else {
        drop(
            ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                .await
                .map_err(SignInUsernameFailure::Auth)?,
        );
        return Err(SignInUsernameFailure::InvalidUsernameOrPassword);
    };

    verify_user_password(&user, &body.password, config, ctx)
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => SignInUsernameFailure::InvalidUsernameOrPassword,
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
            | AuthError::Jwt(_)) => SignInUsernameFailure::Auth(other),
        })?;

    if !user.email_verified()
        && (config.require_email_verification
            || email_verification.is_some_and(EmailVerificationPlugin::is_verification_required))
    {
        send_required_sign_in_verification(
            &user,
            body.callback_url.as_deref(),
            email_verification,
            ctx,
        )
        .await
        .map_err(SignInUsernameFailure::Auth)?;
        return Err(SignInUsernameFailure::EmailNotVerified);
    }

    finalize_sign_in_with_user_core(
        req,
        user,
        body.remember_me,
        email_verification,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
    .map_err(SignInUsernameFailure::Auth)
}
