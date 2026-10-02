//! Trusted server-only passwordless-to-credential operation.
use super::super::email_password::EmailPasswordConfig;
use better_auth_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, AuthUser,
    CreateAccount, UpdateAccount,
};

/// Set the authenticated user's password when no password is currently set.
///
/// This is a trusted server API, with no public authentication route and no target
/// user selector. It re-reads the signed-cookie session from physical storage;
/// cached or hook-provided virtual sessions cannot authorize credential changes.
/// The initialized email/password policy and custom hasher apply. Existing
/// sessions remain active, and the configured hasher runs even when an existing
/// password will subsequently cause rejection.
///
/// # Errors
/// Returns an authentication error for absent or invalid authoritative sessions,
/// password-bound errors, `PASSWORD_ALREADY_SET`, or a storage/hasher error.
pub async fn set_password<S: AuthSchema>(
    request: &AuthRequest,
    new_password: &str,
    context: &AuthContext<S>,
) -> AuthResult<()> {
    let (user, _) = context
        .require_authoritative_session(request)
        .await
        .map_err(|error| {
            if matches!(error, AuthError::Unauthenticated) {
                AuthError::Upstream {
                    status: 401,
                    code: "UNAUTHORIZED",
                    message: "Unauthorized",
                }
            } else {
                error
            }
        })?;
    let policy = context.extensions.get::<EmailPasswordConfig>();
    let minimum = policy
        .as_ref()
        .map_or(context.config.password.min_length, |policy| {
            policy.password_min_length
        });
    let maximum = policy
        .as_ref()
        .map_or(128, |policy| policy.password_max_length);
    let length = new_password.encode_utf16().count();
    if length < minimum {
        return Err(AuthError::Upstream {
            status: 400,
            code: "PASSWORD_TOO_SHORT",
            message: "Password too short",
        });
    }
    if length > maximum {
        return Err(AuthError::Upstream {
            status: 400,
            code: "PASSWORD_TOO_LONG",
            message: "Password too long",
        });
    }
    let user_id = user.id();
    let credential = context
        .database
        .get_user_accounts(user_id.as_ref())
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential" && account.account_id() == user_id);
    let hasher = policy
        .as_ref()
        .and_then(|policy| policy.password_hasher.as_ref());
    let hash_context = better_auth_core::PasswordHashContext {
        // The pathless endpoint's handler context uses the published virtual
        // identity. It does not identify a public URL or register a route.
        path: Some("virtual:".into()),
        request: better_auth_core::hooks::current_request_hook_context(),
    };
    let password = context
        .hash_password_with_context(hasher, new_password, Some(&hash_context))
        .await?;
    if let Some(account) = credential {
        if account
            .password()
            .is_some_and(|password| !password.is_empty())
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "PASSWORD_ALREADY_SET",
                message: "User already has a password set",
            });
        }
        drop(
            context
                .database
                .update_account(
                    account.id().as_ref(),
                    UpdateAccount {
                        password: Some(password),
                        ..Default::default()
                    },
                )
                .await?,
        );
    } else {
        drop(
            context
                .database
                .create_account(CreateAccount {
                    user_id: user.id().into_owned(),
                    account_id: user.id().into_owned(),
                    provider_id: "credential".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password),
                })
                .await?,
        );
    }
    Ok(())
}
