use alibi_core::entity::{AuthAccount, AuthUser};
use alibi_core::{AuthContext, AuthResult};

/// Fetch the user's credential account, if present.
///
/// # Errors
///
/// Propagates errors from credential-account storage.
pub async fn get_credential_account<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: impl AsRef<str>,
) -> AuthResult<Option<S::Account>> {
    Ok(ctx
        .database
        .get_credential_account_record(user_id.as_ref())
        .await?
        .map(alibi_core::AdapterRecord::into_stored))
}

/// Resolve the user's stored password hash from the credential account.
///
/// # Errors
///
/// Propagates errors from credential-account storage.
pub async fn get_credential_password_hash(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<Option<String>> {
    Ok(get_credential_account(ctx, user.id())
        .await?
        .and_then(|account| account.password().map(str::to_owned)))
}

/// Whether the user currently has a password set.
///
/// # Errors
///
/// Propagates errors from credential-account storage.
pub async fn user_has_password(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<bool> {
    Ok(get_credential_password_hash(ctx, user).await?.is_some())
}
