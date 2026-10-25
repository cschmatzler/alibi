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

/// Store a reset password in upstream's `resetCredentialPassword` order:
/// spend the reset proof, revoke the user's sessions when configured, then
/// update or create the credential account.
///
/// Upstream runs these steps in one adapter transaction. They run here in the
/// same order without one, matching upstream's adapters without transactions:
/// a later failure leaves the proof spent and revoked sessions revoked, but
/// never stores the new password while the old sessions remain valid.
///
/// # Errors
///
/// Propagates proof, revocation and credential storage errors.
pub(crate) async fn reset_credential_password<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    password_hash: String,
    revoke_sessions: bool,
    consume_proof: impl Future<Output = AuthResult<()>> + Send,
) -> AuthResult<()> {
    consume_proof.await?;
    if revoke_sessions {
        ctx.database.delete_user_sessions(user_id).await?;
    }
    if let Some(account) = get_credential_account(ctx, user_id).await? {
        _ = ctx
            .database
            .update_account_record(
                &account.id(),
                alibi_core::UpdateAccount {
                    password: Some(password_hash),
                    ..Default::default()
                },
            )
            .await?;
    } else {
        _ = ctx
            .database
            .create_account_record(alibi_core::CreateAccount {
                additional_fields: alibi_core::field_policy::FieldValues::default(),
                user_id: user_id.to_owned(),
                account_id: user_id.to_owned(),
                provider_id: "credential".to_owned(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some(password_hash),
            })
            .await?;
    }
    Ok(())
}
