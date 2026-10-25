use alibi_core::entity::{AuthAccount, AuthUser};
use alibi_core::verification::{VerificationConsumption, VerificationSnapshot};
use alibi_core::{AuthContext, AuthResult};
use std::sync::Arc;

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

/// Checks a reset proof's consumed snapshot inside the reset transaction.
pub(crate) type ResetProofCheck =
    Box<dyn Fn(Option<VerificationSnapshot>) -> AuthResult<()> + Send + Sync>;

/// How a reset spends its single-use proof.
pub(crate) enum ResetProof {
    /// Already spent before the write. Values held only in secondary storage
    /// are spent with `getAndDelete`, which cannot roll back.
    Spent,
    /// Spent first inside the reset transaction. The check rejects a proof a
    /// concurrent reset spent or changed, rolling the transaction back.
    InTransaction {
        consumption: VerificationConsumption,
        check: ResetProofCheck,
    },
}

/// Store a reset password as upstream's `resetCredentialPassword` does: spend
/// the reset proof, revoke the user's sessions when configured, then update
/// or create the credential account, all in one write transaction. A failure
/// in any step leaves the proof, the sessions and the old password in place.
///
/// # Errors
///
/// Propagates proof, revocation and credential storage errors.
pub(crate) async fn reset_credential_password<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    password_hash: String,
    revoke_sessions: bool,
    proof: ResetProof,
) -> AuthResult<()> {
    let account_id = get_credential_account(ctx, user_id)
        .await?
        .map(|account| account.id().as_ref().to_owned());
    let user_id = user_id.to_owned();
    let (consumption, check) = match proof {
        ResetProof::Spent => (None, None),
        ResetProof::InTransaction { consumption, check } => {
            (Some(Arc::new(consumption)), Some(check))
        }
    };
    let spent = consumption.clone();
    alibi_core::store::write_transaction(ctx.database.as_ref(), move |tx| {
        Box::pin(async move {
            if let (Some(consumption), Some(check)) = (&spent, &check) {
                check(consumption.consume_in(tx).await?)?;
            }
            if revoke_sessions {
                tx.delete_user_sessions(&user_id).await?;
            }
            if let Some(account_id) = account_id {
                _ = tx
                    .update_account_record(
                        &account_id,
                        alibi_core::UpdateAccount {
                            password: Some(password_hash),
                            ..Default::default()
                        },
                    )
                    .await?;
            } else {
                _ = tx
                    .create_account_record(alibi_core::CreateAccount {
                        additional_fields: alibi_core::field_policy::FieldValues::default(),
                        user_id: user_id.clone(),
                        account_id: user_id,
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
        })
    })
    .await?;
    if let Some(consumption) = consumption {
        consumption.evict().await?;
    }
    Ok(())
}
