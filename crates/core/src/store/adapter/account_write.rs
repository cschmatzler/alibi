use super::{callback_error, cancelled_by_hook};
use crate::field_policy::FieldValues;
use crate::store::{DatabaseHookContext, DatabaseHooks, HookBackend};
use crate::{AuthResult, AuthSchema, CreateAccount, UpdateAccount};
use chrono::{DateTime, SubsecRound, Utc};
use std::sync::Arc;

async fn prepare_fields(
    additional: &mut FieldValues,
    access_expiry: &mut Option<DateTime<Utc>>,
    refresh_expiry: &mut Option<DateTime<Utc>>,
) -> AuthResult<FieldValues> {
    let mut fields = std::mem::take(additional);
    fields.take_timestamp_input("accessTokenExpiresAt", access_expiry);
    fields.take_timestamp_input("refreshTokenExpiresAt", refresh_expiry);
    fields.apply_adapter_transforms_async().await?;
    Ok(fields)
}

pub async fn prepare_create<S: AuthSchema, B: HookBackend>(
    hooks: &[Arc<dyn DatabaseHooks<S, B>>],
    context: &DatabaseHookContext<'_, B>,
    input: &mut CreateAccount,
) -> AuthResult<(DateTime<Utc>, FieldValues)> {
    for hook in hooks {
        if hook
            .before_create_account(input, context)
            .await?
            .is_cancelled()
        {
            return Err(cancelled_by_hook("account creation"));
        }
    }
    let now = Utc::now().trunc_subsecs(3);
    let fields = prepare_fields(
        &mut input.additional_fields,
        &mut input.access_token_expires_at,
        &mut input.refresh_token_expires_at,
    )
    .await?;
    Ok((now, fields))
}

pub async fn prepare_update<S: AuthSchema, B: HookBackend>(
    hooks: &[Arc<dyn DatabaseHooks<S, B>>],
    context: &DatabaseHookContext<'_, B>,
    id: &str,
    input: &mut UpdateAccount,
) -> AuthResult<FieldValues> {
    for hook in hooks {
        if hook
            .before_update_account(id, input, context)
            .await?
            .is_cancelled()
        {
            return Err(cancelled_by_hook("account update"));
        }
    }
    prepare_fields(
        &mut input.additional_fields,
        &mut input.access_token_expires_at,
        &mut input.refresh_token_expires_at,
    )
    .await
}

pub async fn after_update<S: AuthSchema, B: HookBackend>(
    hooks: &[Arc<dyn DatabaseHooks<S, B>>],
    context: &DatabaseHookContext<'_, B>,
    id: &str,
    account: Option<&S::Account>,
) -> AuthResult<()> {
    for hook in hooks {
        match account {
            Some(account) => hook.after_update_account(account, context).await?,
            None => hook
                .after_update_account_missing(id, context)
                .await
                .map_err(callback_error)?,
        }
    }
    Ok(())
}
