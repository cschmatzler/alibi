use super::{callback_error, cancelled_by_hook};
use crate::store::{DatabaseHookContext, DatabaseHooks, HookBackend, PreparedUserUpdate};
use crate::{AuthResult, AuthSchema};
use std::sync::Arc;

pub async fn prepare_update<S: AuthSchema, B: HookBackend>(
    hooks: &[Arc<dyn DatabaseHooks<S, B>>],
    context: &DatabaseHookContext<'_, B>,
    id: &str,
    update: &mut PreparedUserUpdate,
) -> AuthResult<()> {
    for hook in hooks {
        if hook
            .before_update_user(id, &mut update.data, context)
            .await
            .map_err(callback_error)?
            .is_cancelled()
        {
            return Err(cancelled_by_hook("user update"));
        }
    }
    update.apply_adapter_transforms().await
}

pub async fn after_update<S: AuthSchema, B: HookBackend>(
    hooks: &[Arc<dyn DatabaseHooks<S, B>>],
    context: &DatabaseHookContext<'_, B>,
    id: &str,
    user: Option<&S::User>,
) -> AuthResult<()> {
    for hook in hooks {
        match user {
            Some(user) => hook.after_update_user(user, context).await,
            None => hook.after_update_user_missing(id, context).await,
        }
        .map_err(callback_error)?;
    }
    Ok(())
}
