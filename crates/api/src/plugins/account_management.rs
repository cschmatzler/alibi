use super::StatusResponse;
use alibi_core::entity::{AuthAccount, AuthUser};
use alibi_core::{AuthContext, AuthError, AuthResult};
use alibi_core::{AuthRequest, AuthResponse};
use serde::Deserialize;
use validator::Validate;

/// Account management plugin for listing and unlinking user accounts.
pub struct AccountManagementPlugin {
    config: AccountManagementConfig,
}

#[derive(Debug, Clone, alibi_core::PluginConfig)]
#[plugin(name = "AccountManagementPlugin")]
pub struct AccountManagementConfig {
    #[config(default = true)]
    pub require_authentication: bool,
}

#[derive(Debug, Deserialize, Validate)]
struct UnlinkAccountRequest {
    #[serde(rename = "accountId")]
    account_id: String,
}

alibi_core::impl_auth_plugin! {
    AccountManagementPlugin, "account-management";
    routes {
        get "/list-accounts" => handle_list_accounts, "list_accounts";
        post "/unlink-account" => handle_unlink_account, "unlink_account";
    }

 extra {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx)
    }
 }
}

// ---------------------------------------------------------------------------
// Old handler methods — delegate to core functions
// ---------------------------------------------------------------------------

impl AccountManagementPlugin {
    async fn handle_list_accounts(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) =
            super::organization::handlers::extension_common::session(req, ctx).await?;
        let filtered = list_accounts_core(&user, ctx).await?;
        Ok(AuthResponse::json(200, &filtered)?)
    }

    async fn handle_unlink_account(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_cached_session(req).await?;

        let unlink_req: UnlinkAccountRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = unlink_account_core(&user, &unlink_req.account_id, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

impl std::fmt::Debug for AccountManagementPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountManagementPlugin")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_accounts_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<Vec<serde_json::Map<String, serde_json::Value>>> {
    let accounts = ctx.database.get_user_accounts_record(&user.id()).await?;
    accounts
        .iter()
        .map(|account| {
            let mut output = ctx.account_view(account)?;
            let scopes = match output.remove("scope") {
                None | Some(serde_json::Value::Null) => Vec::new(),
                Some(serde_json::Value::String(scope)) => scope
                    .split(',')
                    .map(str::trim)
                    .filter(|scope| !scope.is_empty())
                    .map(str::to_owned)
                    .collect(),
                Some(_) => return Err(AuthError::internal("Account scope must be a string")),
            };
            drop(output.insert("scopes".into(), serde_json::to_value(scopes)?));
            Ok(output)
        })
        .collect()
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn unlink_account_core(
    user: &impl AuthUser,
    account_id: &str,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let accounts = ctx.database.get_user_accounts(&user.id()).await?;
    if accounts.len() == 1 && !ctx.config.account.account_linking.allow_unlinking_all {
        return Err(AuthError::bad_request("You can't unlink your last account"));
    }
    let account = accounts
        .iter()
        .find(|account| account.id() == account_id)
        .ok_or_else(|| AuthError::bad_request("Account not found"))?;
    ctx.database.delete_account(&account.id()).await?;
    Ok(StatusResponse { status: true })
}
