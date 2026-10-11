use super::StatusResponse;
use super::authentication_helpers::{JsonField, RequestBody, parse_body};
use alibi_core::entity::{AuthAccount, AuthUser};
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult};
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

impl RequestBody for UnlinkAccountRequest {
    const FIELDS: &'static [JsonField] = &[JsonField::string("accountId", true)];
}

alibi_core::impl_auth_plugin! {
    AccountManagementPlugin, "account-management";
    routes {
        get "/list-accounts" => handle_list_accounts, "list_accounts";
        post "/unlink-account" => handle_unlink_account, "unlink_account";
    }

 extra {
    route_openapi_metadata!(S);

    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        vec![crate::endpoint::definition(
            "listUserAccounts", "listUserAccounts", Some("/list-accounts"),
            alibi_core::HttpMethod::Get,
        )]
    }

    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        let (user, session) = ctx.require_cached_session(call).await.map_err(|error| {
            if matches!(error, AuthError::Unauthenticated | AuthError::SessionNotFound) {
                super::organization::handlers::extension_common::org_error(401, "UNAUTHORIZED")
            } else {
                error
            }
        })?;
        call.record_authenticated_session(match &user {
            alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(user),
            alibi_core::AuthenticatedUser::Cached(user) => (**user).clone(),
        }, session);
        alibi_core::endpoint::EndpointResponse::json(&list_accounts_core(&user, ctx).await?)
    }
 }
}

impl AccountManagementPlugin {
    /// List the authenticated caller's linked accounts through logical endpoint hooks.
    ///
    /// The result retains configured account output fields and parsed scopes, while
    /// omitting credentials. Supply incoming headers using `EndpointOptions`.
    #[must_use]
    pub const fn list_accounts_endpoint()
    -> alibi_core::endpoint::ServerEndpoint<Vec<serde_json::Map<String, serde_json::Value>>> {
        alibi_core::endpoint::ServerEndpoint::new("account-management", "listUserAccounts")
    }

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

        let unlink_req: UnlinkAccountRequest = match parse_body(req) {
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

pub(crate) async fn list_accounts_core(
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
            _ = output.insert("scopes".into(), serde_json::to_value(scopes)?);
            Ok(output)
        })
        .collect()
}

pub(crate) async fn unlink_account_core(
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
