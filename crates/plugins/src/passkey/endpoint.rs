//! Public server operations over the shared passkey engines.
use super::{PasskeyPlugin, list_user_passkeys_core};
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointResponse, ServerEndpoint};
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde_json::Value;

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![crate::endpoint::definition(
        "listPasskeys",
        "listPasskeys",
        Some("/passkey/list-user-passkeys"),
        HttpMethod::Get,
    )]
}

impl PasskeyPlugin {
    /// List the caller's registered credentials under its signed session.
    #[must_use]
    pub fn list_passkeys_endpoint() -> ServerEndpoint<Vec<Value>> {
        ServerEndpoint::new("passkey", "listPasskeys")
    }

    pub(super) async fn list_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = crate::helpers::ordinary_session(call, ctx).await?;
        EndpointResponse::json(&list_user_passkeys_core(&user, ctx).await?)
    }
}
