//! Client credentials grant application authority without a delegated user.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::EndpointResponse;
use alibi_core::session::SessionRequest;
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use serde_json::Value;
impl OAuthProviderPlugin {
    pub(super) async fn machine_grant<S: AuthSchema>(
        &self,
        body: &Value,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let credentials = match super::credentials::extract(body, req, ctx, self, "token").await? {
            Ok(credentials) => credentials,
            Err(response) => return Ok(no_store(response)),
        };
        if credentials.client_id.is_empty() {
            return error("invalid_request", "Missing required client_id");
        }
        let client = match credentials.authenticate(ctx, self).await? {
            Ok(client) => client,
            Err(response) => return Ok(no_store(response)),
        };
        if client
            .metadata
            .get("grant_types")
            .and_then(Value::as_array)
            .is_some_and(|grants| !grants.iter().any(|grant| grant == "client_credentials"))
        {
            return error(
                "unauthorized_client",
                "client is not authorized to use grant type client_credentials",
            );
        }
        if client
            .metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            == Some("none")
        {
            return error(
                "unauthorized_client",
                "public clients cannot use the client_credentials grant",
            );
        }
        let allowed = client
            .metadata
            .get("client_credentials_scopes")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if allowed.is_empty() {
            return error(
                "unauthorized_client",
                "client has no authorized client_credentials scopes",
            );
        }
        let scopes = body
            .get("scope")
            .and_then(Value::as_str)
            .map_or_else(|| allowed.clone(), |value| value.split(' ').collect());
        let invalid = scopes
            .iter()
            .filter(|scope| {
                !allowed.contains(scope)
                    || ["openid", "profile", "email", "offline_access"].contains(scope)
            })
            .copied()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return error(
                "invalid_scope",
                &format!("The following scopes are invalid: {}", invalid.join(", ")),
            );
        }
        let scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        let params = super::OAuthTokenIssueParams::new(client, scopes);
        match self.mint_tokens(ctx, req, &params).await {
            Ok(value) => Ok(no_store(EndpointResponse::json(&value)?)),
            Err(error) => {
                let mut response = EndpointResponse::error(error.error);
                if let Some(body) = error.body {
                    response = response.with_error_body(*body);
                }
                Ok(no_store(response))
            }
        }
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("cache-control", "no-store")
        .with_header("pragma", "no-cache")
}
fn error(code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(400, code, description).map(no_store)
}
