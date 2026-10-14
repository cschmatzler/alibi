//! SCIM server discovery operations.
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointResponse, ServerEndpoint};
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};

#[derive(Clone, Debug, Default)]
pub struct ScimPlugin;
impl ScimPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    /// Discover the installed SCIM protocol capabilities without credentials.
    #[must_use]
    pub const fn service_provider_config_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "getSCIMServiceProviderConfig")
    }
    fn service_provider_config<S: AuthSchema>(ctx: &AuthContext<S>) -> Value {
        json!({
            "schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch":{"supported":true}, "bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},
            "filter":{"supported":true,"maxResults":100}, "changePassword":{"supported":false},
            "sort":{"supported":false},"etag":{"supported":false},
            "authenticationSchemes":[{"name":"OAuth Bearer Token","description":"Authentication using a bearer token in the Authorization header.","specUri":"https://www.rfc-editor.org/info/rfc6750","type":"oauthbearertoken","primary":true}],
            "meta":{"resourceType":"ServiceProviderConfig","location":format!("{}{}{}",ctx.config.base_url.trim_end_matches('/'),ctx.config.base_path.trim_end_matches('/'),"/scim/v2/ServiceProviderConfig")}
        })
    }
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ScimPlugin {
    route_openapi_metadata!(S);
    fn name(&self) -> &'static str {
        "scim"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get(
            "/scim/v2/ServiceProviderConfig",
            "getSCIMServiceProviderConfig",
        )]
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        vec![crate::endpoint::definition(
            "getSCIMServiceProviderConfig",
            "getSCIMServiceProviderConfig",
            Some("/scim/v2/ServiceProviderConfig"),
            HttpMethod::Get,
        )]
    }
    async fn on_endpoint(
        &self,
        _call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        Ok(EndpointResponse::json(&Self::service_provider_config(ctx))?
            .with_header("content-type", "application/scim+json"))
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() != &HttpMethod::Get || req.path() != "/scim/v2/ServiceProviderConfig" {
            return Ok(None);
        }
        Ok(Some(
            AuthResponse::json(200, &Self::service_provider_config(ctx))?
                .with_header("content-type", "application/scim+json"),
        ))
    }
}
