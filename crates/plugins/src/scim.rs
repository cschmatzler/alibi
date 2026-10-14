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
    /// List the SCIM resource types and their optional extensions.
    #[must_use]
    pub const fn resource_types_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "getSCIMResourceTypes")
    }
    fn resource_types<S: AuthSchema>(ctx: &AuthContext<S>) -> Value {
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":1,"itemsPerPage":2,"Resources":[
            {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"User","name":"User","endpoint":"/Users","description":"User Account","schema":"urn:ietf:params:scim:schemas:core:2.0:User","schemaExtensions":[{"schema":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","required":false}],"meta":{"resourceType":"ResourceType","location":format!("{base}/scim/v2/ResourceTypes/User")}},
            {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"Group","name":"Group","endpoint":"/Groups","description":"Group","schema":"urn:ietf:params:scim:schemas:core:2.0:Group","meta":{"resourceType":"ResourceType","location":format!("{base}/scim/v2/ResourceTypes/Group")}}
        ]})
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
        vec![
            AuthRoute::get("/scim/v2/ResourceTypes", "getSCIMResourceTypes"),
            AuthRoute::get(
                "/scim/v2/ServiceProviderConfig",
                "getSCIMServiceProviderConfig",
            ),
        ]
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        vec![
            crate::endpoint::definition(
                "getSCIMResourceTypes",
                "getSCIMResourceTypes",
                Some("/scim/v2/ResourceTypes"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getSCIMServiceProviderConfig",
                "getSCIMServiceProviderConfig",
                Some("/scim/v2/ServiceProviderConfig"),
                HttpMethod::Get,
            ),
        ]
    }
    async fn on_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let value = if call.operation_id() == "getSCIMResourceTypes" {
            Self::resource_types(ctx)
        } else {
            Self::service_provider_config(ctx)
        };
        Ok(EndpointResponse::json(&value)?.with_header("content-type", "application/scim+json"))
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() != &HttpMethod::Get
            || !matches!(
                req.path(),
                "/scim/v2/ServiceProviderConfig" | "/scim/v2/ResourceTypes"
            )
        {
            return Ok(None);
        }
        let value = if req.path() == "/scim/v2/ResourceTypes" {
            Self::resource_types(ctx)
        } else {
            Self::service_provider_config(ctx)
        };
        Ok(Some(
            AuthResponse::json(200, &value)?.with_header("content-type", "application/scim+json"),
        ))
    }
}
