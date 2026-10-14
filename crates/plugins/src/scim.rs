//! SCIM server discovery operations.
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointResponse, ServerEndpoint};
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};
mod authentication;
mod collection;
mod managed;
mod projection;
mod resources;
mod user_attributes;
mod user_profile;
pub use authentication::{ScimBearerTokenVerificationInput, ScimBearerTokenVerifier};
pub use managed::{ScimManagedConnectionInput, ScimManagedCredentialRotationInput};
pub use projection::{
    ConfiguredScimPlugin, ScimAuthorizationSource, ScimIdentity, ScimIdentityResolution,
    ScimIdentityResolutionInput, ScimIdentitySource, ScimIdentityState, ScimProjectedUserState,
    ScimProjection, ScimRoleExistenceInput, ScimRoleMappingInput, ScimRoleProjection,
};

/// A static inbound provisioning credential.
#[derive(Clone)]
pub struct ScimCredential {
    pub id: String,
    pub token: String,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl std::fmt::Debug for ScimCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimCredential")
            .field("id", &self.id)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl ScimCredential {
    #[must_use]
    pub fn new(id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            token: token.into(),
            scopes: None,
            expires_at: None,
        }
    }
}
/// A connection owns an isolated set of canonical SCIM resources.
#[derive(Clone, Debug)]
pub struct ScimConnectionOptions {
    pub id: String,
    pub provisioning_domain_id: Option<String>,
    pub credentials: Vec<ScimCredential>,
}
/// Policy for the framework-managed provisioning credential catalog.
#[derive(Clone)]
pub struct ScimManagedConnectionOptions {
    pub credential_hash_secret: String,
    pub max_active_credentials: usize,
    pub last_used_write_interval_seconds: u64,
}
impl std::fmt::Debug for ScimManagedConnectionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimManagedConnectionOptions")
            .field("max_active_credentials", &self.max_active_credentials)
            .field(
                "last_used_write_interval_seconds",
                &self.last_used_write_interval_seconds,
            )
            .finish_non_exhaustive()
    }
}
impl ScimManagedConnectionOptions {
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            credential_hash_secret: secret.into(),
            max_active_credentials: 5,
            last_used_write_interval_seconds: 300,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct ScimPlugin {
    managed_connections: Option<ScimManagedConnectionOptions>,
    connections: Vec<ScimConnectionOptions>,
    has_token_verifier: bool,
}
impl ScimPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            managed_connections: None,
            connections: Vec::new(),
            has_token_verifier: false,
        }
    }
    #[must_use]
    pub fn managed_connections(mut self, options: ScimManagedConnectionOptions) -> Self {
        self.managed_connections = Some(options);
        self
    }
    #[must_use]
    pub fn connections(mut self, connections: Vec<ScimConnectionOptions>) -> Self {
        self.connections = connections;
        self
    }
    /// Delete a canonical User and reconcile its durable identity and access state.
    /// # Errors
    /// Returns an error if parameters cannot be serialized.
    pub fn delete_user_endpoint(id: &str) -> AuthResult<ServerEndpoint<()>> {
        ServerEndpoint::new("scim", "deleteSCIMUser").with_params(&json!({"userId":id}))
    }
    /// Apply SCIM PATCH operations to a connection-owned canonical Group.
    /// # Errors
    /// Returns an error if parameters cannot be serialized.
    pub fn patch_group_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "patchSCIMGroup").with_params(&json!({"groupId":id}))
    }
    /// Replace all mutable attributes of a connection-owned canonical Group.
    /// # Errors
    /// Returns an error if parameters cannot be serialized.
    pub fn replace_group_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "replaceSCIMGroup").with_params(&json!({"groupId":id}))
    }
    /// Delete a connection-owned canonical SCIM Group.
    /// # Errors
    /// Returns an error if parameters cannot be serialized.
    pub fn delete_group_endpoint(id: &str) -> AuthResult<ServerEndpoint<()>> {
        ServerEndpoint::new("scim", "deleteSCIMGroup").with_params(&json!({"groupId":id}))
    }
    /// Provision a connection-owned canonical SCIM User.
    #[must_use]
    pub const fn create_user_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "createSCIMUser")
    }
    /// Create a connection-owned canonical SCIM Group.
    #[must_use]
    pub const fn create_group_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "createSCIMGroup")
    }
    /// List the connection-owned SCIM Users through the server API.
    #[must_use]
    pub const fn users_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "listSCIMUsers")
    }
    /// List the connection-owned SCIM Groups through the server API.
    #[must_use]
    pub const fn groups_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "listSCIMGroups")
    }
    /// Read a connection-owned SCIM User through the server API.
    /// # Errors
    /// Returns an error if parameters cannot be serialized.
    pub fn user_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "getSCIMUser").with_params(&json!({"userId":id}))
    }
    /// Read a connection-owned SCIM Group through the server API.
    /// # Errors
    /// Returns an error if parameters cannot be serialized.
    pub fn group_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "getSCIMGroup").with_params(&json!({"groupId":id}))
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
    /// List the SCIM User, Enterprise User and Group schema contracts.
    #[must_use]
    pub const fn schemas_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("scim", "getSCIMSchemas")
    }
    fn schemas<S: AuthSchema>(ctx: &AuthContext<S>) -> AuthResult<Value> {
        // Runtime protocol descriptors match @better-auth/scim 1.7.7; keep them
        // independent of test fixtures and resolve locations for this application.
        let mut schemas: Vec<Value> = serde_json::from_str(include_str!("scim/schemas.json"))?;
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        for schema in &mut schemas {
            if let Some(meta) = schema.get_mut("meta").and_then(Value::as_object_mut)
                && let Some(path) = meta.get("location").and_then(Value::as_str)
            {
                let location = format!("{base}{path}");
                _ = meta.insert("location".into(), Value::String(location));
            }
        }
        Ok(
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":schemas.len(),"startIndex":1,"itemsPerPage":schemas.len(),"Resources":schemas}),
        )
    }
    /// Read a SCIM schema by its raw or URI-encoded identifier.
    /// # Errors
    /// Returns an error if path parameters cannot be serialized.
    pub fn schema_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "getSCIMSchema").with_params(&json!({"schemaId":id}))
    }
    fn schema<S: AuthSchema>(ctx: &AuthContext<S>, id: &str) -> AuthResult<EndpointResponse> {
        let decoded = urlencoding::decode(id).unwrap_or(std::borrow::Cow::Borrowed(id));
        let schemas = Self::schemas(ctx)?;
        let schema = schemas
            .get("Resources")
            .and_then(Value::as_array)
            .and_then(|schemas| {
                schemas.iter().find(|schema| {
                    schema.get("id").and_then(Value::as_str) == Some(decoded.as_ref())
                })
            });
        Self::discovery_result(schema, "Schema not found")
    }
    fn discovery_result(resource: Option<&Value>, detail: &str) -> AuthResult<EndpointResponse> {
        let response = if let Some(resource) = resource {
            EndpointResponse::json(resource)?
        } else {
            EndpointResponse::error(AuthError::Api {status:404,code:None,message:detail.into()})
                .with_error_body(alibi_core::utils::json::parse_value(&json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":detail}).to_string())?)
        };
        Ok(response.with_header("content-type", "application/scim+json"))
    }
    /// Read one case-sensitive SCIM resource type through the server API.
    /// # Errors
    /// Returns an error if the path parameters cannot be serialized.
    pub fn resource_type_endpoint(id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "getSCIMResourceType")
            .with_params(&json!({"resourceTypeId":id}))
    }
    fn resource_type<S: AuthSchema>(
        ctx: &AuthContext<S>,
        id: Option<&str>,
    ) -> AuthResult<EndpointResponse> {
        let types = Self::resource_types(ctx);
        let resource = types
            .get("Resources")
            .and_then(Value::as_array)
            .and_then(|types| {
                types
                    .iter()
                    .find(|resource| resource.get("id").and_then(Value::as_str) == id)
            });
        Self::discovery_result(resource, "Resource type not found")
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
    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        // SCIM emits protocol-specific admission errors in its request handler.
        if route.path == "/scim/v2/Users"
            || route.path == "/scim/v2/Groups"
            || (route.path.starts_with("/scim/v2/Groups/")
                && matches!(route.method, HttpMethod::Put | HttpMethod::Patch))
        {
            Vec::new()
        } else {
            vec!["application/json"]
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/scim/v2/Users", "createSCIMUser"),
            AuthRoute::post("/scim/v2/Groups", "createSCIMGroup"),
            AuthRoute::delete("/scim/v2/Users/{userId}", "deleteSCIMUser"),
            AuthRoute::put("/scim/v2/Groups/{groupId}", "replaceSCIMGroup"),
            AuthRoute::new(
                HttpMethod::Patch,
                "/scim/v2/Groups/{groupId}",
                "patchSCIMGroup",
            ),
            AuthRoute::delete("/scim/v2/Groups/{groupId}", "deleteSCIMGroup"),
            AuthRoute::get("/scim/v2/Users", "listSCIMUsers"),
            AuthRoute::get("/scim/v2/Groups", "listSCIMGroups"),
            AuthRoute::get("/scim/v2/Users/{userId}", "getSCIMUser"),
            AuthRoute::get("/scim/v2/Groups/{groupId}", "getSCIMGroup"),
            AuthRoute::get("/scim/v2/Schemas", "getSCIMSchemas"),
            AuthRoute::get("/scim/v2/Schemas/{schemaId}", "getSCIMSchema"),
            AuthRoute::get("/scim/v2/ResourceTypes", "getSCIMResourceTypes"),
            AuthRoute::get(
                "/scim/v2/ResourceTypes/{resourceTypeId}",
                "getSCIMResourceType",
            ),
            AuthRoute::get(
                "/scim/v2/ServiceProviderConfig",
                "getSCIMServiceProviderConfig",
            ),
        ]
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        vec![
            crate::endpoint::definition(
                "deleteSCIMUser",
                "deleteSCIMUser",
                Some("/scim/v2/Users/:userId"),
                HttpMethod::Delete,
            ),
            crate::endpoint::definition(
                "patchSCIMGroup",
                "patchSCIMGroup",
                Some("/scim/v2/Groups/:groupId"),
                HttpMethod::Patch,
            ),
            crate::endpoint::definition(
                "replaceSCIMGroup",
                "replaceSCIMGroup",
                Some("/scim/v2/Groups/:groupId"),
                HttpMethod::Put,
            ),
            crate::endpoint::definition(
                "deleteSCIMGroup",
                "deleteSCIMGroup",
                Some("/scim/v2/Groups/:groupId"),
                HttpMethod::Delete,
            ),
            crate::endpoint::definition(
                "createSCIMUser",
                "createSCIMUser",
                Some("/scim/v2/Users"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "createSCIMGroup",
                "createSCIMGroup",
                Some("/scim/v2/Groups"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "listSCIMUsers",
                "listSCIMUsers",
                Some("/scim/v2/Users"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "listSCIMGroups",
                "listSCIMGroups",
                Some("/scim/v2/Groups"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getSCIMUser",
                "getSCIMUser",
                Some("/scim/v2/Users/:userId"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getSCIMGroup",
                "getSCIMGroup",
                Some("/scim/v2/Groups/:groupId"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "reconcileSCIMProjection",
                "reconcileSCIMProjection",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "decommissionSCIMManagedConnection",
                "decommissionSCIMManagedConnection",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "decommissionSCIMConnection",
                "decommissionSCIMConnection",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "listSCIMManagedConnectionEvents",
                "listSCIMManagedConnectionEvents",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "revokeSCIMManagedCredential",
                "revokeSCIMManagedCredential",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "rotateSCIMManagedCredential",
                "rotateSCIMManagedCredential",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "getSCIMManagedConnection",
                "getSCIMManagedConnection",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "listSCIMManagedConnections",
                "listSCIMManagedConnections",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "createSCIMManagedConnection",
                "createSCIMManagedConnection",
                None,
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "getSCIMSchema",
                "getSCIMSchema",
                Some("/scim/v2/Schemas/:schemaId"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getSCIMSchemas",
                "getSCIMSchemas",
                Some("/scim/v2/Schemas"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getSCIMResourceType",
                "getSCIMResourceType",
                Some("/scim/v2/ResourceTypes/:resourceTypeId"),
                HttpMethod::Get,
            ),
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
    fn validate_endpoint(
        &self,
        call: &EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        if matches!(
            call.operation_id(),
            "reconcileSCIMProjection"
                | "decommissionSCIMManagedConnection"
                | "decommissionSCIMConnection"
                | "listSCIMManagedConnectionEvents"
                | "revokeSCIMManagedCredential"
                | "createSCIMManagedConnection"
                | "listSCIMManagedConnections"
                | "getSCIMManagedConnection"
                | "rotateSCIMManagedCredential"
        ) {
            managed::validate(call)
        } else {
            Ok(alibi_core::endpoint::EndpointInput {
                body: call.body().cloned(),
                query: call.query().cloned(),
            })
        }
    }
    async fn on_init(&self, _ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
        self.validate_connections()?;
        if let Some(options) = &self.managed_connections {
            if options.credential_hash_secret.encode_utf16().count() < 32 {
                return Err(AuthError::config(
                    "SCIM managed credentialHashSecret must contain at least 32 characters.",
                ));
            }
            if !(1..=100).contains(&options.max_active_credentials) {
                return Err(AuthError::config(
                    "SCIM managed maxActiveCredentials must be an integer between 1 and 100.",
                ));
            }
        }
        Ok(())
    }
    async fn on_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "deleteSCIMUser" {
            return self.delete_user(call, ctx).await;
        }
        if call.operation_id() == "patchSCIMGroup" {
            return self.patch_group(call, ctx).await;
        }
        if call.operation_id() == "replaceSCIMGroup" {
            return self.replace_group(call, ctx).await;
        }
        if call.operation_id() == "deleteSCIMGroup" {
            return self.delete_group(call, ctx).await;
        }
        if call.operation_id() == "createSCIMUser" {
            return self.create_user(call, ctx).await;
        }
        if call.operation_id() == "createSCIMGroup" {
            return self.create_group(call, ctx).await;
        }
        if call.operation_id() == "listSCIMUsers" {
            return self.list_users(call, ctx).await;
        }
        if call.operation_id() == "listSCIMGroups" {
            return self.list_groups(call, ctx).await;
        }
        if call.operation_id() == "getSCIMUser" {
            return self.get_user(call, ctx).await;
        }
        if call.operation_id() == "getSCIMGroup" {
            return self.get_group(call, ctx).await;
        }
        if call.operation_id() == "reconcileSCIMProjection" {
            return self.reconcile_projection(call, ctx).await;
        }
        if call.operation_id() == "decommissionSCIMManagedConnection" {
            return self.decommission_managed_connection(call, ctx).await;
        }
        if call.operation_id() == "decommissionSCIMConnection" {
            return self.decommission_connection(call, ctx).await;
        }
        if call.operation_id() == "listSCIMManagedConnectionEvents" {
            return self.list_managed_connection_events(call, ctx).await;
        }
        if call.operation_id() == "revokeSCIMManagedCredential" {
            return self.revoke_managed_credential(call, ctx).await;
        }
        if call.operation_id() == "rotateSCIMManagedCredential" {
            return self.rotate_managed_credential(call, ctx).await;
        }
        if call.operation_id() == "getSCIMManagedConnection" {
            return self.get_managed_connection(call, ctx).await;
        }
        if call.operation_id() == "listSCIMManagedConnections" {
            return self.list_managed_connections(call, ctx).await;
        }
        if call.operation_id() == "createSCIMManagedConnection" {
            return self.create_managed_connection(call, ctx).await;
        }
        if call.operation_id() == "getSCIMSchema" {
            return Self::schema(
                ctx,
                call.params()
                    .and_then(|params| params.get("schemaId"))
                    .and_then(alibi_core::utils::json::JsValue::as_str)
                    .unwrap_or(""),
            );
        }
        if call.operation_id() == "getSCIMSchemas" {
            return Ok(EndpointResponse::json(&Self::schemas(ctx)?)?
                .with_header("content-type", "application/scim+json"));
        }
        if call.operation_id() == "getSCIMResourceType" {
            return Self::resource_type(
                ctx,
                call.params()
                    .and_then(|params| params.get("resourceTypeId"))
                    .and_then(alibi_core::utils::json::JsValue::as_str),
            );
        }
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
        if req.method() == &HttpMethod::Delete
            && let Some(id) = req.path().strip_prefix("/scim/v2/Users/")
        {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::delete("/scim/v2/Users/{userId}", "deleteSCIMUser"),
            )
            .with_params_value(alibi_core::utils::json::JsValue::from(json!({"userId":id})));
            let response = self.delete_user(&call, ctx).await?;
            return Ok(Some(resources::to_http_response(&response)?));
        }
        if matches!(req.method(), HttpMethod::Put | HttpMethod::Patch)
            && let Some(id) = req.path().strip_prefix("/scim/v2/Groups/")
        {
            let route = if req.method() == &HttpMethod::Put {
                AuthRoute::put("/scim/v2/Groups/{groupId}", "replaceSCIMGroup")
            } else {
                AuthRoute::new(
                    HttpMethod::Patch,
                    "/scim/v2/Groups/{groupId}",
                    "patchSCIMGroup",
                )
            };
            let call = EndpointCall::from_http_request(req, &route).with_params_value(
                alibi_core::utils::json::JsValue::from(json!({"groupId":id})),
            );
            let response = match resources::mutation_request_error(req, &call) {
                Some(response) => response,
                None => {
                    if req.method() == &HttpMethod::Put {
                        self.replace_group(&call, ctx).await?
                    } else {
                        self.patch_group(&call, ctx).await?
                    }
                }
            };
            return Ok(Some(resources::to_http_response(&response)?));
        }
        if req.method() == &HttpMethod::Delete
            && let Some(id) = req.path().strip_prefix("/scim/v2/Groups/")
        {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::delete("/scim/v2/Groups/{groupId}", "deleteSCIMGroup"),
            )
            .with_params_value(alibi_core::utils::json::JsValue::from(
                json!({"groupId":id}),
            ));
            let mut response = self.delete_group(&call, ctx).await?.to_response()?;
            let mut headers = alibi_core::Headers::new();
            for (name, value) in response.headers {
                if !name.eq_ignore_ascii_case("x-better-auth-scim-response") {
                    headers.append(name, value);
                }
            }
            response.headers = headers;
            return Ok(Some(
                response.with_header("content-type", "application/scim+json"),
            ));
        }
        if req.method() == &HttpMethod::Post && req.path() == "/scim/v2/Users" {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::post("/scim/v2/Users", "createSCIMUser"),
            );
            let response = if let Some(error) = resources::mutation_request_error(req, &call) {
                error
            } else {
                self.create_user(&call, ctx).await?
            };
            return Ok(Some(resources::to_http_response(&response)?));
        }
        if req.method() == &HttpMethod::Post && req.path() == "/scim/v2/Groups" {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::post("/scim/v2/Groups", "createSCIMGroup"),
            );
            let media = req
                .headers
                .get("content-type")
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            let response = if !media.is_some_and(|media| {
                media.eq_ignore_ascii_case("application/json")
                    || media.eq_ignore_ascii_case("application/scim+json")
            }) {
                resources::error(
                    415,
                    "SCIM requests must use application/scim+json or application/json",
                    None,
                )
            } else if call.body().is_none() {
                resources::error(
                    400,
                    "SCIM request body must contain valid JSON",
                    Some("invalidSyntax"),
                )
            } else {
                self.create_group(&call, ctx).await?
            };
            let mut response = response.to_response()?;
            let mut headers = alibi_core::Headers::new();
            for (name, value) in response.headers {
                if !name.eq_ignore_ascii_case("x-better-auth-scim-response") {
                    headers.append(name, value);
                }
            }
            response.headers = headers;
            return Ok(Some(
                response.with_header("content-type", "application/scim+json"),
            ));
        }
        if req.method() == &HttpMethod::Get && req.path() == "/scim/v2/Users" {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::get("/scim/v2/Users", "listSCIMUsers"),
            );
            let mut response = self.list_users(&call, ctx).await?.to_response()?;
            let mut headers = alibi_core::Headers::new();
            for (name, value) in response.headers {
                if !name.eq_ignore_ascii_case("x-better-auth-scim-response") {
                    headers.append(name, value);
                }
            }
            response.headers = headers;
            return Ok(Some(
                response.with_header("content-type", "application/scim+json"),
            ));
        }
        if req.method() == &HttpMethod::Get && req.path() == "/scim/v2/Groups" {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::get("/scim/v2/Groups", "listSCIMGroups"),
            );
            let mut response = self.list_groups(&call, ctx).await?.to_response()?;
            let mut headers = alibi_core::Headers::new();
            for (name, value) in response.headers {
                if !name.eq_ignore_ascii_case("x-better-auth-scim-response") {
                    headers.append(name, value);
                }
            }
            response.headers = headers;
            return Ok(Some(
                response.with_header("content-type", "application/scim+json"),
            ));
        }
        if req.method() == &HttpMethod::Get
            && let Some(id) = req.path().strip_prefix("/scim/v2/Users/")
        {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::get("/scim/v2/Users/{userId}", "getSCIMUser"),
            )
            .with_params_value(alibi_core::utils::json::JsValue::from(json!({"userId":id})));
            let mut response = self.get_user(&call, ctx).await?.to_response()?;
            let mut headers = alibi_core::Headers::new();
            for (name, value) in response.headers {
                if !name.eq_ignore_ascii_case("x-better-auth-scim-response") {
                    headers.append(name, value);
                }
            }
            response.headers = headers;
            return Ok(Some(
                response.with_header("content-type", "application/scim+json"),
            ));
        }
        if req.method() == &HttpMethod::Get
            && let Some(id) = req.path().strip_prefix("/scim/v2/Groups/")
        {
            let call = EndpointCall::from_http_request(
                req,
                &AuthRoute::get("/scim/v2/Groups/{groupId}", "getSCIMGroup"),
            )
            .with_params_value(alibi_core::utils::json::JsValue::from(
                json!({"groupId":id}),
            ));
            let mut response = self.get_group(&call, ctx).await?.to_response()?;
            let mut headers = alibi_core::Headers::new();
            for (name, value) in response.headers {
                if !name.eq_ignore_ascii_case("x-better-auth-scim-response") {
                    headers.append(name, value);
                }
            }
            response.headers = headers;
            return Ok(Some(
                response.with_header("content-type", "application/scim+json"),
            ));
        }
        if req.method() == &HttpMethod::Get
            && let Some(id) = req.path().strip_prefix("/scim/v2/Schemas/")
        {
            return Ok(Some(Self::schema(ctx, id)?.to_response()?));
        }
        if req.method() == &HttpMethod::Get
            && let Some(id) = req.path().strip_prefix("/scim/v2/ResourceTypes/")
        {
            return Ok(Some(Self::resource_type(ctx, Some(id))?.to_response()?));
        }
        if req.method() != &HttpMethod::Get
            || !matches!(
                req.path(),
                "/scim/v2/ServiceProviderConfig" | "/scim/v2/ResourceTypes" | "/scim/v2/Schemas"
            )
        {
            return Ok(None);
        }
        let value = if req.path() == "/scim/v2/Schemas" {
            Self::schemas(ctx)?
        } else if req.path() == "/scim/v2/ResourceTypes" {
            Self::resource_types(ctx)
        } else {
            Self::service_provider_config(ctx)
        };
        Ok(Some(
            AuthResponse::json(200, &value)?.with_header("content-type", "application/scim+json"),
        ))
    }
}
