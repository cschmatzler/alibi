//! SCIM server discovery operations.
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointResponse, ServerEndpoint};
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};
mod managed;
mod projection;
pub use managed::{ScimManagedConnectionInput, ScimManagedCredentialRotationInput};
pub use projection::{
    ConfiguredScimPlugin, ScimAuthorizationSource, ScimIdentitySource, ScimProjectedUserState,
    ScimProjection, ScimRoleExistenceInput, ScimRoleMappingInput, ScimRoleProjection,
};

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
}
impl ScimPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            managed_connections: None,
        }
    }
    #[must_use]
    pub fn managed_connections(mut self, options: ScimManagedConnectionOptions) -> Self {
        self.managed_connections = Some(options);
        self
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
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
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
