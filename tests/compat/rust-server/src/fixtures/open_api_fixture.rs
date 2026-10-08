//! Real OpenAPI plugin configurations; no fixture endpoint manufactures schema output.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::jwt::JwtPlugin;
use alibi::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, MultiSessionPlugin, OAuthPlugin, OpenApiConfig,
    OpenApiPlugin, OrganizationPlugin, PasskeyPlugin, PasswordManagementPlugin, PhoneNumberPlugin,
    SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthResult, AuthSchema};
use alibi_seaorm::sea_orm::DatabaseConnection;
use axum::Router;
use std::sync::Arc;

struct DocumentationSchema;
impl AuthSchema for DocumentationSchema {
    type User = <TestSchema as AuthSchema>::User;
    type Session = <TestSchema as AuthSchema>::Session;
    type Account = <TestSchema as AuthSchema>::Account;
    type Verification = <TestSchema as AuthSchema>::Verification;
    fn openapi_models() -> Vec<alibi::plugin::OpenApiModel> {
        let mut models = alibi::__private_core::openapi::annotations::core_models();
        models[0].fields.push(
            alibi::plugin::OpenApiField::new(
                "metadata",
                serde_json::json!({"type":"json","default":null}),
                true,
            )
            .read_only()
            .hidden(),
        );
        for (name, schema) in [
            (
                "access",
                serde_json::json!({"type":["reader","editor"],"default":"reader"}),
            ),
            (
                "aliases",
                serde_json::json!({"type":"array","items":{"type":"string"},"default":["initial"]}),
            ),
            (
                "score",
                serde_json::json!({"type":"array","items":{"type":"number"}}),
            ),
            (
                "anniversary",
                serde_json::json!({"type":"string","format":"date-time"}),
            ),
        ] {
            models[0].fields.push(alibi::plugin::OpenApiField::new(
                name,
                schema,
                name == "access",
            ));
        }
        models
    }
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "openapi-collisions",
        "openapi-parameters",
        "openapi-minimal",
        "openapi-last-login",
        "openapi-last-login-database",
        "openapi-default",
        "openapi-configured",
        "openapi-disabled",
        "openapi-jwt",
        "openapi-username",
        "openapi-custom-schema",
        "openapi-plugins",
        "openapi-plugins-teams",
        "openapi-plugins-configured",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name == "openapi-custom-schema" {
            config.disabled_paths.push("/documentation-disabled".into());
        }
        let options = match name {
            "openapi-configured" => {
                config.disabled_paths.push("/error".into());
                OpenApiConfig::default()
                    .path("/docs")
                    .theme("moon")
                    .nonce("fixture-reference-nonce")
            }
            "openapi-disabled" => OpenApiConfig::default().disable_default_reference(true),
            _ => OpenApiConfig::default(),
        };
        if name == "openapi-jwt" {
            config
                .disabled_paths
                .extend(["/jwks".into(), "/token".into()]);
        }
        let instance = if name == "openapi-custom-schema" {
            instance::<DocumentationSchema>(config, database.clone(), name, options).await?
        } else {
            instance::<TestSchema>(config, database.clone(), name, options).await?
        };
        router = router.nest(&path, instance);
    }
    Ok(router)
}

async fn instance<S>(
    config: AuthConfig,
    database: DatabaseConnection,
    name: &str,
    options: OpenApiConfig,
) -> AuthResult<Router>
where
    S: AuthSchema<
            User = <TestSchema as AuthSchema>::User,
            Session = <TestSchema as AuthSchema>::Session,
            Account = <TestSchema as AuthSchema>::Account,
            Verification = <TestSchema as AuthSchema>::Verification,
        >,
{
    let mut builder = AuthBuilder::<S>::new(config.clone())
        .store(crate::backend::store::<S>(config, database.clone()))
        .rate_limit(RateLimitConfig::new().enabled(false));
    if name != "openapi-minimal" {
        builder = builder
            .plugin(SessionManagementPlugin::new())
            .plugin(EmailPasswordPlugin::new().enable_username(name == "openapi-username"))
            .plugin(PasswordManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(OAuthPlugin::new())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .delete_user_enabled(true),
            );
    }
    if name == "openapi-collisions" {
        builder = builder.plugin(CollisionsPlugin);
    }
    if name == "openapi-parameters" {
        builder = builder.plugin(ParametersPlugin);
    }
    if name == "openapi-custom-schema" {
        builder = builder.plugin(DocumentationPlugin);
    }
    if name.starts_with("openapi-last-login") {
        builder = builder.plugin(alibi::plugins::LastLoginMethodPlugin::with_config(
            alibi::plugins::LastLoginMethodConfig {
                store_in_database: name == "openapi-last-login-database",
                ..Default::default()
            },
        ));
    }
    if name.starts_with("openapi-plugins") {
        use alibi::plugins::organization::{
            DynamicAccessControlConfig, OrganizationConfig, TeamsConfig,
        };
        let organization = OrganizationConfig {
            teams: TeamsConfig {
                enabled: name == "openapi-plugins-teams",
                ..Default::default()
            },
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: name == "openapi-plugins-teams",
                ..Default::default()
            },
            ..Default::default()
        };
        let mut api_key = alibi::plugins::api_key::ApiKeyConfig::default();
        if name == "openapi-plugins-configured" {
            api_key.rate_limit.max_requests = 43.0;
            api_key.rate_limit.time_window = 7654321.0;
        }
        builder = builder
            .plugin(alibi::plugins::one_tap::OneTapPlugin::with_config(
                alibi::plugins::one_tap::OneTapConfig {
                    client_id: Some(alibi::plugins::one_tap::OneTapClientId::Single(
                        "openapi-one-tap-client".into(),
                    )),
                    ..Default::default()
                },
            ))
            .plugin(AdminPlugin::new())
            .plugin(OrganizationPlugin::with_config(organization))
            .plugin(TwoFactorPlugin::new())
            .plugin(ApiKeyPlugin::with_config(api_key))
            .plugin(PasskeyPlugin::new())
            .plugin(DeviceAuthorizationPlugin::new())
            .plugin(JwtPlugin::new())
            .plugin(MultiSessionPlugin::new())
            .plugin(PhoneNumberPlugin::new(Default::default()))
            .plugin(alibi::plugins::siwe::SiwePlugin::new(
                alibi::plugins::siwe::SiweConfig::new(
                    "localhost",
                    Arc::new(alibi::plugins::siwe::RandomSiweNonce),
                    Arc::new(alibi::plugins::siwe::Eip191Verifier),
                ),
            ));
    }
    if name == "openapi-jwt" {
        builder = builder.plugin(JwtPlugin::new());
    }
    let auth = Arc::new(
        builder
            .plugin(OpenApiPlugin::with_config(options))
            .build()
            .await?,
    );
    let mut router = auth.clone().axum_router().with_state(auth.clone());
    if name == "openapi-custom-schema" {
        router = router.route(
            "/__test/server-document",
            axum::routing::get(move || {
                let auth = auth.clone();
                async move {
                    let output = auth
                        .dispatch_endpoint(
                            alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(
                                "documentation",
                                "serverDocument",
                            ),
                            alibi::endpoint::EndpointOptions::default(),
                        )
                        .await
                        .unwrap();
                    axum::Json(output.decode().unwrap())
                }
            }),
        );
    }
    Ok(router)
}

struct DocumentationPlugin;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::plugin::AuthPlugin<S> for DocumentationPlugin {
    fn name(&self) -> &'static str {
        "documentation"
    }
    fn routes(&self) -> Vec<alibi::plugin::AuthRoute> {
        use alibi::plugin::AuthRoute;
        vec![
            AuthRoute::get("/documents/{id}", "read_document"),
            AuthRoute::post("/documents/{id}", "update_document"),
            AuthRoute::get("/documentation-hidden", "hidden_document"),
            AuthRoute::get("/documentation-server-only", "server_document"),
            AuthRoute::get("/documentation-disabled", "disabled_document"),
        ]
    }
    fn server_endpoints(&self) -> Vec<alibi::endpoint::EndpointDefinition> {
        vec![alibi::endpoint::EndpointDefinition {
            name: "serverDocument",
            operation_id: "serverDocument",
            path: Some("/documentation-server-only".into()),
            method: alibi::__private_core::HttpMethod::Get,
        }]
    }
    async fn on_endpoint(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _ctx: &alibi::plugin::AuthContext<S>,
    ) -> AuthResult<alibi::endpoint::EndpointResponse> {
        if call.operation_id() == "serverDocument" {
            return alibi::endpoint::EndpointResponse::json(
                &serde_json::json!({"kind":"server-only"}),
            );
        }
        Err(alibi::AuthError::not_found(
            "Unknown documentation operation",
        ))
    }
    fn openapi_metadata(
        &self,
        _ctx: &alibi::plugin::AuthInitContext<S>,
    ) -> alibi::plugin::PluginOpenApiMetadata {
        use alibi::__private_core::HttpMethod;
        use alibi::plugin::{OpenApiEndpoint, OpenApiField, OpenApiModel, PluginOpenApiMetadata};
        use serde_json::json;
        let read = OpenApiEndpoint {
            operation_id: Some("document".into()),
            description: Some("Read a document".into()),
            tags: Some(vec!["Documents".into()]),
            parameters: vec![
                json!({"name":"view","in":"query","schema":{"type":"string","enum":["summary","complete"],"description":"Projection"}}),
            ],
            ..Default::default()
        };
        let write = OpenApiEndpoint {
            operation_id: Some("document".into()),
            description: Some("Update a document".into()),
            tags: Some(vec!["Documents".into()]),
            request_body: Some(
                json!({"required":true,"content":{"application/json":{"schema":{"type":["array","null"],"items":{"type":"string","enum":["approved","pending"]},"description":"Document labels"}}}}),
            ),
            ..Default::default()
        };
        PluginOpenApiMetadata::default()
            .endpoint(HttpMethod::Get, "/documents/{id}", read)
            .endpoint(HttpMethod::Post, "/documents/{id}", write)
            .endpoint(
                HttpMethod::Get,
                "/documentation-hidden",
                OpenApiEndpoint {
                    operation_id: Some("hiddenDocument".into()),
                    ..Default::default()
                },
            )
            .endpoint(
                HttpMethod::Get,
                "/documentation-server-only",
                OpenApiEndpoint {
                    server_only: true,
                    ..Default::default()
                },
            )
            .endpoint(
                HttpMethod::Get,
                "/documentation-disabled",
                OpenApiEndpoint {
                    operation_id: Some("disabledDocument".into()),
                    ..Default::default()
                },
            )
            .model(OpenApiModel::new(
                "Document",
                vec![
                    OpenApiField::new("label", json!({"type":"string"}), true),
                    OpenApiField::new(
                        "visibility",
                        json!({"type":["private","public"],"default":"private"}),
                        false,
                    ),
                    OpenApiField::new(
                        "labels",
                        json!({"type":"array","items":{"type":"string"}}),
                        false,
                    ),
                    OpenApiField::new("secret", json!({"type":"string"}), true)
                        .read_only()
                        .hidden(),
                    OpenApiField::new("dynamic", json!({"type":"number"}), false),
                ],
            ))
    }
    async fn on_request(
        &self,
        req: &alibi::__private_core::AuthRequest,
        _ctx: &alibi::plugin::AuthContext<S>,
    ) -> AuthResult<Option<alibi::__private_core::AuthResponse>> {
        use alibi::__private_core::AuthResponse;
        use serde_json::json;
        if let Some(id) = req.path().strip_prefix("/documents/") {
            let body = if req.method() == &alibi::__private_core::HttpMethod::Post {
                json!({"id":id,"labels":req.body_as_json::<serde_json::Value>()?})
            } else {
                json!({"id":id})
            };
            return Ok(Some(AuthResponse::json(200, &body)?));
        }
        for (path, kind) in [
            ("/documentation-hidden", "hidden"),
            ("/documentation-server-only", "server-only"),
            ("/documentation-disabled", "disabled"),
        ] {
            if req.path() == path {
                return Ok(Some(AuthResponse::json(200, &json!({"kind":kind}))?));
            }
        }
        Ok(None)
    }
}

struct ParametersPlugin;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::plugin::AuthPlugin<S> for ParametersPlugin {
    fn name(&self) -> &'static str {
        "documentation-parameters"
    }
    fn routes(&self) -> Vec<alibi::plugin::AuthRoute> {
        ["explicit", "empty"]
            .iter()
            .map(|mode| {
                alibi::plugin::AuthRoute::get(
                    format!("/parameters-{mode}/{{id}}"),
                    format!("parameters{mode}"),
                )
            })
            .collect()
    }
    fn openapi_metadata(
        &self,
        _ctx: &alibi::plugin::AuthInitContext<S>,
    ) -> alibi::plugin::PluginOpenApiMetadata {
        use serde_json::json;
        let mut metadata = alibi::plugin::PluginOpenApiMetadata::default();
        for mode in ["explicit", "empty"] {
            metadata = metadata.endpoint(alibi::__private_core::HttpMethod::Get, format!("/parameters-{mode}/{{id}}"), alibi::plugin::OpenApiEndpoint {
                operation_id: Some(format!("parameters{mode}")),
                parameters: if mode == "empty" { vec![] } else { vec![
                    json!({"name":"documented","in":"query","required":true,"description":"Explicit query","schema":{"type":"string","enum":["visible"]}}),
                    json!({"name":"id","in":"path","required":true,"description":"Application identifier","schema":{"type":"string","pattern":"^document-[0-9]+$"}}),
                ] }, ..Default::default()
            });
        }
        metadata
    }
    async fn on_request(
        &self,
        req: &alibi::__private_core::AuthRequest,
        _ctx: &alibi::plugin::AuthContext<S>,
    ) -> AuthResult<Option<alibi::__private_core::AuthResponse>> {
        for mode in ["explicit", "empty"] {
            if let Some(id) = req.path().strip_prefix(&format!("/parameters-{mode}/")) {
                let (Some(inferred), Some(documented)) =
                    (req.query.get("inferred"), req.query.get("documented"))
                else {
                    return Err(alibi::AuthError::bad_request("Missing query input"));
                };
                return Ok(Some(alibi::__private_core::AuthResponse::json(
                    200,
                    &serde_json::json!({"id":id,"inferred":inferred,"documented":documented}),
                )?));
            }
        }
        Ok(None)
    }
}

struct CollisionsPlugin;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::plugin::AuthPlugin<S> for CollisionsPlugin {
    fn name(&self) -> &'static str {
        "documentation-collisions"
    }
    fn routes(&self) -> Vec<alibi::plugin::AuthRoute> {
        ["reserved", "first", "second", "third"]
            .iter()
            .map(|route| {
                alibi::plugin::AuthRoute::get(
                    format!("/collisions/{route}"),
                    format!("fixture{route}"),
                )
            })
            .collect()
    }
    fn openapi_metadata(
        &self,
        _ctx: &alibi::plugin::AuthInitContext<S>,
    ) -> alibi::plugin::PluginOpenApiMetadata {
        let mut metadata = alibi::plugin::PluginOpenApiMetadata::default();
        for (route, operation_id) in [
            ("reserved", "collisionGet"),
            ("first", "collision"),
            ("second", "collision"),
            ("third", "collision"),
        ] {
            metadata = metadata.endpoint(
                alibi::__private_core::HttpMethod::Get,
                format!("/collisions/{route}"),
                alibi::plugin::OpenApiEndpoint {
                    operation_id: Some(operation_id.into()),
                    ..Default::default()
                },
            );
        }
        metadata
    }
    async fn on_request(
        &self,
        req: &alibi::__private_core::AuthRequest,
        _ctx: &alibi::plugin::AuthContext<S>,
    ) -> AuthResult<Option<alibi::__private_core::AuthResponse>> {
        if let Some(route) = req.path().strip_prefix("/collisions/") {
            return Ok(Some(alibi::__private_core::AuthResponse::json(
                200,
                &serde_json::json!({"route":route}),
            )?));
        }
        Ok(None)
    }
}
