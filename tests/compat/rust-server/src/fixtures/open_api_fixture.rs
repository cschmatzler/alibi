//! Real OpenAPI plugin configurations; no fixture endpoint manufactures schema output.
use crate::TestSchema;
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::jwt::JwtPlugin;
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, MultiSessionPlugin, OAuthPlugin, OpenApiConfig,
    OpenApiPlugin, OrganizationPlugin, PasskeyPlugin, PasswordManagementPlugin, PhoneNumberPlugin,
    SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, AuthSchema};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use std::sync::Arc;

struct DocumentationSchema;
impl AuthSchema for DocumentationSchema {
    type User = <TestSchema as AuthSchema>::User;
    type Session = <TestSchema as AuthSchema>::Session;
    type Account = <TestSchema as AuthSchema>::Account;
    type Verification = <TestSchema as AuthSchema>::Verification;
    fn openapi_models() -> Vec<better_auth::plugin::OpenApiModel> {
        let mut models = better_auth::__private_core::openapi::annotations::core_models();
        models[0].fields.push(
            better_auth::plugin::OpenApiField::new(
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
            models[0]
                .fields
                .push(better_auth::plugin::OpenApiField::new(
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
        .store(SeaOrmStore::<S>::new(config, database.clone()))
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
    if name == "openapi-custom-schema" {
        builder = builder.plugin(DocumentationPlugin);
    }
    if name.starts_with("openapi-last-login") {
        builder = builder.plugin(better_auth::plugins::LastLoginMethodPlugin::with_config(
            better_auth::plugins::LastLoginMethodConfig {
                store_in_database: name == "openapi-last-login-database",
                ..Default::default()
            },
        ));
    }
    if name.starts_with("openapi-plugins") {
        use better_auth::plugins::organization::{
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
        let mut api_key = better_auth::plugins::api_key::ApiKeyConfig::default();
        if name == "openapi-plugins-configured" {
            api_key.rate_limit.max_requests = 43.0;
            api_key.rate_limit.time_window = 7654321.0;
        }
        builder = builder
            .plugin(better_auth::plugins::one_tap::OneTapPlugin::with_config(
                better_auth::plugins::one_tap::OneTapConfig {
                    client_id: Some(better_auth::plugins::one_tap::OneTapClientId::Single(
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
            .plugin(better_auth::plugins::siwe::SiwePlugin::new(
                better_auth::plugins::siwe::SiweConfig::new(
                    "localhost",
                    Arc::new(better_auth::plugins::siwe::RandomSiweNonce),
                    Arc::new(better_auth::plugins::siwe::Eip191Verifier),
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
                            better_auth::endpoint::ServerEndpoint::<serde_json::Value>::new(
                                "documentation",
                                "serverDocument",
                            ),
                            better_auth::endpoint::EndpointOptions::default(),
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
impl<S: AuthSchema> better_auth::plugin::AuthPlugin<S> for DocumentationPlugin {
    fn name(&self) -> &'static str {
        "documentation"
    }
    fn routes(&self) -> Vec<better_auth::plugin::AuthRoute> {
        use better_auth::plugin::AuthRoute;
        vec![
            AuthRoute::get("/documents/{id}", "read_document"),
            AuthRoute::post("/documents/{id}", "update_document"),
            AuthRoute::get("/documentation-hidden", "hidden_document"),
            AuthRoute::get("/documentation-server-only", "server_document"),
            AuthRoute::get("/documentation-disabled", "disabled_document"),
        ]
    }
    fn server_endpoints(&self) -> Vec<better_auth::endpoint::EndpointDefinition> {
        vec![better_auth::endpoint::EndpointDefinition {
            name: "serverDocument",
            operation_id: "serverDocument",
            path: Some("/documentation-server-only".into()),
            method: better_auth::__private_core::HttpMethod::Get,
        }]
    }
    async fn on_endpoint(
        &self,
        call: &better_auth::endpoint::EndpointCall,
        _ctx: &better_auth::plugin::AuthContext<S>,
    ) -> AuthResult<better_auth::endpoint::EndpointResponse> {
        if call.operation_id() == "serverDocument" {
            return better_auth::endpoint::EndpointResponse::json(
                &serde_json::json!({"kind":"server-only"}),
            );
        }
        Err(better_auth::AuthError::not_found(
            "Unknown documentation operation",
        ))
    }
    fn openapi_metadata(
        &self,
        _ctx: &better_auth::plugin::AuthInitContext<S>,
    ) -> better_auth::plugin::PluginOpenApiMetadata {
        use better_auth::__private_core::HttpMethod;
        use better_auth::plugin::{
            OpenApiEndpoint, OpenApiField, OpenApiModel, PluginOpenApiMetadata,
        };
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
        req: &better_auth::__private_core::AuthRequest,
        _ctx: &better_auth::plugin::AuthContext<S>,
    ) -> AuthResult<Option<better_auth::__private_core::AuthResponse>> {
        use better_auth::__private_core::AuthResponse;
        use serde_json::json;
        if let Some(id) = req.path().strip_prefix("/documents/") {
            let body = if req.method() == &better_auth::__private_core::HttpMethod::Post {
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
