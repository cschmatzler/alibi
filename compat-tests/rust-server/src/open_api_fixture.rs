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
use better_auth_seaorm::{sea_orm::DatabaseConnection, SeaOrmStore};
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
        models
    }
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
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
        .rate_limit(RateLimitConfig::new().enabled(false))
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
    Ok(auth.clone().axum_router().with_state(auth))
}
