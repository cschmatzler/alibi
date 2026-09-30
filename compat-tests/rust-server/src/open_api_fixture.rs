//! Real OpenAPI plugin configurations; no fixture endpoint manufactures schema output.
use crate::TestSchema;
use axum::Router;
use better_auth::{AuthBuilder,AuthConfig,AuthResult};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{OpenApiConfig,OpenApiPlugin,SessionManagementPlugin};
use better_auth::plugins::jwt::JwtPlugin;
use better_auth_seaorm::{SeaOrmStore,sea_orm::DatabaseConnection};
use std::sync::Arc;

const DISABLED:&[&str]=&["/sign-in/social","/callback/:id","/sign-up/email","/sign-in/email","/reset-password","/verify-password","/verify-email","/send-verification-email","/change-email","/change-password","/update-session","/update-user","/delete-user","/request-password-reset","/reset-password/:token","/link-social","/list-accounts","/delete-user/callback","/unlink-account","/refresh-token","/get-access-token","/account-info"];
pub(super) async fn router(config:&AuthConfig,database:DatabaseConnection)->AuthResult<Router> {
 let mut router=Router::new();
 for name in ["openapi-default","openapi-configured","openapi-disabled","openapi-jwt"] {
  let path=format!("/__test/profiles/{name}/api/auth");
  let mut config=config.clone().base_path(&path).disabled_paths(DISABLED.iter().map(|path|(*path).to_string()).collect());
  let options=match name {
    "openapi-configured"=> { config.disabled_paths.push("/error".into());OpenApiConfig::default().path("/docs").theme("moon").nonce("fixture-reference-nonce") },
    "openapi-disabled"=>OpenApiConfig::default().disable_default_reference(true),
    _=>OpenApiConfig::default(),
  };
  if name=="openapi-jwt" {config.disabled_paths.extend(["/jwks".into(),"/token".into()]);}
  let mut builder=AuthBuilder::<TestSchema>::new(config.clone()).store(SeaOrmStore::<TestSchema>::new(config,database.clone())).rate_limit(RateLimitConfig::new().enabled(false)).plugin(SessionManagementPlugin::new());
  if name=="openapi-jwt" {builder=builder.plugin(JwtPlugin::new());}
  let auth=Arc::new(builder.plugin(OpenApiPlugin::with_config(options)).build().await?);
  router=router.nest(&path,auth.clone().axum_router().with_state(auth));
 }
 Ok(router)
}
