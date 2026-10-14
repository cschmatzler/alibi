use alibi::endpoint::EndpointOptions;
use alibi::integrations::axum::AxumIntegration;
use alibi::plugins::ScimPlugin;
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::{Json, Router, routing::post};
use std::sync::Arc;
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let path = "/__test/profiles/scim/api/auth";
    let config = base.clone().base_path(path);
    let auth = Arc::new(
        AuthBuilder::<crate::TestSchema>::new(config.clone())
            .store(crate::backend::store(config, database))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(ScimPlugin::new())
            .build()
            .await?,
    );
    let router = Router::new().nest(path, auth.clone().axum_router().with_state(auth.clone()));
    Ok(router.route(
        "/__test/server-api/scim",
        post(move || {
            let auth = auth.clone();
            async move {
                let output = auth
                    .dispatch_endpoint(
                        ScimPlugin::service_provider_config_endpoint(),
                        EndpointOptions::default(),
                    )
                    .await
                    .unwrap();
                Json(output.value().clone())
            }
        }),
    ))
}
