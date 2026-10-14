use alibi::endpoint::EndpointOptions;
use alibi::integrations::axum::AxumIntegration;
use alibi::plugins::ScimPlugin;
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::{Json, Router, extract::Query, routing::post};
use std::collections::HashMap;
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
        post(move |Query(query): Query<HashMap<String, String>>| {
            let auth = auth.clone();
            async move {
                if query
                    .get("operation")
                    .is_some_and(|operation| operation == "getSCIMResourceType")
                {
                    let output = auth
                        .dispatch_endpoint(
                            ScimPlugin::resource_type_endpoint(
                                query.get("id").map_or("", String::as_str),
                            )
                            .unwrap(),
                            EndpointOptions::default(),
                        )
                        .await;
                    return match output {
                        Ok(output) => (axum::http::StatusCode::OK, Json(output.value().clone())),
                        Err(error) => (
                            axum::http::StatusCode::from_u16(error.error.status_code()).unwrap(),
                            Json(*error.body.unwrap()),
                        ),
                    };
                }
                let output = auth
                    .dispatch_endpoint(
                        if query
                            .get("operation")
                            .is_some_and(|operation| operation == "getSCIMSchemas")
                        {
                            ScimPlugin::schemas_endpoint()
                        } else if query
                            .get("operation")
                            .is_some_and(|operation| operation == "getSCIMResourceTypes")
                        {
                            ScimPlugin::resource_types_endpoint()
                        } else {
                            ScimPlugin::service_provider_config_endpoint()
                        },
                        EndpointOptions::default(),
                    )
                    .await
                    .unwrap();
                (axum::http::StatusCode::OK, Json(output.value().clone()))
            }
        }),
    ))
}
