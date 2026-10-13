//! Direct discovery delegates to actual configured provider/JWT plugins.
use crate::TestSchema;
use alibi::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin};
use alibi::seaorm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use std::{collections::HashMap, sync::Arc};
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut instances = HashMap::new();
    for mode in ["default", "oauth", "disabled", "configured"] {
        let mut provider = OAuthProviderConfig::default();
        let mut jwt = JwtPluginConfig::default();
        if mode == "oauth" || mode == "configured" {
            provider.scopes = vec!["read".into()];
        }
        if mode == "disabled" {
            provider.disable_jwt_plugin = true;
        }
        if mode == "configured" {
            provider.advertised_scopes = Some(vec!["read".into()]);
            provider.grant_types = vec!["client_credentials".into()];
            provider.allow_dynamic_client_registration = true;
            provider.allow_unauthenticated_client_registration = true;
            jwt.claims.issuer = Some("http://issuer.fixture.test/tenant?discard=1#discard".into());
            jwt.jwks_path = "/keys".into();
            jwt.remote_url = Some("https://keys.fixture.test/jwks".into());
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config.clone(),
                    database.clone(),
                ))
                .plugin(JwtPlugin::with_config(jwt))
                .plugin(OAuthProviderPlugin::with_config(provider))
                .build()
                .await?,
        );
        instances.insert(mode.to_owned(), auth);
    }
    Ok(Router::new().route(
        "/__test/server-api/oauth-provider-metadata",
        get(move |Query(query): Query<HashMap<String, String>>| {
            let auth = instances
                .get(query.get("mode").map_or("default", String::as_str))
                .unwrap()
                .clone();
            async move {
                let endpoint = alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(
                    "oauth-provider",
                    if query
                        .get("operation")
                        .is_some_and(|operation| operation == "getOpenIdConfig")
                    {
                        "getOpenIdConfig"
                    } else {
                        "getOAuthServerConfig"
                    },
                );
                match auth
                    .dispatch_endpoint(endpoint, alibi::endpoint::EndpointOptions::default())
                    .await
                {
                    Ok(output) => output.into_response().unwrap().into_response(),
                    Err(error) => {
                        let mut response = if error.body_absent {
                            alibi::AuthResponse::new(error.error.status_code())
                        } else {
                            error.error.to_auth_response()
                        };
                        if let Some(body) = error.body {
                            response.body = serde_json::to_vec(&*body).unwrap();
                        }
                        if let Some(headers) = error.headers {
                            for (name, value) in headers.iter() {
                                response.headers.append(name, value);
                            }
                        }
                        response.into_response()
                    }
                }
            }
        }),
    ))
}
