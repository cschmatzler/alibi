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
    let client_auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config.clone(),
                database.clone(),
            ))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(alibi::plugins::SessionManagementPlugin::new())
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::new())
            .build()
            .await?,
    );
    Ok(Router::new().route("/__test/server-api/oauth-provider-clients",axum::routing::post(move |axum::Json(input):axum::Json<serde_json::Value>| {
        let auth=client_auth.clone();async move {
            if input["action"]=="row" {
                let row=auth.store().get_oauth_client(input["clientId"].as_str().unwrap()).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"clientId":row.client_id,"userId":row.user_id,"clientName":row.metadata.get("client_name"),"redirectUris":row.metadata.get("redirect_uris"),"client_secret":row.client_secret}))).into_response();
            }
            let (plugin,operation)=if input["action"]=="signup" {("email-password","signUpEmail")}else if input["action"]=="update" {("oauth-provider","updateOAuthClient")}else if input["action"]=="rotate" {("oauth-provider","rotateClientSecret")}else if input["action"]=="delete" {("oauth-provider","deleteOAuthClient")}else if input["action"]=="list" {("oauth-provider","getOAuthClients")}else if input["action"]=="public" {("oauth-provider","getOAuthClientPublic")}else if input["action"]=="get" {("oauth-provider","getOAuthClient")}else{("oauth-provider","createOAuthClient")};
            let endpoint=if input["action"]=="get" || input["action"]=="public" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_query(&input["query"]).unwrap()} else {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_body(&input["body"]).unwrap()};
            match auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()}).await {
                Ok(output)=>output.into_response().unwrap().into_response(),
                Err(error)=>{let mut response=if error.body_absent{alibi::AuthResponse::new(error.error.status_code())}else{error.error.to_auth_response()};if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}if let Some(headers)=error.headers {for(name,value)in headers.iter(){if name.eq_ignore_ascii_case("set-cookie"){response.headers.append(name,value);}else{response.headers.insert(name,value);}}}response.into_response()}
            }
        }
    })).route(
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
