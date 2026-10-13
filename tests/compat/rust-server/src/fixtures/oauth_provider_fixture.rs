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
    let mut client_instances=HashMap::new();
    for mode in ["default","dynamic","public","prelogin","expired","resources-open"] {
        let provider=OAuthProviderConfig {enforce_per_client_resources:mode!="resources-open",allow_public_client_prelogin:matches!(mode,"prelogin"|"expired"),code_expires_in:if mode=="expired" {-1.0}else{600.0},allow_dynamic_client_registration:matches!(mode,"dynamic"|"public"),allow_unauthenticated_client_registration:mode=="public",..Default::default()};
        let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config.clone(),
                database.clone(),
            ))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(alibi::plugins::SessionManagementPlugin::new())
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(provider))
            .build()
            .await?,
    );
        client_instances.insert(mode.to_owned(),auth);
    }
    let authorization_path=format!("{}/oauth2/authorize",config.base_path);
    let admin_path=format!("{}/admin/oauth2/create-client",config.base_path);
    Ok(Router::new().route("/__test/server-api/oauth-provider-clients",axum::routing::post(move |axum::Json(input):axum::Json<serde_json::Value>| {
        let authorization_path=authorization_path.clone();
        let admin_path=admin_path.clone();
        let auth=client_instances.get(input["mode"].as_str().unwrap_or("default")).unwrap().clone();async move {
            if input["action"]=="resource-links" {
                let rows=auth.store().list_oauth_client_resources(input["clientId"].as_str().unwrap()).await.unwrap().into_iter().map(|row|serde_json::json!({"id":row.id,"clientId":row.client_id,"resourceId":row.resource_id,"metadata":row.metadata,"createdAt":row.created_at})).collect::<Vec<_>>();return axum::Json(rows).into_response();
            }
            if input["action"]=="resource-row" {
                let row=auth.store().get_oauth_resource(input["identifier"].as_str().unwrap()).await.unwrap();
                return axum::Json(row.map(|row|{let mut value=row.metadata.as_object().unwrap().clone();value.insert("id".into(),serde_json::json!(row.id));value.insert("identifier".into(),serde_json::json!(row.identifier));value.insert("createdAt".into(),serde_json::json!(row.created_at));value.insert("updatedAt".into(),serde_json::json!(row.updated_at));serde_json::Value::Object(value)})).into_response();
            }
            if input["action"]=="resource-http" {
                let mut request=alibi::AuthRequest::new(if input["operation"]=="delete" || input["operation"]=="unlink"{alibi::HttpMethod::Delete}else if input["operation"]=="update"{alibi::HttpMethod::Patch}else if (input["operation"]=="list" || input["operation"]=="read"){alibi::HttpMethod::Get}else{alibi::HttpMethod::Post},if input["operation"]=="read" || input["operation"]=="update" || input["operation"]=="delete" || input["operation"]=="link" || input["operation"]=="unlink" {format!("{}/{}{}",admin_path.replace("create-client","resources"),url::form_urlencoded::byte_serialize(input["identifier"].as_str().unwrap().as_bytes()).collect::<String>(),if input["operation"]=="link" || input["operation"]=="unlink"{format!("/clients/{}",url::form_urlencoded::byte_serialize(input["clientId"].as_str().unwrap().as_bytes()).collect::<String>())}else{String::new()})}else{admin_path.replace("create-client","resources")});request.body=Some(serde_json::to_vec(&input["body"]).unwrap());request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();_=request.headers.insert("content-type".into(),"application/json".into());
                let response=auth.handle_request(request).await.unwrap();return axum::Json(serde_json::json!({"status":response.status})).into_response();
            }
            if input["action"]=="consent-row" {
                let clients=auth.store().get_oauth_client(input["clientId"].as_str().unwrap()).await.unwrap().unwrap();
                let rows=auth.store().list_oauth_consents_by_user(clients.user_id.as_deref().unwrap()).await.unwrap().into_iter().filter(|row|row.client_id==clients.client_id).map(|row|{let mut value=row.metadata.as_object().unwrap().clone();value.insert("id".into(),serde_json::json!(row.id));value.insert("clientId".into(),serde_json::json!(row.client_id));value.insert("userId".into(),serde_json::json!(row.user_id));value.insert("createdAt".into(),serde_json::json!(row.created_at));value.insert("updatedAt".into(),serde_json::json!(row.updated_at));serde_json::Value::Object(value)}).collect::<Vec<_>>();
                return axum::Json(rows).into_response();
            }
            if input["action"]=="grant-row" {
                use alibi::AuthVerification as _;
                use sha2::Digest as _;
                use base64::Engine as _;
                let identifier=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input["token"].as_str().unwrap().as_bytes()));
                let row=auth.store().get_verification_by_identifier(&identifier).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"value":serde_json::from_str::<serde_json::Value>(row.value()).unwrap(),"createdAt":row.created_at(),"expiresAt":row.expires_at()}))).into_response();
            }
            if input["action"]=="admin-http" {
                let mut request=alibi::AuthRequest::new(if input["operation"]=="update" {alibi::HttpMethod::Patch}else{alibi::HttpMethod::Post},if input["operation"]=="update" {admin_path.replace("create-client","update-client")}else{admin_path});
                request.body=Some(serde_json::to_vec(&input["body"]).unwrap());
                _=request.headers.insert("content-type".into(),"application/json".into());
                if let Some(cookie)=input["headers"]["cookie"].as_str(){_=request.headers.insert("cookie".into(),cookie.to_owned());}
                let response=auth.handle_request(request).await.unwrap();
                return axum::Json(serde_json::json!({"status":response.status})).into_response();
            }
            if input["action"]=="row" {
                let row=auth.store().get_oauth_client(input["clientId"].as_str().unwrap()).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"clientId":row.client_id,"userId":row.user_id,"clientName":row.metadata.get("client_name"),"redirectUris":row.metadata.get("redirect_uris"),"client_secret":row.client_secret}))).into_response();
            }
            let (plugin,operation)=if input["action"]=="signup" {("email-password","signUpEmail")}else if input["action"]=="session" {("session-management","getSession")}else if input["action"]=="authorize" {("oauth-provider","oauth2Authorize")}else if input["action"]=="resource-unlink" {("oauth-provider","adminUnlinkClientResource")}else if input["action"]=="resource-link" {("oauth-provider","adminLinkClientResource")}else if input["action"]=="resource-delete" {("oauth-provider","adminDeleteOAuthResource")}else if input["action"]=="resource-update" {("oauth-provider","adminUpdateOAuthResource")}else if input["action"]=="resource-get" {("oauth-provider","adminGetOAuthResource")}else if input["action"]=="resource-list" {("oauth-provider","adminListOAuthResources")}else if input["action"]=="resource-create" {("oauth-provider","adminCreateOAuthResource")}else if input["action"]=="consent-delete" {("oauth-provider","deleteOAuthConsent")}else if input["action"]=="consent-update" {("oauth-provider","updateOAuthConsent")}else if input["action"]=="consent-get" {("oauth-provider","getOAuthConsent")}else if input["action"]=="consents" {("oauth-provider","getOAuthConsents")}else if input["action"]=="consent" {("oauth-provider","oauth2Consent")}else if input["action"]=="prelogin" {("oauth-provider","getOAuthClientPublicPrelogin")}else if input["action"]=="admin-update" {("oauth-provider","adminUpdateOAuthClient")}else if input["action"]=="admin-create" {("oauth-provider","adminCreateOAuthClient")}else if input["action"]=="register" {("oauth-provider","registerOAuthClient")}else if input["action"]=="update" {("oauth-provider","updateOAuthClient")}else if input["action"]=="rotate" {("oauth-provider","rotateClientSecret")}else if input["action"]=="delete" {("oauth-provider","deleteOAuthClient")}else if input["action"]=="list" {("oauth-provider","getOAuthClients")}else if input["action"]=="public" {("oauth-provider","getOAuthClientPublic")}else if input["action"]=="get" {("oauth-provider","getOAuthClient")}else{("oauth-provider","createOAuthClient")};
            let endpoint=if input["action"]=="resource-update" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_params(&input["params"]).unwrap().with_body(&input["body"]).unwrap()}else if input["action"]=="resource-get" || input["action"]=="resource-delete" || input["action"]=="resource-link" || input["action"]=="resource-unlink" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_params(&input["params"]).unwrap()}else if input["action"]=="consent-get" || input["action"]=="get" || input["action"]=="public" || input["action"]=="authorize" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_query(&input["query"]).unwrap()} else {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_body(&input["body"]).unwrap()};
            match auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),request:if (input["action"]=="authorize" || input["action"]=="consent") && input["attachRequest"]!=false {let mut request=alibi::AuthRequest::new(if input["action"]=="consent" {alibi::HttpMethod::Post}else{alibi::HttpMethod::Get},if input["action"]=="consent"{authorization_path.replace("authorize","consent")}else{authorization_path});request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();Some(request)}else{None},..Default::default()}).await {
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
