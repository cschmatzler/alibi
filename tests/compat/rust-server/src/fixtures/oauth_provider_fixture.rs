//! Direct discovery delegates to actual configured provider/JWT plugins.
use crate::TestSchema;
use alibi::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin};
use alibi::seaorm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use std::{collections::HashMap, sync::Arc};
#[derive(Debug)]
struct MachinePrivileges;
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientPrivileges for MachinePrivileges {
    async fn allowed(&self,ctx:&alibi::plugins::OAuthClientPrivilegeContext)->alibi::AuthResult<bool> {
        Ok(ctx.action=="configure-client-credentials-scopes" && ctx.headers.get("x-machine-operator").map(String::as_str)==Some("grant") && ctx.user.get("email").and_then(serde_json::Value::as_str).is_some_and(|email|email.contains("machine-owner")) && ctx.session.get("userId")==ctx.user.get("id"))
    }
}
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
    let mut client_instances = HashMap::new();
    for mode in [
        "default",
        "dynamic",
        "public",
        "prelogin",
        "expired",
        "resources-open",
        "selection",
        "machine",
    ] {
        let provider = OAuthProviderConfig {
            client_credentials_scope_privileges:if mode=="machine"{Some(Arc::new(MachinePrivileges))}else{None},
            scopes:if mode=="machine"{vec!["api:read".into(),"api:write".into()]}else{OAuthProviderConfig::default().scopes},
            select_account_page: if mode == "selection" {
                Some("/select".into())
            } else {
                None
            },
            enforce_per_client_resources: mode != "resources-open",
            allow_public_client_prelogin: matches!(mode, "prelogin" | "expired"),
            code_expires_in: if mode == "expired" { -1.0 } else { 600.0 },
            allow_dynamic_client_registration: matches!(mode, "dynamic" | "public"),
            allow_unauthenticated_client_registration: mode == "public",
            ..Default::default()
        };
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
        client_instances.insert(mode.to_owned(), auth);
    }
    let logout_database=database.clone();
    let logout_origin = config.base_url.clone();
    let authorization_path = format!("{}/oauth2/authorize", config.base_path);
    let admin_path = format!("{}/admin/oauth2/create-client", config.base_path);
    Ok(Router::new().route("/__test/server-api/oauth-provider-clients",axum::routing::post(move |axum::Json(input):axum::Json<serde_json::Value>| {
        let logout_database=logout_database.clone();
        let logout_origin=logout_origin.clone();
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
                let mut request=alibi::AuthRequest::new(if input["operation"]=="delete" || input["operation"]=="unlink"{alibi::HttpMethod::Delete}else if input["operation"]=="update"{alibi::HttpMethod::Patch}else if input["operation"]=="list" || input["operation"]=="read" {alibi::HttpMethod::Get}else{alibi::HttpMethod::Post},if input["operation"]=="read" || input["operation"]=="update" || input["operation"]=="delete" || input["operation"]=="link" || input["operation"]=="unlink" {format!("{}/{}{}",admin_path.replace("create-client","resources"),url::form_urlencoded::byte_serialize(input["identifier"].as_str().unwrap().as_bytes()).collect::<String>(),if input["operation"]=="link" || input["operation"]=="unlink"{format!("/clients/{}",url::form_urlencoded::byte_serialize(input["clientId"].as_str().unwrap().as_bytes()).collect::<String>())}else{String::new()})}else{admin_path.replace("create-client","resources")});request.body=Some(serde_json::to_vec(&input["body"]).unwrap());request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();_=request.headers.insert("content-type".into(),"application/json".into());
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
                return axum::Json(row.map(|row|serde_json::json!({"id":row.id,"clientId":row.client_id,"userId":row.user_id,"clientName":row.metadata.get("client_name"),"redirectUris":row.metadata.get("redirect_uris"),"client_secret":row.client_secret}))).into_response();
            }
            if input["action"]=="token-row" {
                use base64::Engine as _; use sha2::Digest as _;
                let hashed=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input["token"].as_str().unwrap()));
                let row=auth.store().get_oauth_token(if input["kind"]=="refresh" {alibi::store::OAuthTokenKind::Refresh}else{alibi::store::OAuthTokenKind::Access},&hashed).await.unwrap();
                return axum::Json(row.map(|r|serde_json::json!({"id":r.id,"clientId":r.client_id,"userId":r.user_id,"sessionId":r.session_id,"scopes":r.metadata["scopes"],"createdAt":r.created_at,"expiresAt":r.expires_at,"authorizationCodeId":r.authorization_code_id,"token":r.token,"refreshId":r.metadata.get("refreshId"),"authTime":r.metadata.get("authTime"),"resources":r.metadata.get("resources"),"revoked":r.metadata.get("revoked"),"rotatedAt":r.metadata.get("rotatedAt")}))).into_response();
            }
            if input["action"]=="expire-session" {
                use alibi::AuthSession as _;
                let token=input["token"].as_str().unwrap();
                auth.store().update_session_expiry(token,chrono::Utc::now()-chrono::Duration::seconds(1)).await.unwrap();
                let updated=auth.store().get_session(token).await.unwrap();
                return axum::Json(serde_json::json!({"expired":updated.is_some_and(|session|session.expires_at()<chrono::Utc::now())})).into_response();
            }
            if input["action"]=="revoke-concurrently" {
                let call=||async {
                    let mut request=alibi::AuthRequest::new(alibi::HttpMethod::Post,authorization_path.replace("authorize","revoke"));
                    request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();
                    let result=auth.dispatch_endpoint(alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("oauth-provider","oauth2Revoke").with_body(&input["body"]).unwrap(),alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),request:Some(request),..Default::default()}).await;
                    match result {Ok(output)=>output.into_response().unwrap().status,Err(error)=>error.error.status_code()}
                };
                let (first,second)=tokio::join!(call(),call());let mut statuses=vec![first,second];statuses.sort_unstable();
                return axum::Json(statuses).into_response();
            }
            if input["action"]=="signout" && input["foreignKeys"]==true {
                use alibi::seaorm::sea_orm::{ConnectionTrait,DbBackend,Statement};
                let prior=logout_database.query_one_raw(Statement::from_string(DbBackend::Sqlite,"PRAGMA foreign_keys")).await.unwrap().unwrap().try_get::<i64>("","foreign_keys").unwrap();
                _=logout_database.execute_unprepared("PRAGMA foreign_keys=ON").await.unwrap();
                let outcome=auth.dispatch_endpoint(alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("session-management","signOut"),alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|value|serde_json::from_value(value.clone()).unwrap()),..Default::default()}).await;
                _=logout_database.execute_unprepared(&format!("PRAGMA foreign_keys={prior}")).await.unwrap();
                return outcome.unwrap().into_response().unwrap().into_response();
            }
            if input["action"]=="session-row" {
                use alibi::AuthSession as _;
                let row=auth.store().get_session(input["token"].as_str().unwrap()).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"id":row.id()}))).into_response();
            }
            if input["action"]=="logout-http" || input["action"]=="protocol-http" {
                let prefix=authorization_path.strip_suffix("/oauth2/authorize").unwrap();
                let mut request=alibi::AuthRequest::new(if input["method"]=="POST"{alibi::HttpMethod::Post}else{alibi::HttpMethod::Get},format!("{prefix}{}",input["path"].as_str().unwrap()));
                request.headers=input.get("headers").map(|value|serde_json::from_value(value.clone()).unwrap()).unwrap_or_default();
                _=request.headers.insert("origin".into(),logout_origin);
                _=request.headers.insert("content-type".into(),input["contentType"].as_str().unwrap_or("application/x-www-form-urlencoded; charset=UTF-8").into());
                if input["method"]=="POST" && input["contentType"]=="application/json" {request.body=Some(serde_json::to_vec(&input["body"]).unwrap());}else if input["method"]=="POST"{request.body=Some(url::form_urlencoded::Serializer::new(String::new()).extend_pairs(input["body"].as_object().unwrap().iter().map(|(key,value)|(key.as_str(),value.as_str().unwrap()))).finish().into_bytes());}
                return auth.handle_request(request).await.unwrap().into_response();
            }
            let (plugin,operation)=if input["action"]=="signout" {("session-management","signOut")}else if input["action"]=="confirm-logical" {("oauth-provider","oauth2EndSessionConfirmation")}else if input["action"]=="end-session" {("oauth-provider","oauth2EndSession")}else if input["action"]=="userinfo" {("oauth-provider","oauth2UserInfo")}else if input["action"]=="jwks" {("jwt","getJwks")}else if input["action"]=="revoke" {("oauth-provider","oauth2Revoke")}else if input["action"]=="introspect" {("oauth-provider","oauth2Introspect")}else if input["action"]=="token" {("oauth-provider","oauth2Token")}else if input["action"]=="signup" {("email-password","signUpEmail")}else if input["action"]=="session" {("session-management","getSession")}else if input["action"]=="authorize" {("oauth-provider","oauth2Authorize")}else if input["action"]=="resource-unlink" {("oauth-provider","adminUnlinkClientResource")}else if input["action"]=="resource-link" {("oauth-provider","adminLinkClientResource")}else if input["action"]=="resource-delete" {("oauth-provider","adminDeleteOAuthResource")}else if input["action"]=="resource-update" {("oauth-provider","adminUpdateOAuthResource")}else if input["action"]=="resource-get" {("oauth-provider","adminGetOAuthResource")}else if input["action"]=="resource-list" {("oauth-provider","adminListOAuthResources")}else if input["action"]=="resource-create" {("oauth-provider","adminCreateOAuthResource")}else if input["action"]=="consent-delete" {("oauth-provider","deleteOAuthConsent")}else if input["action"]=="consent-update" {("oauth-provider","updateOAuthConsent")}else if input["action"]=="consent-get" {("oauth-provider","getOAuthConsent")}else if input["action"]=="consents" {("oauth-provider","getOAuthConsents")}else if input["action"]=="continue" {("oauth-provider","oauth2Continue")}else if input["action"]=="consent" {("oauth-provider","oauth2Consent")}else if input["action"]=="prelogin" {("oauth-provider","getOAuthClientPublicPrelogin")}else if input["action"]=="admin-update" {("oauth-provider","adminUpdateOAuthClient")}else if input["action"]=="admin-create" {("oauth-provider","adminCreateOAuthClient")}else if input["action"]=="register" {("oauth-provider","registerOAuthClient")}else if input["action"]=="update" {("oauth-provider","updateOAuthClient")}else if input["action"]=="rotate" {("oauth-provider","rotateClientSecret")}else if input["action"]=="delete" {("oauth-provider","deleteOAuthClient")}else if input["action"]=="list" {("oauth-provider","getOAuthClients")}else if input["action"]=="public" {("oauth-provider","getOAuthClientPublic")}else if input["action"]=="get" {("oauth-provider","getOAuthClient")}else{("oauth-provider","createOAuthClient")};
            let endpoint=if input["action"]=="signout" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation)}else if input["action"]=="confirm-logical" {alibi::plugins::OAuthProviderPlugin::oauth2_end_session_confirmation_endpoint().unwrap()}else if input["action"]=="userinfo" {let endpoint=alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation);if let Some(body)=input.get("body"){endpoint.with_body(body).unwrap()}else{endpoint}}else if input["action"]=="resource-update" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_params(&input["params"]).unwrap().with_body(&input["body"]).unwrap()}else if input["action"]=="resource-get" || input["action"]=="resource-delete" || input["action"]=="resource-link" || input["action"]=="resource-unlink" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_params(&input["params"]).unwrap()}else if input["action"]=="consent-get" || input["action"]=="get" || input["action"]=="public" || (input["action"]=="authorize" || input["action"]=="end-session") {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_query(&input["query"]).unwrap()} else {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_body(&input["body"]).unwrap()};
            match auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),request:if (input["action"]=="userinfo" || input["action"]=="revoke" || input["action"]=="introspect" || input["action"]=="token" || input["action"]=="authorize" || input["action"]=="consent" || input["action"]=="continue") && input["attachRequest"]!=false {let mut request=alibi::AuthRequest::new(if (input["action"]=="userinfo" && input["method"]=="POST") || input["action"]=="revoke" || input["action"]=="introspect" || input["action"]=="token" || input["action"]=="consent" || input["action"]=="continue" {alibi::HttpMethod::Post}else{alibi::HttpMethod::Get},if input["action"]=="userinfo"{authorization_path.replace("authorize","userinfo")}else if input["action"]=="revoke"{authorization_path.replace("authorize","revoke")}else if input["action"]=="introspect"{authorization_path.replace("authorize","introspect")}else if input["action"]=="token"{authorization_path.replace("authorize","token")}else if input["action"]=="continue"{authorization_path.replace("authorize","continue")}else if input["action"]=="consent"{authorization_path.replace("authorize","consent")}else{authorization_path});request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();Some(request)}else{None},..Default::default()}).await {
                Ok(output)=>output.into_response().unwrap().into_response(),
                Err(error)=>{let mut response=if error.body_absent{alibi::AuthResponse::new(error.error.status_code())}else{error.error.to_auth_response()};if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}
                if let Some(headers)=error.headers {for(name,value)in headers.iter(){if name.eq_ignore_ascii_case("set-cookie"){response.headers.append(name,value);}else{response.headers.insert(name,value);}}}response.into_response()}
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
