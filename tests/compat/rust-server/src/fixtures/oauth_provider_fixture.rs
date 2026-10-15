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
    async fn allowed(
        &self,
        ctx: &alibi::plugins::OAuthClientPrivilegeContext,
    ) -> alibi::AuthResult<bool> {
        Ok(ctx.action == "configure-client-credentials-scopes"
            && ctx.headers.get("x-machine-operator").map(String::as_str) == Some("grant")
            && ctx
                .user
                .get("email")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|email| email.contains("machine-owner"))
            && ctx.session.get("userId") == ctx.user.get("id"))
    }
}
#[derive(Debug)]
struct OperatorClientSecrets {
    calls: std::sync::atomic::AtomicUsize,
    empty: bool,
}
impl alibi::plugins::OAuthClientSecretGenerator for OperatorClientSecrets {
    fn generate(&self) -> alibi::AuthResult<String> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        Ok(if self.empty {String::new()} else {format!("operator-secret-{call}")})
    }
}
#[derive(Debug)]
struct OperatorClientIds {calls:std::sync::atomic::AtomicUsize,empty:bool}
impl alibi::plugins::OAuthClientIdGenerator for OperatorClientIds {
    fn generate(&self)->alibi::AuthResult<String> {let call=self.calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst)+1;Ok(if self.empty {String::new()} else {format!("operator-client-{call}")})}
}
#[derive(Debug)]
struct FormCredentials;
impl alibi::plugins::OAuthClientIdGenerator for FormCredentials {
    fn generate(&self)->alibi::AuthResult<String>{Ok("client +/é:fixed".into())}
}
impl alibi::plugins::OAuthClientSecretGenerator for FormCredentials {
    fn generate(&self)->alibi::AuthResult<String>{Ok("secret +/é:tail".into())}
}
#[derive(Debug,Default)]
struct RegistryState {mode:std::sync::atomic::AtomicU8,events:std::sync::Mutex<Vec<String>>}
#[derive(Debug)]
struct RegistryDiscovery {first:bool,state:Arc<RegistryState>}
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientDiscovery for RegistryDiscovery {
    fn id(&self)->&str{if self.first{"registry-first"}else{"registry-live"}}
    fn matches(&self,id:&str)->bool{self.state.events.lock().unwrap().push(if self.first{"first:matches"}else{"live:matches"}.into());id.starts_with("registry-") && (self.first || self.state.mode.load(std::sync::atomic::Ordering::SeqCst)!=2)}
    async fn resolve(&self,callback:&alibi::CallbackContext,id:&str,existing:Option<alibi::store::OAuthClient>)->alibi::AuthResult<Option<alibi::store::OAuthClient>> {
        self.state.events.lock().unwrap().push(if self.first{"first:resolve"}else if existing.is_some(){"live:resolve:existing"}else{"live:resolve:new"}.into());
        let mode=self.state.mode.load(std::sync::atomic::Ordering::SeqCst);
        if self.first || mode==1{return Ok(None);}
        let ctx=callback.context::<TestSchema>().ok_or_else(||alibi::AuthError::internal("Missing real callback context"))?;
        if let Some(mut existing)=existing {
            if mode==3 {existing.metadata["client_name"]=serde_json::json!("Updated registry");return ctx.database.update_oauth_client_metadata(id,existing.metadata,chrono::Utc::now()).await;}
            return Ok(Some(existing));
        }
        ctx.database.create_oauth_client(alibi::store::CreateOAuthClient{client_id:id.into(),user_id:None,client_secret:None,metadata:serde_json::json!({"client_discovery_id":"registry-live","client_name":"Registry client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none","scope":"email","grant_types":["authorization_code"],"response_types":["code"],"disabled":false}),created_at:chrono::Utc::now()}).await.map(Some)
    }
}
#[derive(Debug)]
struct ValidationDiscovery(String);
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientDiscovery for ValidationDiscovery {
    fn id(&self)->&str{&self.0}
    fn matches(&self,_:&str)->bool{false}
    async fn resolve(&self,_:&alibi::CallbackContext,_:&str,_:Option<alibi::store::OAuthClient>)->alibi::AuthResult<Option<alibi::store::OAuthClient>>{Ok(None)}
}
#[derive(Debug)]
struct ManagedRegistryId;
impl alibi::plugins::OAuthClientIdGenerator for ManagedRegistryId {fn generate(&self)->alibi::AuthResult<String>{Ok("registry-managed".into())}}

#[path = "../../../../fixtures/oauth/remote-jwks-response.rs"]
mod remote_response;
#[derive(Debug)]
struct RemoteResource {mode:std::sync::Mutex<String>,uri:std::sync::Mutex<String>,document:std::sync::Mutex<serde_json::Value>,fetches:std::sync::Mutex<Vec<serde_json::Value>>}
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientMetadataResourceFetch for RemoteResource {
    async fn fetch(&self,url:&str,options:alibi::plugins::OAuthClientMetadataFetchOptions)->alibi::AuthResult<alibi::plugins::OAuthClientMetadataFetchResponse> {
        self.fetches.lock().unwrap().push(serde_json::json!({"url":url,"accept":options.headers.get("accept"),"redirect":options.redirect,"aborted":options.signal.aborted()}));
        let mode=self.mode.lock().unwrap().clone();
        if mode=="exception" {return Err(alibi::AuthError::internal("offline"));}
        let (status,headers,bytes)=remote_response::response(&mode,&self.document.lock().unwrap());
        let mut response=axum::http::Response::builder().status(status);
        for(key,value)in headers{response=response.header(key,value);}
        let response=response.body(bytes).unwrap();
        Ok(alibi::plugins::OAuthClientMetadataFetchResponse{response:response.into(),redirected:false})
    }
}
#[derive(Debug)]
struct RemoteRegistry {resource:Arc<RemoteResource>}
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientDiscovery for RemoteRegistry {
    fn id(&self)->&str{"remote-registry"}
    fn matches(&self,id:&str)->bool{id=="https://client.fixture.test/client.json"}
    fn metadata_resource_fetch(&self)->Option<Arc<dyn alibi::plugins::OAuthClientMetadataResourceFetch>>{if *self.resource.mode.lock().unwrap()=="no-transport"{None}else{Some(self.resource.clone())}}
    async fn resolve(&self,callback:&alibi::CallbackContext,id:&str,existing:Option<alibi::store::OAuthClient>)->alibi::AuthResult<Option<alibi::store::OAuthClient>> {
        let mut client=if let Some(existing)=existing{existing}else{
        callback.context::<TestSchema>().unwrap().database.create_oauth_client(alibi::store::CreateOAuthClient{client_id:id.into(),client_secret:None,user_id:None,metadata:serde_json::json!({"client_discovery_id":"remote-registry","client_name":"Remote client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.fixture.test/jwks","scope":"email","grant_types":["authorization_code"],"response_types":["code"]}),created_at:chrono::Utc::now()}).await?};
        client.metadata["jwks_uri"]=serde_json::json!(*self.resource.uri.lock().unwrap());
        Ok(Some(client))
    }
}
fn remote_document(family:&str,algorithm:&str,kid:&str)->serde_json::Value {
    let keys:serde_json::Value=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../fixtures/oauth/client-assertion-keys.json"))).unwrap();
    let mut public=keys["keys"].as_array().unwrap().iter().find(|key|key["family"]==family).unwrap()["publicJwk"].clone();
    public["alg"]=serde_json::json!(algorithm);public["kid"]=serde_json::json!(kid);serde_json::json!({"keys":[public]})
}

#[derive(Debug)]
struct CustomSecretHash;
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientSecretHasher for CustomSecretHash {
    async fn hash(&self,secret:&str)->alibi::AuthResult<String>{
        use base64::Engine as _;use sha2::Digest as _;
        Ok(format!("custom:{}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(secret.as_bytes()))))
    }
}
#[derive(Debug)]
struct CustomSecretVerify;
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientSecretHasher for CustomSecretVerify {
    async fn hash(&self,secret:&str)->alibi::AuthResult<String>{alibi::plugins::OAuthClientSecretHasher::hash(&CustomSecretHash,secret).await}
    async fn verify(&self,secret:&str,stored:&str)->alibi::AuthResult<bool>{Ok(alibi::plugins::OAuthClientSecretHasher::hash(&CustomSecretHash,secret.strip_suffix('!').unwrap_or(secret)).await?==stored)}
}

#[derive(Debug)]
struct MetadataDiscovery {id:&'static str,empty:bool}
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientDiscovery for MetadataDiscovery {
    fn id(&self)->&str{self.id}
    fn matches(&self,_:&str)->bool{false}
    fn discovery_metadata(&self)->serde_json::Map<String,serde_json::Value>{
        if self.empty{return serde_json::Map::new();}
        let value=if self.id=="metadata-first"{serde_json::json!({
            "client_id_metadata_document_supported":true,"registry_order":"first","registry_first_only":17,
            "issuer":"https://untrusted.fixture.test","token_endpoint_auth_methods_supported":["wrong"],"scopes_supported":["wrong"],"claims_supported":["wrong"],"jwks_uri":"https://untrusted.fixture.test/keys"
        })}else{serde_json::json!({"registry_order":"second","registry_second_only":{"enabled":true},"issuer":"https://also-untrusted.fixture.test"})};
        value.as_object().unwrap().clone()
    }
    async fn resolve(&self,_:&alibi::CallbackContext,_:&str,_:Option<alibi::store::OAuthClient>)->alibi::AuthResult<Option<alibi::store::OAuthClient>>{Ok(None)}
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut instances = HashMap::new();
    for mode in ["default", "oauth", "disabled", "configured", "registry", "registry-oauth", "registry-empty"] {
        let mut provider = OAuthProviderConfig::default();
        if mode.starts_with("registry") {
            provider.client_discoveries=["metadata-first","metadata-second"].into_iter().map(|id|Arc::new(MetadataDiscovery{id,empty:mode=="registry-empty"}) as Arc<dyn alibi::plugins::OAuthClientDiscovery>).collect();
            if mode=="registry-oauth"{provider.scopes=vec!["read".into()];}
        }
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
    let registry_state=Arc::new(RegistryState::default());
    let remote_state=Arc::new(RemoteResource{mode:std::sync::Mutex::new("valid".into()),uri:std::sync::Mutex::new("https://client.fixture.test/jwks".into()),document:std::sync::Mutex::new(remote_document("RSA","RS256","first")),fetches:std::sync::Mutex::default()});
    let remote_provider=OAuthProviderPlugin::with_config(OAuthProviderConfig{client_discoveries:vec![Arc::new(RemoteRegistry{resource:remote_state.clone()})],..Default::default()});

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
        "reuse",
        "generated",
        "empty-generator",
        "encrypted-generator",
        "prefixed-generator",
        "encrypted-prefixed-generator",
        "custom-hash",
        "custom-prefixed-verify",
        "generated-id",
        "empty-id",
        "basic-special",
        "assertion-short",
        "assertion-zero",
        "assertion-negative",
        "assertion-nan",
        "assertion-infinite",
        "assertion-negative-infinite",
        "assertion-helper",
        "assertion-helper-peer",
        "discovered",
        "uri-host",
        "remote-jwks",
        "remote-jwks-peer",
    ] {
        let provider = OAuthProviderConfig {
            client_discoveries: if mode=="discovered" {vec![Arc::new(RegistryDiscovery{first:true,state:registry_state.clone()}),Arc::new(RegistryDiscovery{first:false,state:registry_state.clone()})]}else{Vec::new()},
            client_id_generator: if mode=="discovered" {Some(Arc::new(ManagedRegistryId))} else if mode == "basic-special" {Some(Arc::new(FormCredentials))} else if matches!(mode, "generated-id" | "empty-id") {Some(Arc::new(OperatorClientIds {calls:std::sync::atomic::AtomicUsize::new(0),empty:mode=="empty-id"}))} else {None},
            assertion_max_lifetime: match mode {"assertion-short"=>30.0,"assertion-zero"=>0.0,"assertion-negative"=>-1.0,"assertion-nan"=>f64::NAN,"assertion-infinite"=>f64::INFINITY,"assertion-negative-infinite"=>f64::NEG_INFINITY,_=>300.0},
            disable_jwt_plugin: matches!(mode,"encrypted-generator"|"encrypted-prefixed-generator"),
            client_secret_prefix: mode.contains("prefixed").then(|| "client_prefix_".into()),
            client_secret_hasher:match mode {"custom-hash"=>Some(Arc::new(CustomSecretHash)),"custom-prefixed-verify"=>Some(Arc::new(CustomSecretVerify)),_=>None},
            client_secret_generator: if mode == "basic-special" {Some(Arc::new(FormCredentials))} else if matches!(mode, "generated" | "empty-generator" | "encrypted-generator" | "prefixed-generator" | "encrypted-prefixed-generator" | "custom-hash" | "custom-prefixed-verify") {
                Some(Arc::new(OperatorClientSecrets {calls: std::sync::atomic::AtomicUsize::new(0), empty: mode == "empty-generator"}))
            } else {None},
            refresh_token_reuse_interval: if mode == "reuse" { 60.0 } else { 0.0 },
            client_credentials_scope_privileges: if mode == "machine" {
                Some(Arc::new(MachinePrivileges))
            } else {
                None
            },
            scopes: if mode == "machine" {
                vec!["api:read".into(), "api:write".into()]
            } else {
                OAuthProviderConfig::default().scopes
            },
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
        let client_config=if mode=="uri-host" {config.clone().trusted_origin("https://*")}else{config.clone()};
        let builder = AuthBuilder::<TestSchema>::new(client_config.clone())
            .store(crate::backend::store::<TestSchema>(client_config, database.clone()))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(alibi::plugins::SessionManagementPlugin::new());
        let builder = if matches!(mode,"encrypted-generator"|"encrypted-prefixed-generator") {builder} else {builder.plugin(JwtPlugin::new())};
        let provider=if matches!(mode,"remote-jwks"|"remote-jwks-peer"){remote_provider.clone()}else{OAuthProviderPlugin::with_config(provider)};
        let auth = Arc::new(builder.plugin(provider).build().await?);
        client_instances.insert(mode.to_owned(), auth);
    }
    let validation_config=config.clone();
    let logout_database = database.clone();
    let logout_origin = config.base_url.clone();
    let authorization_path = format!("{}/oauth2/authorize", config.base_path);
    let admin_path = format!("{}/admin/oauth2/create-client", config.base_path);
    Ok(Router::new().route("/__test/server-api/oauth-provider-clients",axum::routing::post(move |axum::Json(input):axum::Json<serde_json::Value>| {
        let logout_database=logout_database.clone();
        let registry_state=registry_state.clone();
        let remote_state=remote_state.clone();
        let validation_config=validation_config.clone();
        let logout_origin=logout_origin.clone();
        let authorization_path=authorization_path.clone();
        let admin_path=admin_path.clone();
        let auth=client_instances.get(input["mode"].as_str().unwrap_or("default")).unwrap().clone();async move {
            if input["action"]=="secret-hash-validation" {
                let result=AuthBuilder::<TestSchema>::new(validation_config.clone()).store(crate::backend::store::<TestSchema>(validation_config,logout_database.clone())).plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig{disable_jwt_plugin:true,client_secret_hasher:Some(Arc::new(CustomSecretHash)),..Default::default()})).build().await;
                return axum::Json(match result {Ok(_)=>serde_json::json!({"valid":true}),Err(alibi::AuthError::Config(message))=>serde_json::json!({"valid":false,"message":message}),Err(error)=>panic!("unexpected configuration failure: {error}")}).into_response();
            }
            if input["action"]=="remote-jwks-document" {
                *remote_state.document.lock().unwrap()=remote_document(input["family"].as_str().unwrap(),input["algorithm"].as_str().unwrap(),input["kid"].as_str().unwrap());
                return axum::Json(serde_json::json!({"updated":true})).into_response();
            }
            if input["action"]=="remote-jwks-response" {
                *remote_state.mode.lock().unwrap()=input["responseMode"].as_str().unwrap().into();
                *remote_state.uri.lock().unwrap()=input["uri"].as_str().unwrap().into();
                remote_state.fetches.lock().unwrap().clear();
                return axum::Json(serde_json::json!({"updated":true})).into_response();
            }
            if input["action"]=="remote-jwks-fetches" {return axum::Json(remote_state.fetches.lock().unwrap().clone()).into_response();}
            if input["action"]=="discovery-validation" {
                let sources=input["ids"].as_array().unwrap().iter().map(|id|Arc::new(ValidationDiscovery(id.as_str().unwrap().into())) as Arc<dyn alibi::plugins::OAuthClientDiscovery>).collect();
                let cfg=OAuthProviderConfig{client_discoveries:sources,..Default::default()};
                let result=AuthBuilder::<TestSchema>::new(validation_config.clone()).store(crate::backend::store::<TestSchema>(validation_config,logout_database.clone())).plugin(JwtPlugin::new()).plugin(OAuthProviderPlugin::with_config(cfg)).build().await;
                return axum::Json(match result {Ok(_)=>serde_json::json!({"valid":true}),Err(alibi::AuthError::Config(message))=>serde_json::json!({"valid":false,"message":message}),Err(error)=>panic!("unexpected configuration failure: {error}")}).into_response();
            }
            if input["action"]=="discovery-state" {
                registry_state.mode.store(match input["state"].as_str().unwrap(){"reject"=>1,"mismatch"=>2,"refresh"=>3,_=>0},std::sync::atomic::Ordering::SeqCst);
                registry_state.events.lock().unwrap().clear();
                return axum::Json(serde_json::json!({"updated":true})).into_response();
            }
            if input["action"]=="discovery-events" {return axum::Json(registry_state.events.lock().unwrap().clone()).into_response();}
            if input["action"]=="discovery-row" {
                let row=auth.store().get_oauth_client(input["clientId"].as_str().unwrap()).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"clientId":row.client_id,"clientDiscoveryId":row.metadata.get("client_discovery_id"),"name":row.metadata.get("client_name")}))).into_response();
            }
            if input["action"]=="consume-assertion" {
                let params=&input["params"];
                let payload=alibi::utils::json::JsValue::from(params["payload"].clone());
                match alibi::plugins::consume_client_assertion(auth.context(),&OAuthProviderConfig::default(),params["namespace"].as_str().unwrap(),&payload,params["expectedAudience"].as_str().unwrap()).await {
                    Ok(())=>return axum::Json(serde_json::json!({"consumed":true})).into_response(),
                    Err(error)=>{
                        let mut response=alibi::endpoint::EndpointResponse::error(error.error);
                        if let Some(body)=error.body {response=response.with_error_body(*body);}
                        return response.to_response().unwrap().into_response();
                    }
                }
            }
            if input["action"]=="assertion-row" {
                use alibi::seaorm::{sea_orm::EntityTrait as _,store::entities::oauth_client_assertion::Entity};
                let row=Entity::find_by_id(input["id"].as_str().unwrap()).one(&logout_database).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"id":row.id,"expiresAt":row.expires_at}))).into_response();
            }
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
                return axum::Json(row.map(|r|serde_json::json!({"id":r.id,"clientId":r.client_id,"userId":r.user_id,"sessionId":r.session_id,"scopes":r.metadata["scopes"],"createdAt":r.created_at,"expiresAt":r.expires_at,"authorizationCodeId":r.authorization_code_id,"token":r.token,"refreshId":r.metadata.get("refreshId"),"authTime":r.metadata.get("authTime"),"resources":r.metadata.get("resources"),"revoked":r.metadata.get("revoked"),"rotatedAt":r.metadata.get("rotatedAt"),"rotationReplayResponse":r.metadata.get("rotationReplayResponse"),"rotationReplayExpiresAt":r.metadata.get("rotationReplayExpiresAt")}))).into_response();
            }
            if input["action"]=="replace-refresh-replay" {
                use base64::Engine as _;use sha2::Digest as _;
                let hash=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input["token"].as_str().unwrap()));
                let row=auth.store().get_oauth_token(alibi::store::OAuthTokenKind::Refresh,&hash).await.unwrap().unwrap();
                auth.store().store_oauth_refresh_replay(&row.id,input["ciphertext"].as_str().unwrap()).await.unwrap();
                return axum::Json(serde_json::json!({"id":row.id})).into_response();
            }
            if input["action"]=="expire-refresh-replay" {
                use alibi::seaorm::sea_orm::{ConnectionTrait,DbBackend,Statement};
                use base64::Engine as _;use sha2::Digest as _;
                let hash=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input["token"].as_str().unwrap()));
                let expires=(chrono::Utc::now()-chrono::Duration::seconds(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis,true);
                _=logout_database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE \"oauthRefreshToken\" SET \"rotationReplayExpiresAt\"=? WHERE \"token\"=?",[expires.into(),hash.clone().into()])).await.unwrap();
                let row=auth.store().get_oauth_token(alibi::store::OAuthTokenKind::Refresh,&hash).await.unwrap();
                return axum::Json(row.map(|row|serde_json::json!({"id":row.id,"rotationReplayExpiresAt":row.metadata.get("rotationReplayExpiresAt")}))).into_response();
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
            match auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),request:if (input["action"]=="userinfo" || input["action"]=="revoke" || input["action"]=="introspect" || input["action"]=="token" || input["action"]=="authorize" || input["action"]=="consent" || input["action"]=="continue") && input["attachRequest"]!=false {let mut request=alibi::AuthRequest::new(if (input["action"]=="userinfo" && input["method"]=="POST") || input["action"]=="revoke" || input["action"]=="introspect" || input["action"]=="token" || input["action"]=="consent" || input["action"]=="continue" {alibi::HttpMethod::Post}else{alibi::HttpMethod::Get},if input["action"]=="userinfo"{authorization_path.replace("authorize","userinfo")}else if input["action"]=="revoke"{authorization_path.replace("authorize","revoke")}else if input["action"]=="introspect"{authorization_path.replace("authorize","introspect")}else if input["action"]=="token"{authorization_path.replace("authorize","token")}else if input["action"]=="continue"{authorization_path.replace("authorize","continue")}else if input["action"]=="consent"{authorization_path.replace("authorize","consent")}else{authorization_path});request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();
                if matches!(input["action"].as_str(),Some("revoke"|"introspect"|"token")) {
                    let pairs:Vec<(String,String)>=if let Some(entries)=input["formEntries"].as_array() {entries.iter().map(|pair|(pair[0].as_str().unwrap().into(),pair[1].as_str().unwrap().into())).collect()} else {input["body"].as_object().into_iter().flat_map(|body|body.iter()).map(|(key,value)|(key.clone(),alibi::utils::json::JsValue::from(value.clone()).coerce_string().unwrap())).collect()};
                    request.body=Some(url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish().into_bytes());
                    _=request.headers.insert("content-type".into(),"application/x-www-form-urlencoded".into());
                }
                Some(request)}else{None},..Default::default()}).await {
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
