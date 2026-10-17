//! Direct discovery delegates to actual configured provider/JWT plugins.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration as _;
use alibi::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin};
use alibi::seaorm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use std::{collections::HashMap, sync::Arc};
#[path = "../../../../fixtures/oauth/access-jwt.rs"]
mod access_jwt;
#[path = "../../../../fixtures/oauth/extension-grant.rs"]
mod extension_grant;
#[path = "../../../../fixtures/oauth/extension-claims.rs"]
mod extension_claims;
#[path = "../../../../fixtures/oauth/initial-access-token.rs"]
mod initial_access_token;
#[path = "../../../../fixtures/oauth/credential-generators.rs"]
mod credential_generators;
#[path = "../../../../fixtures/oauth/refresh-formatting.rs"]
mod refresh_formatting;
#[path = "../../../../fixtures/oauth/rate-limits.rs"]
mod rate_limits;
#[path = "../../../../fixtures/oauth/extension-authentication.rs"]
mod extension_authentication;
#[path = "../../../../fixtures/oauth/redirect-policy.rs"]
mod redirect_policy;
#[path = "../../../../fixtures/oauth/token-response-fields.rs"]
mod token_response_fields;
#[path = "../../../../fixtures/oauth/request-uri.rs"]
mod request_uri;
#[path = "../../../../fixtures/oauth/signup-policy.rs"]
mod signup_policy;
use extension_grant::ExtensionGrant;
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
struct TypedTokenHasher;
#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenHasher for TypedTokenHasher {
    async fn hash(&self,token:&str,kind:&str)->alibi::AuthResult<String>{use base64::Engine as _;use sha2::Digest as _;Ok(format!("app:{kind}:{}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token))))}
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
struct TrustedClientId;
impl alibi::plugins::OAuthClientIdGenerator for TrustedClientId {fn generate(&self)->alibi::AuthResult<String>{Ok("trusted-client".into())}}
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


const CUSTOM_CIPHER_KEY: &str = "application-client-secret-encryption-key-32-characters";
#[derive(Debug)]
struct CustomSecretCipher;
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientSecretCipher for CustomSecretCipher {
    async fn encrypt(&self,secret:&str)->alibi::AuthResult<String>{
        Ok(format!("custom:{}",alibi::plugins::oauth::encryption::encrypt_token(secret,CUSTOM_CIPHER_KEY)?))
    }
    async fn decrypt(&self,stored:&str)->alibi::AuthResult<String>{
        let ciphertext=stored.strip_prefix("custom:").ok_or_else(||alibi::AuthError::internal("invalid custom ciphertext"))?;
        alibi::plugins::oauth::encryption::decrypt_token(ciphertext,CUSTOM_CIPHER_KEY)
    }
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

#[path="../../../../fixtures/oauth/extension-metadata.rs"]
mod extension_metadata;
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut instances = HashMap::new();
    for mode in ["default", "oauth", "disabled", "configured", "registry", "registry-oauth", "registry-empty","extensions","extensions-oauth","extensions-mutation"] {
        let mut provider = OAuthProviderConfig::default();
        if mode.starts_with("registry") {
            provider.client_discoveries=["metadata-first","metadata-second"].into_iter().map(|id|Arc::new(MetadataDiscovery{id,empty:mode=="registry-empty"}) as Arc<dyn alibi::plugins::OAuthClientDiscovery>).collect();
            if mode=="registry-oauth"{provider.scopes=vec!["read".into()];}
        }
        if mode.starts_with("extensions"){provider.extensions=["first","second"].into_iter().map(|id|Arc::new(alibi::plugins::OAuthProviderExtension{metadata:Some(Arc::new(extension_metadata::ExtensionMetadata{id,mutate:mode=="extensions-mutation"})),..Default::default()})).collect();}
        if mode=="extensions-oauth"{provider.scopes=vec!["read".into()];}
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
    let trusted_config=OAuthProviderConfig{cached_trusted_clients:["trusted-client","trusted-missing"].map(str::to_owned).into(),client_id_generator:Some(Arc::new(TrustedClientId)),..Default::default()};
    let trusted_provider=OAuthProviderPlugin::with_config(trusted_config.clone());
    let remote_provider=OAuthProviderPlugin::with_config(OAuthProviderConfig{client_discoveries:vec![Arc::new(RemoteRegistry{resource:remote_state.clone()})],..Default::default()});

    let mut client_instances = HashMap::new();
    let registration_policy=Arc::new(initial_access_token::RegistrationPolicy::default());
    let live_claims=Arc::new(extension_claims::LiveAccessClaims::default());
    let redirect_policy=Arc::new(redirect_policy::RedirectPolicy::default());
    let signup_policy=Arc::new(signup_policy::SignupPolicy::default());
    let credential_generators=Arc::new(credential_generators::Generators::default());
    let refresh_formatter=Arc::new(refresh_formatting::Formatter::default());
    let user_info_claims=Arc::new(extension_claims::LiveUserInfoClaims::default());
    let id_token_claims=Arc::new(extension_claims::LiveIdTokenClaims::default());
    let response_fields=Arc::new(token_response_fields::TokenResponseFields::default());
    let request_registry=Arc::new(request_uri::RequestRegistry::default());
    for mode in [
        "extension-grant",
        "pairwise",
        "claims",
        "claims-opaque",
        "response-fields",
        "extension-auth",
        "interaction",
        "redirect-policy",
        "request-uri",
        "signup-policy",
        "signup-fallback",
        "signup-empty-page",
        "signup-page-only",
        "default",
        "dynamic",
        "public",
        "token-dynamic",
        "token-public",
        "registration-pkce-absent",
        "registration-pkce-true",
        "registration-pkce-false",
        "registration-scopes-fallback",
        "registration-scopes-custom-provider",
        "registration-scopes-allowed-empty",
        "registration-scopes-empty",
        "registration-scopes-both-empty",
        "registration-scopes-allowed-only",
        "registration-scopes-default-only",
        "registration-scopes-union",
        "registration-scopes-allowed-fallback",
        "prelogin",
        "expired",
        "resources-open",
        "resource-keyring",
        "selection",
        "machine",
        "reuse",
        "generated",
        "empty-generator",
        "encrypted-generator",
        "prefixed-generator",
        "encrypted-prefixed-generator",
        "custom-hash",
        "custom-token-hash",
        "custom-prefixed-verify",
        "custom-encrypted-prefixed",
        "generated-id",
        "empty-id",
        "basic-special",
        "scope-numeric",
        "scope-zero",
        "scope-relative",
        "scope-date",
        "scope-ceiling",
        "issuance-expiry",
        "rate-default",
        "rate-override",
        "rate-false",
        "rate-global-disabled",
        "rate-application",
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
        "trusted",
        "trusted-peer",
    ] {
        let mut provider = OAuthProviderConfig {
            request_uri_resolver:(mode=="request-uri").then(||request_registry.clone() as Arc<dyn alibi::plugins::OAuthRequestUriResolver>),
            validate_redirect_uri:if mode=="request-uri"{Some(request_registry.clone() as Arc<dyn alibi::plugins::OAuthRedirectUriValidator>)}else{(mode=="redirect-policy").then(||redirect_policy.clone() as Arc<dyn alibi::plugins::OAuthRedirectUriValidator>)},
            signup:mode.starts_with("signup-").then(||alibi::plugins::OAuthSignupConfig{page:match mode {"signup-fallback"=>None,"signup-empty-page"=>Some(String::new()),_=>Some("/signup".into())},should_redirect:(mode!="signup-page-only").then(||signup_policy.clone() as Arc<dyn alibi::plugins::OAuthSignupPolicy>)}),
            pairwise_secret: (mode=="pairwise").then(|| "fixture-pairwise-secret-at-least-32-characters".into()),
            token_hasher:(mode=="custom-token-hash").then(||Arc::new(TypedTokenHasher) as Arc<dyn alibi::plugins::OAuthTokenHasher>),
            client_discoveries: if mode=="request-uri"{vec![request_registry.clone()]}else if mode=="discovered" {vec![Arc::new(RegistryDiscovery{first:true,state:registry_state.clone()}),Arc::new(RegistryDiscovery{first:false,state:registry_state.clone()})]}else{Vec::new()},
            client_id_generator: if mode=="discovered" {Some(Arc::new(ManagedRegistryId))} else if mode == "basic-special" {Some(Arc::new(FormCredentials))} else if matches!(mode, "generated-id" | "empty-id") {Some(Arc::new(OperatorClientIds {calls:std::sync::atomic::AtomicUsize::new(0),empty:mode=="empty-id"}))} else {None},
            assertion_max_lifetime: match mode {"assertion-short"=>30.0,"assertion-zero"=>0.0,"assertion-negative"=>-1.0,"assertion-nan"=>f64::NAN,"assertion-infinite"=>f64::INFINITY,"assertion-negative-infinite"=>f64::NEG_INFINITY,_=>300.0},
            disable_jwt_plugin: matches!(mode,"encrypted-generator"|"encrypted-prefixed-generator"|"custom-encrypted-prefixed"|"claims-opaque"),
            client_secret_prefix: mode.contains("prefixed").then(|| "client_prefix_".into()),
            client_secret_cipher:(mode=="custom-encrypted-prefixed").then(||Arc::new(CustomSecretCipher) as Arc<dyn alibi::plugins::OAuthClientSecretCipher>),
            client_secret_hasher:match mode {"custom-hash"=>Some(Arc::new(CustomSecretHash)),"custom-prefixed-verify"=>Some(Arc::new(CustomSecretVerify)),_=>None},
            client_secret_generator: if mode == "basic-special" {Some(Arc::new(FormCredentials))} else if matches!(mode, "generated" | "empty-generator" | "encrypted-generator" | "prefixed-generator" | "encrypted-prefixed-generator" | "custom-hash" | "custom-prefixed-verify" | "custom-encrypted-prefixed") {
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
            select_account_page: if mode == "selection" || mode.starts_with("signup-") {
                Some("/select".into())
            } else {
                None
            },
            enforce_per_client_resources: mode != "resources-open",
            allow_public_client_prelogin: matches!(mode, "prelogin" | "expired"),
            code_expires_in: if mode == "expired" { -1.0 } else { 600.0 },
            allow_dynamic_client_registration: matches!(mode, "dynamic" | "public" | "token-dynamic" | "token-public") || mode.starts_with("registration-pkce-"),
            client_registration_require_pkce: match mode {"registration-pkce-true"=>Some(true),"registration-pkce-false"=>Some(false),_=>None},
            allow_unauthenticated_client_registration: matches!(mode, "public" | "token-public") || mode.starts_with("registration-pkce-"),
            initial_access_token_validator: mode.starts_with("token-").then(||registration_policy.clone() as Arc<dyn alibi::plugins::OAuthInitialAccessTokenValidator>),
            ..Default::default()
        };
        if mode=="extension-grant" {provider.grant_types.push("urn:fixture:orphan".into());provider.extensions.push(Arc::new(alibi::plugins::OAuthProviderExtension{grants:[("urn:fixture:extension".into(),Arc::new(ExtensionGrant) as Arc<dyn alibi::plugins::OAuthExtensionGrantHandler>)].into_iter().collect(),..Default::default()}));}
        if mode=="extension-auth" {provider.extensions=extension_authentication::extensions();}
        if mode=="reuse" {provider.opaque_access_token_generator=Some(credential_generators::access(credential_generators.clone()));provider.refresh_token_generator=Some(credential_generators::refresh(credential_generators.clone()));provider.token_hasher=Some(credential_generators.clone());provider.opaque_access_token_prefix=Some("A_".into());provider.refresh_token_prefix=Some("R_".into());provider.refresh_token_formatter=Some(refresh_formatter.clone());}
        if mode=="claims" {provider.extensions=extension_claims::extensions_with_user_info(user_info_claims.clone());}
        if mode=="claims" {provider.custom_id_token_claims=Some(id_token_claims.clone());}
        if matches!(mode,"claims"|"claims-opaque") {provider.custom_access_token_claims=Some(extension_claims::access_operator::<TestSchema>(live_claims.clone()));}
        if matches!(mode,"claims"|"pairwise") {provider.custom_user_info_claims=Some(user_info_claims.clone());}
        if mode=="claims-opaque" {provider.extensions=extension_claims::extensions_with_live(Some(live_claims.clone()));}
        if mode=="response-fields" {provider.custom_token_response_fields=Some(response_fields.clone());provider.disable_jwt_plugin=true;}
        if mode=="issuance-expiry" {provider=issuance_expiry_config();}
        if mode.starts_with("registration-scopes-") {
            if mode=="registration-scopes-custom-provider" {provider.scopes=vec!["email".into(),"profile".into(),"openid".into(),"email".into(),String::new()];}
            provider.allow_dynamic_client_registration=true;
            provider.allow_unauthenticated_client_registration=true;
            provider.client_registration_default_scopes=match mode {
                "registration-scopes-empty"|"registration-scopes-both-empty"|"registration-scopes-allowed-only"=>Some(vec![]),
                "registration-scopes-default-only"=>Some(vec!["email".into()]),
                "registration-scopes-union"=>Some(vec!["email".into(),"email".into()]),
                _=>None,
            };
            provider.client_registration_allowed_scopes=match mode {
                "registration-scopes-allowed-empty"|"registration-scopes-both-empty"=>Some(vec![]),
                "registration-scopes-allowed-only"=>Some(vec!["profile".into()]),
                "registration-scopes-union"=>Some(vec!["profile".into(),"email".into(),"profile".into()]),
                "registration-scopes-allowed-fallback"=>Some(vec!["email".into()]),
                _=>None,
            };
        }
        if let Some(name)=mode.strip_prefix("scope-"){provider=scope_expiry_config(name);}
        if mode.starts_with("rate-") {provider.rate_limit=rate_limits::policies(mode).0;provider.disable_jwt_plugin=true;}
        let mut client_config=if mode=="uri-host" {config.clone().trusted_origin("https://*")}else{config.clone()};
        if mode=="response-fields" {client_config=client_config.base_path("/__test/profiles/oauth-response-fields/api/auth");}
        if mode=="pairwise" {
            client_config.advanced.database.generate_id=Some(alibi::config::DatabaseIdStrategy::Custom(Arc::new(|model:&str,_size:Option<usize>|Ok(Some(if model=="user" {"pairwise-owner".into()} else {uuid::Uuid::new_v4().to_string()})))));
        }
        let builder = AuthBuilder::<TestSchema>::new(client_config.clone())
            .store(crate::backend::store::<TestSchema>(client_config, database.clone()))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(alibi::plugins::SessionManagementPlugin::new());
        let builder=if matches!(mode,"interaction"|"redirect-policy"|"request-uri") || mode.starts_with("signup-") || mode.starts_with("token-") || mode.starts_with("registration-"){builder.rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))}else{builder};
        let builder=if mode.starts_with("rate-") {builder.rate_limit(rate_limits::policies(mode).1)} else {builder};
        let builder = if matches!(mode,"encrypted-generator"|"encrypted-prefixed-generator"|"custom-encrypted-prefixed") {builder} else {builder.plugin(if mode=="resource-keyring"{JwtPlugin::with_config(JwtPluginConfig{additional_key_pairs:vec![alibi::plugins::jwt::JwtKeyPairConfig{algorithm:alibi::plugins::jwt::JwtAlgorithm::Es256,modulus_length:None}],..Default::default()})}else{JwtPlugin::with_config(JwtPluginConfig{disable_setting_jwt_header:matches!(mode,"interaction"|"redirect-policy"|"request-uri") || mode.starts_with("signup-"),..Default::default()})})};
        let provider=if matches!(mode,"remote-jwks"|"remote-jwks-peer"){remote_provider.clone()}else if matches!(mode,"trusted"|"trusted-peer"){trusted_provider.clone()}else{OAuthProviderPlugin::with_config(provider)};
        let auth = Arc::new(builder.plugin(provider).build().await?);
        client_instances.insert(mode.to_owned(), auth);
    }
    let dpop_memory=Arc::new(alibi::plugins::oauth2::create_in_memory_dpop_replay_store());
    let validation_config=config.clone();
    let logout_database = database.clone();
    let logout_origin = config.base_url.clone();
    let authorization_path = format!("{}/oauth2/authorize", config.base_path);
    let admin_path = format!("{}/admin/oauth2/create-client", config.base_path);
    let response_fields_auth=client_instances.get("response-fields").unwrap().clone();
    let response_fields_routes=response_fields_auth.clone().axum_router().with_state(response_fields_auth);
    Ok(Router::new().nest("/__test/profiles/oauth-response-fields/api/auth",response_fields_routes).route("/__test/server-api/oauth-provider-clients",axum::routing::post(move |axum::Json(input):axum::Json<serde_json::Value>| {
        let logout_database=logout_database.clone();
        let live_claims=live_claims.clone();
        let registration_policy=registration_policy.clone();
        let redirect_policy=redirect_policy.clone();
        let signup_policy=signup_policy.clone();
        let credential_generators=credential_generators.clone();
        let refresh_formatter=refresh_formatter.clone();
        let user_info_claims=user_info_claims.clone();
        let id_token_claims=id_token_claims.clone();
        let response_fields=response_fields.clone();
        let request_registry=request_registry.clone();
        let registry_state=registry_state.clone();
        let remote_state=remote_state.clone();
        let trusted_provider=trusted_provider.clone();
        let trusted_config=trusted_config.clone();
        let dpop_memory=dpop_memory.clone();
        let validation_config=validation_config.clone();
        let logout_origin=logout_origin.clone();
        let authorization_path=authorization_path.clone();
        let admin_path=admin_path.clone();
        let auth=client_instances.get(input["mode"].as_str().unwrap_or("default")).unwrap().clone();async move {
            if input["action"]=="registration-scopes-validation" {
                let options=&input["options"];
                let cfg=OAuthProviderConfig{
                    client_registration_default_scopes:options.get("clientRegistrationDefaultScopes").map(|v|serde_json::from_value(v.clone()).unwrap()),
                    client_registration_allowed_scopes:options.get("clientRegistrationAllowedScopes").map(|v|serde_json::from_value(v.clone()).unwrap()),
                    ..Default::default()
                };
                let result=AuthBuilder::<TestSchema>::new(validation_config.clone()).store(crate::backend::store::<TestSchema>(validation_config,logout_database.clone())).plugin(JwtPlugin::new()).plugin(OAuthProviderPlugin::with_config(cfg)).build().await;
                return axum::Json(match result {Ok(_)=>serde_json::json!({"valid":true}),Err(alibi::AuthError::Config(message))=>serde_json::json!({"valid":false,"message":message}),Err(error)=>panic!("unexpected configuration failure: {error}")}).into_response();
            }
            if input["action"]=="registration-state" {
                use alibi::seaorm::sea_orm::{ConnectionTrait as _,DbBackend,Statement};
                let mut counts=serde_json::Map::new();
                for table in ["user","account","session","verification","jwks","oauthClient"] {
                    let row=logout_database.query_one_raw(Statement::from_string(DbBackend::Sqlite,format!("SELECT COUNT(*) AS count FROM \"{table}\""))).await.unwrap().unwrap();
                    counts.insert(table.into(),serde_json::json!(row.try_get::<i64>("","count").unwrap()));
                }
                return axum::Json(serde_json::json!({"calls":*registration_policy.calls.lock().unwrap(),"counts":counts})).into_response();
            }
            if input["action"]=="redirect-policy-calls" {
                return axum::Json(std::mem::take(&mut *redirect_policy.calls.lock().unwrap())).into_response();
            }
            if input["action"]=="refresh-formatter-state" {
                if let Some(mode)=input["encryptMode"].as_str(){*refresh_formatter.encrypt_mode.lock().unwrap()=mode.into();}
                if let Some(mode)=input["decryptMode"].as_str(){*refresh_formatter.decrypt_mode.lock().unwrap()=mode.into();}
                if input["reset"]==true {refresh_formatter.calls.lock().unwrap().clear();}
                return axum::Json(serde_json::json!({"encryptMode":*refresh_formatter.encrypt_mode.lock().unwrap(),"decryptMode":*refresh_formatter.decrypt_mode.lock().unwrap(),"calls":*refresh_formatter.calls.lock().unwrap(),"completed":*refresh_formatter.completed.lock().unwrap()})).into_response();
            }
            if input["action"]=="request-uri-configure" {
                *request_registry.parameters.lock().unwrap()=input["parameters"].clone().into();
                return axum::Json(serde_json::json!({"configured":true})).into_response();
            }
            if input["action"]=="request-uri-calls" {
                return axum::Json(std::mem::take(&mut *request_registry.calls.lock().unwrap())).into_response();
            }
            if input["action"]=="request-uri-redirects" {
                return axum::Json(std::mem::take(&mut *request_registry.redirect_calls.lock().unwrap())).into_response();
            }
            if input["action"]=="signup-policy-calls" {
                return axum::Json(std::mem::take(&mut *signup_policy.calls.lock().unwrap())).into_response();
            }
            if input["action"]=="claims-state" {
                if let Some(value)=input["value"].as_str(){*live_claims.value.lock().unwrap()=value.into();}
                if let Some(value)=input["operator"].as_bool(){*live_claims.operator.lock().unwrap()=value;}
                if let Some(value)=input.get("mutateResource"){*live_claims.mutate_resource.lock().unwrap()=value.as_str().map(str::to_owned);}
                if input["reset"]==true {live_claims.calls.lock().unwrap().clear();live_claims.operator_calls.lock().unwrap().clear();live_claims.operator_contexts.lock().unwrap().clear();}
                return axum::Json(serde_json::json!({"value":*live_claims.value.lock().unwrap(),"calls":*live_claims.calls.lock().unwrap(),"operator":*live_claims.operator.lock().unwrap(),"mutateResource":*live_claims.mutate_resource.lock().unwrap(),"operatorCalls":*live_claims.operator_calls.lock().unwrap()})).into_response();
            }
            if input["action"]=="credential-generator-state" {
                if let Some(mode)=input["accessMode"].as_str(){*credential_generators.access_mode.lock().unwrap()=mode.into();}
                if let Some(mode)=input["refreshMode"].as_str(){*credential_generators.refresh_mode.lock().unwrap()=mode.into();}
                if input["reset"]==true {*credential_generators.access_count.lock().unwrap()=0;*credential_generators.refresh_count.lock().unwrap()=0;credential_generators.calls.lock().unwrap().clear();credential_generators.contexts.lock().unwrap().clear();credential_generators.hash_calls.lock().unwrap().clear();}
                return axum::Json(serde_json::json!({"accessMode":*credential_generators.access_mode.lock().unwrap(),"refreshMode":*credential_generators.refresh_mode.lock().unwrap(),"accessCount":*credential_generators.access_count.lock().unwrap(),"refreshCount":*credential_generators.refresh_count.lock().unwrap(),"calls":*credential_generators.calls.lock().unwrap(),"hashCalls":*credential_generators.hash_calls.lock().unwrap()})).into_response();
            }
            if input["action"]=="response-fields-state" {
                if let Some(value)=input["value"].as_str(){*response_fields.mode.lock().unwrap()=value.into();}
                if input["reset"]==true {response_fields.calls.lock().unwrap().clear();}
                return axum::Json(serde_json::json!({"mode":*response_fields.mode.lock().unwrap(),"calls":*response_fields.calls.lock().unwrap()})).into_response();
            }
            if input["action"]=="userinfo-claims-state" {
                if let Some(value)=input.get("value") {*user_info_claims.value.lock().unwrap()=value.as_str().map(str::to_owned);}
                if input["reset"]==true {
                    user_info_claims.calls.lock().unwrap().clear();
                    user_info_claims.events.lock().unwrap().clear();
                    user_info_claims.contexts.lock().unwrap().clear();
                }
                return axum::Json(serde_json::json!({"value":*user_info_claims.value.lock().unwrap(),"calls":*user_info_claims.calls.lock().unwrap(),"events":*user_info_claims.events.lock().unwrap()})).into_response();
            }
            if input["action"]=="id-claims-state" {
                if let Some(value)=input.get("value") {*id_token_claims.value.lock().unwrap()=value.as_str().map(str::to_owned);}
                if let Some(value)=input["error"].as_str(){*id_token_claims.error.lock().unwrap()=value.into();}
                if input["reset"]==true {id_token_claims.calls.lock().unwrap().clear();}
                return axum::Json(serde_json::json!({"value":*id_token_claims.value.lock().unwrap(),"error":*id_token_claims.error.lock().unwrap(),"calls":*id_token_claims.calls.lock().unwrap()})).into_response();
            }
            if input["action"]=="backchannel-uri" {
                let id=input["clientId"].as_str().unwrap();
                let mut client=auth.store().get_oauth_client(id).await.unwrap().unwrap();
                client.metadata["backchannel_logout_uri"]=input["uri"].clone();
                client.metadata["disabled"]=serde_json::json!(input["disabled"].as_bool().unwrap_or(false));
                auth.store().update_oauth_client_metadata(id,client.metadata,chrono::Utc::now()).await.unwrap();
                return axum::Json(serde_json::json!({"updated":true})).into_response();
            }
            if input["action"]=="extension-auth-validation" {
                let extensions=input["entries"].as_array().unwrap().iter().map(|entry|extension_authentication::extension(entry["method"].as_str().unwrap(),entry.get("types").filter(|value|!value.is_null()).map(|value|serde_json::from_value(value.clone()).unwrap()))).collect();
                let result=AuthBuilder::<TestSchema>::new(validation_config.clone()).store(crate::backend::store::<TestSchema>(validation_config,logout_database.clone())).plugin(JwtPlugin::new()).plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig{extensions,..Default::default()})).build().await;
                return axum::Json(match result {Ok(_)=>serde_json::json!({"valid":true}),Err(alibi::AuthError::Config(message))=>serde_json::json!({"valid":false,"message":message}),Err(error)=>panic!("unexpected configuration failure: {error}")}).into_response();
            }
            if input["action"]=="extension-validation"{
                let extensions=input["keys"].as_array().unwrap().iter().map(|key|Arc::new(alibi::plugins::OAuthProviderExtension{grants:[(key.as_str().unwrap().into(),Arc::new(ExtensionGrant) as Arc<dyn alibi::plugins::OAuthExtensionGrantHandler>)].into_iter().collect(),..Default::default()})).collect();
                let result=AuthBuilder::<TestSchema>::new(validation_config.clone()).store(crate::backend::store::<TestSchema>(validation_config,logout_database.clone())).plugin(JwtPlugin::new()).plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig{extensions,..Default::default()})).build().await;
                return axum::Json(match result{Ok(_)=>serde_json::json!({"valid":true}),Err(alibi::AuthError::Config(message))=>serde_json::json!({"valid":false,"message":message}),Err(error)=>panic!("unexpected setup failure: {error}")}).into_response();
            }
            if input["action"]=="grant-metadata"{return auth.dispatch_endpoint(OAuthProviderPlugin::get_oauth_server_config_endpoint(),alibi::endpoint::EndpointOptions::default()).await.unwrap().into_response().unwrap().into_response();}
            if input["action"]=="dpop-proof"{
                use alibi::plugins::oauth2::*;
                let body=&input["body"];
                if body["operation"]=="row"{
                    use alibi::AuthVerification as _;
                    let row=auth.store().get_verification_by_identifier(&format!("dpop-proof:{}",body["key"].as_str().unwrap())).await.unwrap();
                    return axum::Json(row.map(|row|serde_json::json!({"value":row.value(),"expiresAt":row.expires_at()}))).into_response();
                }
                let database=create_dpop_replay_store(auth.context());
                let capture=DpopReservationCapture{delegate:auth.context(),observed:std::sync::Mutex::new(None)};
                let wrapped=create_dpop_replay_store(&capture);
                let replay:Option<&dyn DpopReplayStore>=match body["replay"].as_str(){Some("memory")=>Some(dpop_memory.as_ref()),Some("database")=>Some(&database),Some("wrapped")=>Some(&wrapped),_=>None};
                if body["operation"]=="payload-jkt"{
                    return axum::Json(match get_dpop_jkt_from_payload(&body["payload"]){Ok(jkt)=>serde_json::json!({"jkt":jkt}),Err(_)=>serde_json::json!({"ordinary_error":true})}).into_response();
                }
                if body["operation"]=="utilities"{
                    let result=(||->Result<serde_json::Value,DpopError>{Ok(serde_json::json!({"authorization":parse_access_token_authorization(body["authorization"].as_str()),"stripped":strip_access_token_authorization_scheme(body["token"].as_str().unwrap()),"confirmation":get_confirmation_jkt(&body["confirmation"]),"normalized":normalize_dpop_htu(body["url"].as_str().unwrap())?,"ath":derive_dpop_ath(body["accessToken"].as_str().unwrap()),"jkt":derive_dpop_jkt(&body["jwk"])?}))})();
                    return axum::Json(result.unwrap_or_else(|_|serde_json::json!({"ordinary_error":true}))).into_response();
                }
                if body["operation"]=="binding"{
                    let authorization:AccessTokenAuthorization=serde_json::from_value(body["authorization"].clone()).unwrap();
                    let mut options=EnforceDpopBindingParams::new(&body["payload"],&authorization,body["method"].as_str().unwrap(),body["url"].as_str().unwrap());
                    options.proof_jwt=body["proofJwt"].as_str();options.replay_store=replay;options.proof_max_age_seconds=body["proofMaxAgeSeconds"].as_f64();options.signing_algorithms=body.get("signingAlgorithms").map(|value|serde_json::from_value(value.clone()).unwrap());
                    return axum::Json(match enforce_dpop_binding(&options).await{Ok(())=>serde_json::json!({"accepted":true}),Err(error)=>if is_dpop_binding_error(&error){serde_json::json!({"error":error.code,"message":error.message})}else{serde_json::json!({"ordinary_error":true})}}).into_response();
                }
                let mut options=VerifyDpopProofOptions::new(body["proofJwt"].as_str().unwrap(),body["method"].as_str().unwrap(),body["url"].as_str().unwrap());
                options.now_seconds=body["nowSeconds"].as_f64();options.proof_max_age_seconds=body["proofMaxAgeSeconds"].as_f64();
                options.access_token=body["accessToken"].as_str();options.expected_jkt=body["expectedJkt"].as_str();options.require_ath=body["requireAth"]==true;options.signing_algorithms=body.get("signingAlgorithms").map(|value|serde_json::from_value(value.clone()).unwrap());options.replay_store=replay;
                return match verify_dpop_proof(&options).await{Ok(proof)=>{let mut value=serde_json::to_value(proof).unwrap();if body["replay"]=="wrapped"{value["reservation"]=serde_json::to_value(capture.observed.lock().unwrap().clone()).unwrap();}axum::Json(value).into_response()},Err(error)=>axum::Json(if is_dpop_proof_error(&error){serde_json::json!({"error":error.code,"message":error.message})}else{serde_json::json!({"ordinary_error":true})}).into_response()};
            }
            if input["action"]=="issue-tokens" {
                let body=&input["body"];let values=&body["params"];let mut config=if let Some(policy)=body["scopePolicy"].as_str(){scope_expiry_config(policy)}else if body["expiryProfile"]==true {issuance_expiry_config()}else{OAuthProviderConfig::default()};
                if body["claimsProfile"]==true {config.extensions=extension_claims::extensions_with_live(None);}
                if body["idClaimsProfile"]==true {config.custom_id_token_claims=Some(id_token_claims.clone());}
                if body["credentialGenerators"]==true {config.opaque_access_token_generator=Some(credential_generators::access(credential_generators.clone()));config.refresh_token_generator=Some(credential_generators::refresh(credential_generators.clone()));config.token_hasher=Some(credential_generators.clone());}
                if body["refreshFormatting"]==true {config.refresh_token_formatter=Some(refresh_formatter.clone());}
                config.opaque_access_token_prefix=body["prefix"]["opaqueAccessToken"].as_str().map(str::to_owned);config.refresh_token_prefix=body["prefix"]["refreshToken"].as_str().map(str::to_owned);
                if body["accessClaimsProfile"]==true {config.custom_access_token_claims=Some(extension_claims::access_operator::<TestSchema>(live_claims.clone()));config.extensions=extension_claims::extensions_with_live(Some(live_claims.clone()));}
                if body["responseFieldsProfile"]==true {config.custom_token_response_fields=Some(response_fields.clone());}
                config.disable_jwt_plugin=body["disableJwtPlugin"]==true;
                config.dpop_proof_max_age_seconds=body["dpop"]["proofMaxAgeSeconds"].as_f64();config.dpop_signing_algorithms=body["dpop"].get("signingAlgorithms").map(|value|serde_json::from_value(value.clone()).unwrap());let provider=OAuthProviderPlugin::with_config(config);
                let client=provider.get_client(auth.context(),body["clientId"].as_str().unwrap()).await.unwrap().unwrap();
                let mut params=alibi::plugins::OAuthTokenIssueParams::new(client,serde_json::from_value(values["scopes"].clone()).unwrap());
                if let Some(id)=body["userId"].as_str(){let user=auth.store().get_user_by_id(id).await.unwrap().unwrap();params.user=Some(auth.context().trusted_user_view(&user));}
                params.session_id=values["sessionId"].as_str().map(str::to_owned);params.reference_id=values["referenceId"].as_str().map(str::to_owned);params.nonce=values["nonce"].as_str().map(str::to_owned);
                params.auth_time=values["authTime"].as_str().map(|v|chrono::DateTime::parse_from_rfc3339(v).unwrap().with_timezone(&chrono::Utc));
                params.resources=values.get("resources").map(|v|serde_json::from_value(v.clone()).unwrap());params.requested_user_info_claims=values.get("requestedUserInfoClaims").map(|v|serde_json::from_value(v.clone()).unwrap());
                if let Some(token)=body["originalRefreshToken"].as_str(){let protected=provider.hash_token(token,"refresh_token").await.unwrap();let mut retained=auth.store().get_oauth_token(alibi::store::OAuthTokenKind::Refresh,&protected).await.unwrap().unwrap();if let Some(token)=body["snapshotToken"].as_str(){retained.token=token.into();}params.refresh_token=Some(retained);}
                params.access_token_claims=values.get("accessTokenClaims").cloned();params.id_token_claims=values.get("idTokenClaims").cloned();params.token_response=values.get("tokenResponse").cloned();params.confirmation=values.get("confirmation").cloned();params.verification_value=values.get("verificationValue").cloned();
                let call=alibi::endpoint::EndpointCall::new(&alibi::endpoint::EndpointDefinition{name:"issueTokensFixture",operation_id:"issueTokensFixture",path:Some("/fixture/issue-tokens".into()),method:alibi::HttpMethod::Post},None,None,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()});
                let result=provider.issue_tokens(auth.context(),&call,body["grantType"].as_str(),&params).await;
                if input["captureError"]==true || input["captureError"]=="failure" {
                    if input["captureError"]=="failure" {return axum::Json(match result {Ok(value)=>serde_json::json!({"result":value}),Err(_)=>serde_json::json!({"failed":true})}).into_response();}
                    return axum::Json(match result {Ok(value)=>serde_json::json!({"result":value}),Err(error)=>match error.error {
                        alibi::AuthError::Api{status,code,message}=>serde_json::json!({"apiError":{"status":status,"code":code,"message":message}}),
                        alibi::AuthError::Internal(message)=>serde_json::json!({"ordinaryError":message}),
                        other=>panic!("unexpected issuance error: {other}"),
                    }}).into_response();
                }
                return match result {
                    Ok(payload)=>axum::Json(payload).into_response(),
                    Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}response.to_response().unwrap().into_response()}
                };
            }
            if input["action"]=="validate-access" {
                let body=&input["body"];let provider=OAuthProviderPlugin::with_config(OAuthProviderConfig{custom_access_token_claims:(body["accessClaimsProfile"]==true).then(||extension_claims::access_operator::<TestSchema>(live_claims.clone())),extensions:if body["accessClaimsProfile"]==true{extension_claims::extensions_with_live(Some(live_claims.clone()))}else{Vec::new()},token_hasher:body["prefix"].is_object().then(||credential_generators.clone() as Arc<dyn alibi::plugins::OAuthTokenHasher>),opaque_access_token_prefix:body["prefix"]["opaqueAccessToken"].as_str().map(str::to_owned),refresh_token_prefix:body["prefix"]["refreshToken"].as_str().map(str::to_owned),..Default::default()});let token=body["token"].as_str().unwrap();let client=body["clientId"].as_str();
                let result=if body["requireActive"]==true{provider.require_active_access_token(auth.context(),token,client).await}else{provider.validate_access_token(auth.context(),token,client).await};
                return match result {Ok(payload)=>axum::Json(payload).into_response(),Err(error)=>{if matches!(&error.error,alibi::AuthError::Internal(_)){return axum::Json(serde_json::json!({"ordinary_error":true})).into_response();}let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
            }
            if input["action"]=="sign-access" {
                let endpoint=alibi::plugins::jwt::JwtPlugin::sign_endpoint(alibi::utils::json::JsValue::from(input["body"].clone()));
                let response=auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions::default()).await.unwrap().into_response().unwrap();
                if input["omitKid"]==true {
                    let keys=auth.store().list_jwks().await.unwrap();let stored=&keys.first().unwrap().private_key;
                    let encrypted:String=serde_json::from_str(stored).unwrap();
                    let private:serde_json::Value=serde_json::from_str(&alibi::plugins::oauth::encryption::decrypt_token(&encrypted,auth.config().current_secret()).unwrap()).unwrap();
                    let token=access_jwt::sign(&private,&input["body"]).unwrap();
                    return axum::Json(serde_json::json!({"token":token})).into_response();
                }
                return response.into_response();
            }
            if input["action"]=="hash-token" {
                let provider=OAuthProviderPlugin::with_config(OAuthProviderConfig{token_hasher:if input["mode"]=="custom-token-hash"{Some(Arc::new(TypedTokenHasher) as Arc<dyn alibi::plugins::OAuthTokenHasher>)}else if input["prefix"].is_object(){Some(credential_generators.clone())}else{None},opaque_access_token_prefix:input["prefix"]["opaqueAccessToken"].as_str().map(str::to_owned),refresh_token_prefix:input["prefix"]["refreshToken"].as_str().map(str::to_owned),..Default::default()});
                return axum::Json(serde_json::json!({"hash":provider.hash_token(input["token"].as_str().unwrap(),input["kind"].as_str().unwrap()).await.unwrap()})).into_response();
            }
            if input["action"]=="authenticate-client" {
                let body=input["body"].clone();
                let mut request=alibi::AuthRequest::new(alibi::HttpMethod::Post,format!("{}/fixture/authenticate-client",auth.config().base_path));
                request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();
                _=request.headers.insert("content-type".into(),"application/json".into());request.body=Some(serde_json::to_vec(&body).unwrap());
                let call=alibi::endpoint::EndpointCall::new(&alibi::endpoint::EndpointDefinition{name:"authenticateClientFixture",operation_id:"authenticateClientFixture",path:Some("/fixture/authenticate-client".into()),method:alibi::HttpMethod::Post},Some(alibi::utils::json::JsValue::from(body.clone())),None,alibi::endpoint::EndpointOptions{headers:Some(request.headers.clone()),request:Some(request),..Default::default()});
                let options=alibi::plugins::OAuthClientAuthenticationOptions{require_credentials:body["requireCredentials"].as_bool().unwrap_or(true),scopes:body.get("requestedScopes").map(|value|serde_json::from_value(value.clone()).unwrap())};
                let provider=OAuthProviderPlugin::with_config(OAuthProviderConfig {extensions:if body["extensionAuth"]==true{extension_authentication::extensions()}else{Vec::new()},..Default::default()});
                return match provider.authenticate_client(auth.context(),&call,body["boundGrant"].as_str(),&options).await {
                    Ok(authenticated)=>axum::Json(serde_json::json!({"clientId":authenticated.client_id,"method":authenticated.method,"confirmation":authenticated.confirmation,"client":{"clientId":authenticated.client.client_id,"clientName":authenticated.client.metadata.get("client_name"),"userId":authenticated.client.user_id}})).into_response(),
                    Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()},
                };
            }
            if input["action"]=="trusted-client" {
                let provider=if input["fresh"]==true{OAuthProviderPlugin::with_config(trusted_config)}else{trusted_provider};
                let mut client=provider.get_client(auth.context(),"trusted-client").await.unwrap();
                if input["rename"]==true {if let Some(client)=client.as_mut(){client.metadata["client_name"]=serde_json::json!("changed return value");}}
                return axum::Json(client.map(|client|serde_json::json!({"name":client.metadata.get("client_name")}))).into_response();
            }
            if input["action"]=="trusted-external-update"||input["action"]=="trusted-external-delete" {
                if input["action"]=="trusted-external-update" {
                    let mut client=auth.context().database.get_oauth_client("trusted-client").await.unwrap().unwrap();client.metadata["client_name"]=serde_json::json!("External update");
                    auth.context().database.update_oauth_client_metadata("trusted-client",client.metadata,chrono::Utc::now()).await.unwrap();
                }else{auth.context().database.delete_oauth_client("trusted-client").await.unwrap();}
                return axum::Json(serde_json::json!({"updated":true})).into_response();
            }
            if input["action"]=="provider-client" {
                let cfg=OAuthProviderConfig{cached_trusted_clients:["registry-client".into()].into(),client_discoveries:if input["discover"]==true{[true,false].into_iter().map(|first|Arc::new(RegistryDiscovery{first,state:registry_state.clone()}) as Arc<dyn alibi::plugins::OAuthClientDiscovery>).collect()}else{Vec::new()},..Default::default()};
                let client=OAuthProviderPlugin::with_config(cfg).get_client(auth.context(),input["clientId"].as_str().unwrap()).await.unwrap();
                return axum::Json(client.map(|client|serde_json::json!({"client_id":client.client_id,"client_name":client.metadata.get("client_name"),"discovery_id":client.metadata.get("client_discovery_id"),"user_id":client.user_id,"client_secret":client.client_secret}))).into_response();
            }
            if input["action"]=="secret-cipher-validation" {
                let result=AuthBuilder::<TestSchema>::new(validation_config.clone()).store(crate::backend::store::<TestSchema>(validation_config,logout_database.clone())).plugin(JwtPlugin::new()).plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig{client_secret_cipher:Some(Arc::new(CustomSecretCipher)),..Default::default()})).build().await;
                return axum::Json(match result {Ok(_)=>serde_json::json!({"valid":true}),Err(alibi::AuthError::Config(message))=>serde_json::json!({"valid":false,"message":message}),Err(error)=>panic!("unexpected configuration failure: {error}")}).into_response();
            }
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
                let identifier=input["protectedToken"].as_str().map(str::to_owned).unwrap_or_else(||base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input["token"].as_str().unwrap().as_bytes())));
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
                return axum::Json(row.map(|row|serde_json::json!({"id":row.id,"clientId":row.client_id,"userId":row.user_id,"clientName":row.metadata.get("client_name"),"redirectUris":row.metadata.get("redirect_uris"),"client_secret":row.client_secret,"referenceId":row.metadata.get("reference_id"),"requirePKCE":row.metadata.get("require_pkce")}))).into_response();
            }
            if input["action"]=="authority-counts" {
                let session=input["sessionId"].as_str().unwrap();
                let access=auth.store().list_oauth_tokens_for_session(alibi::store::OAuthTokenKind::Access,session).await.unwrap();
                let refresh=auth.store().list_oauth_tokens_for_session(alibi::store::OAuthTokenKind::Refresh,session).await.unwrap();
                return axum::Json(serde_json::json!({"access":access.len(),"refresh":refresh.len()})).into_response();
            }
            if input["action"]=="token-row" {
                use base64::Engine as _; use sha2::Digest as _;
                let hashed=input["protectedToken"].as_str().map(str::to_owned).unwrap_or_else(||base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input["token"].as_str().unwrap())));
                let row=auth.store().get_oauth_token(if input["kind"]=="refresh" {alibi::store::OAuthTokenKind::Refresh}else{alibi::store::OAuthTokenKind::Access},&hashed).await.unwrap();
                return axum::Json(row.map(|r|serde_json::json!({"id":r.id,"clientId":r.client_id,"userId":r.user_id,"sessionId":r.session_id,"scopes":r.metadata["scopes"],"createdAt":r.created_at,"expiresAt":r.expires_at,"authorizationCodeId":r.authorization_code_id,"token":r.token,"refreshId":r.metadata.get("refreshId"),"referenceId":r.metadata.get("referenceId"),"confirmation":r.metadata.get("confirmation"),"requestedUserInfoClaims":r.metadata.get("requestedUserInfoClaims"),"authTime":r.metadata.get("authTime"),"resources":r.metadata.get("resources"),"revoked":r.metadata.get("revoked"),"rotatedAt":r.metadata.get("rotatedAt"),"rotationReplayResponse":r.metadata.get("rotationReplayResponse"),"rotationReplayExpiresAt":r.metadata.get("rotationReplayExpiresAt")}))).into_response();
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
            if (input["action"]=="signout" || input["action"]=="revoke-sessions") && input["foreignKeys"]==true {
                use alibi::seaorm::sea_orm::{ConnectionTrait,DbBackend,Statement};
                let prior=logout_database.query_one_raw(Statement::from_string(DbBackend::Sqlite,"PRAGMA foreign_keys")).await.unwrap().unwrap().try_get::<i64>("","foreign_keys").unwrap();
                _=logout_database.execute_unprepared("PRAGMA foreign_keys=ON").await.unwrap();
                let operation=if input["action"]=="revoke-sessions" {"revokeSessions"} else {"signOut"};
                let outcome=auth.dispatch_endpoint(alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("session-management",operation),alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|value|serde_json::from_value(value.clone()).unwrap()),..Default::default()}).await;
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
                let pairs:Vec<(String,String)>=input["query"].as_object().into_iter().flat_map(|query|query.iter()).flat_map(|(name,value)|{
                    let values=value.as_array().cloned().unwrap_or_else(||vec![value.clone()]);
                    values.into_iter().map(move |value|(name.clone(),alibi::utils::json::JsValue::from(value).coerce_string().unwrap()))
                }).collect();
                let mut physical=url::Url::parse(&format!("{}{}",logout_origin,request.path)).unwrap();
                if !pairs.is_empty(){physical.query_pairs_mut().extend_pairs(&pairs);}
                request.set_query_pairs(pairs);
                request=request.with_url(physical);
                request.headers=input.get("headers").map(|value|serde_json::from_value(value.clone()).unwrap()).unwrap_or_default();
                _=request.headers.insert("origin".into(),logout_origin);
                _=request.headers.insert("content-type".into(),input["contentType"].as_str().unwrap_or("application/x-www-form-urlencoded; charset=UTF-8").into());
                if input["method"]=="POST" && input["rawBody"].is_string() {request.body=Some(input["rawBody"].as_str().unwrap().as_bytes().to_vec());}else if input["method"]=="POST" && input["contentType"]=="application/json" {request.body=Some(serde_json::to_vec(&input["body"]).unwrap());}else if input["method"]=="POST"{request.body=Some(url::form_urlencoded::Serializer::new(String::new()).extend_pairs(input["body"].as_object().unwrap().iter().map(|(key,value)|(key.as_str(),value.as_str().unwrap()))).finish().into_bytes());}
                return match auth.handle_request(request).await {
                    Ok(response)=>response.into_response(),
                    Err(error)=>error.to_auth_response().into_response(),
                };
            }
            let (plugin,operation)=if input["action"]=="signout" {("session-management","signOut")}else if input["action"]=="confirm-logical" {("oauth-provider","oauth2EndSessionConfirmation")}else if input["action"]=="end-session" {("oauth-provider","oauth2EndSession")}else if input["action"]=="userinfo" {("oauth-provider","oauth2UserInfo")}else if input["action"]=="jwks" {("jwt","getJwks")}else if input["action"]=="revoke" {("oauth-provider","oauth2Revoke")}else if input["action"]=="introspect" {("oauth-provider","oauth2Introspect")}else if input["action"]=="token" {("oauth-provider","oauth2Token")}else if input["action"]=="signup" {("email-password","signUpEmail")}else if input["action"]=="signin" {("email-password","signInEmail")}else if input["action"]=="session" {("session-management","getSession")}else if input["action"]=="authorize" {("oauth-provider","oauth2Authorize")}else if input["action"]=="resource-unlink" {("oauth-provider","adminUnlinkClientResource")}else if input["action"]=="resource-link" {("oauth-provider","adminLinkClientResource")}else if input["action"]=="resource-delete" {("oauth-provider","adminDeleteOAuthResource")}else if input["action"]=="resource-update" {("oauth-provider","adminUpdateOAuthResource")}else if input["action"]=="resource-get" {("oauth-provider","adminGetOAuthResource")}else if input["action"]=="resource-list" {("oauth-provider","adminListOAuthResources")}else if input["action"]=="resource-create" {("oauth-provider","adminCreateOAuthResource")}else if input["action"]=="consent-delete" {("oauth-provider","deleteOAuthConsent")}else if input["action"]=="consent-update" {("oauth-provider","updateOAuthConsent")}else if input["action"]=="consent-get" {("oauth-provider","getOAuthConsent")}else if input["action"]=="consents" {("oauth-provider","getOAuthConsents")}else if input["action"]=="continue" {("oauth-provider","oauth2Continue")}else if input["action"]=="consent" {("oauth-provider","oauth2Consent")}else if input["action"]=="prelogin" {("oauth-provider","getOAuthClientPublicPrelogin")}else if input["action"]=="admin-update" {("oauth-provider","adminUpdateOAuthClient")}else if input["action"]=="admin-create" {("oauth-provider","adminCreateOAuthClient")}else if input["action"]=="register" {("oauth-provider","registerOAuthClient")}else if input["action"]=="update" {("oauth-provider","updateOAuthClient")}else if input["action"]=="rotate" {("oauth-provider","rotateClientSecret")}else if input["action"]=="delete" {("oauth-provider","deleteOAuthClient")}else if input["action"]=="list" {("oauth-provider","getOAuthClients")}else if input["action"]=="public" {("oauth-provider","getOAuthClientPublic")}else if input["action"]=="get" {("oauth-provider","getOAuthClient")}else{("oauth-provider","createOAuthClient")};
            let endpoint=if input["action"]=="signout" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation)}else if input["action"]=="confirm-logical" {alibi::plugins::OAuthProviderPlugin::oauth2_end_session_confirmation_endpoint().unwrap()}else if input["action"]=="userinfo" {let endpoint=alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation);if let Some(body)=input.get("body"){endpoint.with_body(body).unwrap()}else{endpoint}}else if input["action"]=="resource-update" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_params(&input["params"]).unwrap().with_body(&input["body"]).unwrap()}else if input["action"]=="resource-get" || input["action"]=="resource-delete" || input["action"]=="resource-link" || input["action"]=="resource-unlink" {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_params(&input["params"]).unwrap()}else if input["action"]=="consent-get" || input["action"]=="get" || input["action"]=="public" || (input["action"]=="authorize" || input["action"]=="end-session") {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_query(&input["query"]).unwrap()} else {alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(plugin,operation).with_body(&input["body"]).unwrap()};
            match auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),request:if input["action"]=="signin" && input["attachRequest"]==true {let mut request=alibi::AuthRequest::new(alibi::HttpMethod::Post,authorization_path.replace("/oauth2/authorize","/sign-in/email"));request.headers=input.get("headers").map(|value|serde_json::from_value(value.clone()).unwrap()).unwrap_or_default();Some(request)}else if (input["action"]=="userinfo" || input["action"]=="revoke" || input["action"]=="introspect" || input["action"]=="token" || input["action"]=="authorize" || input["action"]=="consent" || input["action"]=="continue") && input["attachRequest"]!=false {let mut request=alibi::AuthRequest::new(if (input["action"]=="userinfo" && input["method"]=="POST") || input["action"]=="revoke" || input["action"]=="introspect" || input["action"]=="token" || input["action"]=="consent" || input["action"]=="continue" {alibi::HttpMethod::Post}else{alibi::HttpMethod::Get},if input["action"]=="userinfo"{authorization_path.replace("authorize","userinfo")}else if input["action"]=="revoke"{authorization_path.replace("authorize","revoke")}else if input["action"]=="introspect"{authorization_path.replace("authorize","introspect")}else if input["action"]=="token"{authorization_path.replace("authorize","token")}else if input["action"]=="continue"{authorization_path.replace("authorize","continue")}else if input["action"]=="consent"{authorization_path.replace("authorize","consent")}else{authorization_path});request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();
                if matches!(input["action"].as_str(),Some("revoke"|"introspect"|"token")) {
                    let pairs:Vec<(String,String)>=if let Some(entries)=input["formEntries"].as_array() {entries.iter().map(|pair|(pair[0].as_str().unwrap().into(),pair[1].as_str().unwrap().into())).collect()} else {input["body"].as_object().into_iter().flat_map(|body|body.iter()).map(|(key,value)|(key.clone(),alibi::utils::json::JsValue::from(value.clone()).coerce_string().unwrap())).collect()};
                    request.body=Some(url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish().into_bytes());
                    _=request.headers.insert("content-type".into(),"application/x-www-form-urlencoded".into());
                }
                if input["action"]=="authorize" {let url=url::Url::parse(&format!("{logout_origin}{}",request.path)).unwrap();request=request.with_url(url);}
                Some(request)}else{None},..Default::default()}).await {
                Ok(output)=>output.into_response().unwrap().into_response(),
                Err(error)=>{if input["captureError"]==true {if let alibi::AuthError::Internal(message)=&error.error {return axum::Json(serde_json::json!({"ordinaryError":message})).into_response();}}let mut response=if error.body_absent{alibi::AuthResponse::new(error.error.status_code())}else{error.error.to_auth_response()};if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}
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

struct DpopReservationCapture<'a>{delegate:&'a dyn alibi::plugins::oauth2::DpopReplayReservations,observed:std::sync::Mutex<Option<alibi::plugins::oauth2::DpopVerificationReservation>>}
#[async_trait::async_trait]
impl alibi::plugins::oauth2::DpopReplayReservations for DpopReservationCapture<'_>{
    async fn reserve_verification_value(&self,data:alibi::plugins::oauth2::DpopVerificationReservation)->Result<bool,alibi::plugins::oauth2::DpopError>{
        { *self.observed.lock().unwrap()=Some(data.clone()); }
        self.delegate.reserve_verification_value(data).await
    }
}
fn issuance_expiry_config() -> alibi::plugins::OAuthProviderConfig {
    alibi::plugins::OAuthProviderConfig {access_token_expires_in:120.0,m2m_access_token_expires_in:30.0,id_token_expires_in:600.0,refresh_token_expires_in:900.0,..Default::default()}
}

fn scope_expiry_config(name:&str)->OAuthProviderConfig {
    use alibi::plugins::jwt::JwtExpiration;
    let expiration=match name {
        "numeric"=>JwtExpiration::Numeric(1.0),
        "zero"=>JwtExpiration::Numeric(0.0),
        "date"=>JwtExpiration::At(chrono::DateTime::from_timestamp(0,0).unwrap()),
        "relative"=>JwtExpiration::After(chrono::Duration::seconds(45)),
        _=>JwtExpiration::After(chrono::Duration::hours(2)),
    };
    let mut expirations=HashMap::from([("email".into(),expiration)]);
    if name=="relative"{_=expirations.insert("profile".into(),JwtExpiration::After(chrono::Duration::seconds(90)));}
    OAuthProviderConfig{scope_expirations:expirations,..Default::default()}
}
