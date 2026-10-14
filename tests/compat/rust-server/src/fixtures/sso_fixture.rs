//! Paired SSO controls call real operations and read the durable adapter.
use crate::TestSchema;
use alibi::{AuthBuilder,AuthConfig,AuthResult,Alibi};
use alibi::plugins::{EmailPasswordPlugin,SessionManagementPlugin,SsoPlugin,SsoConfig};
use alibi::seaorm::DatabaseConnection;
use axum::{Router,Json,routing::post,response::IntoResponse};
use std::sync::Arc;
#[path="../../../../support/sso_oidc_peer.rs"]mod oidc_peer;
#[path="../../../../support/sso_saml_grant.rs"]mod saml_grant;
#[path="../../../../support/sso_validation_policy.rs"]mod validation_policy;
#[path="../../../../support/sso_configured_providers.rs"]mod configured_providers;
#[path="../../../../support/sso_key_resolver.rs"]mod key_resolver;
#[path="../../../../support/sso_provisioning_policy.rs"]mod provisioning_policy;
#[path="../../../../support/sso_mutation_policy.rs"]mod mutation_policy;
#[path="../../../../support/sso_user_resolution_policy.rs"]mod resolution_policy;
#[path="../../../../support/sso_provider_limit_policy.rs"]mod limit_policy;
async fn instance(config:&AuthConfig,database:&DatabaseConnection,mode:&str,dns:std::net::SocketAddr,policy:&validation_policy::Policy,idp_base:&str,keys:&key_resolver::Policy,provisioning:&provisioning_policy::Policy,mutation:&mutation_policy::Policy,resolution:&resolution_policy::Policy,limits:&limit_policy::Policy)->AuthResult<Alibi<TestSchema>> {
 let mut configured=config.clone();if mode=="domain" {configured.account.account_linking.require_local_email_verified=false;}if mode=="validation" {configured.user_validation=Some(Arc::new(policy.clone()));}let config=configured;
 let store=crate::backend::store::<TestSchema>(config.clone(),database.clone());let store=if mode=="user-resolution" {store.hook(resolution.clone())}else{store};let builder=AuthBuilder::<TestSchema>::new(config.clone()).store(store).plugin(EmailPasswordPlugin::new()).plugin(SessionManagementPlugin::new());let builder=if mode.starts_with("org-") {builder.plugin(alibi::plugins::OrganizationPlugin::new())}else{builder};let builder=if mode.starts_with("org-domain"){builder.plugin(alibi::plugins::OAuthPlugin::new().add_provider("gitlab",alibi::plugins::oauth::OAuthProvider::gitlab_with_issuer("enterprise-client","stored-secret",idp_base)))}else{builder};builder.plugin(SsoPlugin::with_config(SsoConfig{resolve_providers_limit:(mode=="provider-limits").then(||alibi::plugins::SsoProviderLimit(Arc::new(limits.clone()))),resolve_user:(mode=="user-resolution").then(||alibi::plugins::SsoResolver::new::<TestSchema>(Arc::new(resolution.clone()))),guard_provider_mutation:(mode=="mutation-guard").then(||alibi::plugins::SsoMutationGuard::new::<TestSchema>(Arc::new(mutation.clone()))),organization_provisioning:alibi::plugins::SsoOrganizationProvisioning{get_role:matches!(mode,"org-dynamic"|"org-disabled"|"org-invitation").then(||alibi::plugins::SsoRoleResolver(Arc::new(provisioning.clone()))),disabled:matches!(mode,"org-disabled"|"org-domain-disabled"),default_role:if mode=="org-admin"{"admin"}else{"member"}.into()},provision_user:matches!(mode,"provisioning"|"provisioning-every").then(||alibi::plugins::SsoProvisioner(Arc::new(provisioning.clone()))),provision_user_on_every_login:mode=="provisioning-every",resolve_private_key:(matches!(mode,"key-resolver"|"configured-jwt-precedence")).then(||alibi::plugins::SsoKeyResolver(Arc::new(keys.clone()))),default_providers:if mode=="configured-jwt-jwk" {configured_providers::jwt_jwk_provider(idp_base)}else if matches!(mode,"configured-jwt"|"configured-jwt-missing"|"configured-jwt-precedence") {configured_providers::jwt_provider(idp_base,mode!="configured-jwt-missing")}else if mode=="configured" {configured_providers::providers(idp_base)}else if mode=="configured-changed" {configured_providers::changed_providers(idp_base)}else{Vec::new()},disable_implicit_sign_up:mode=="no-signup",trust_email_verified:mode=="trusted-claims",saml_enable_single_logout:matches!(mode,"slo"|"signed-slo"|"signed-request-slo"),saml_want_logout_response_signed:mode=="signed-slo",saml_want_logout_request_signed:mode=="signed-request-slo",redirect_uri:(mode=="shared").then(||"/sso/callback".into()),domain_verification:matches!(mode,"domain"|"configured"|"configured-changed")||mode.starts_with("org-domain"),domain_verification_dns_servers:vec![dns],..Default::default()})).build().await
}
pub(crate) async fn router(config:&AuthConfig,database:DatabaseConnection)->AuthResult<Router> {
 let idp=oidc_peer::start().await;let config=config.clone().trusted_origin(&idp.base);let dns=super::sso_dns_fixture::start().await;
 let policy=validation_policy::Policy::default();let keys=key_resolver::Policy::default();let provisioning=provisioning_policy::Policy::default();let mutation=mutation_policy::Policy::default();let resolution=resolution_policy::Policy::default();let limits=limit_policy::Policy::default();
 let auths=Arc::new(std::collections::HashMap::from([
 ("provider-limits",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"provider-limits",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("user-resolution",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"user-resolution",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("mutation-guard",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"mutation-guard",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("org-domain",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-domain",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("org-domain-disabled",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-domain-disabled",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),

 ("org-dynamic",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-dynamic",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("org-invitation",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-invitation",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),

 ("org-default",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-default",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("org-admin",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-admin",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("org-disabled",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"org-disabled",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),

 ("provisioning",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"provisioning",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("provisioning-every",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"provisioning-every",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),

 ("key-resolver",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"key-resolver",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("configured-jwt-jwk",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"configured-jwt-jwk",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("configured-jwt-precedence",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"configured-jwt-precedence",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("configured-jwt",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"configured-jwt",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("configured-jwt-missing",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"configured-jwt-missing",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("configured-changed",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"configured-changed",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("configured",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"configured",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("no-signup",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"no-signup",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("validation",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"validation",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("trusted-claims",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"trusted-claims",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("default",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"default",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("shared",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"shared",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("signed-request-slo",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"signed-request-slo",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("signed-slo",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"signed-slo",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("slo",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"slo",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?)))),
 ("domain",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,"domain",dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await?))))]));
 Ok(Router::new().route("/__test/server-api/sso",post(move|Json(input):Json<serde_json::Value>|{
 let mode=if input["mode"]=="provider-limits" {"provider-limits"}else if input["mode"]=="user-resolution" {"user-resolution"}else if input["mode"]=="mutation-guard" {"mutation-guard"}else if input["mode"]=="org-domain" {"org-domain"}else if input["mode"]=="org-domain-disabled" {"org-domain-disabled"}else if input["mode"]=="org-dynamic" {"org-dynamic"}else if input["mode"]=="org-invitation" {"org-invitation"}else if input["mode"]=="org-default" {"org-default"}else if input["mode"]=="org-admin" {"org-admin"}else if input["mode"]=="org-disabled" {"org-disabled"}else if input["mode"]=="provisioning" {"provisioning"}else if input["mode"]=="provisioning-every" {"provisioning-every"}else if input["mode"]=="configured-jwt-jwk" {"configured-jwt-jwk"}else if input["mode"]=="configured-jwt-precedence" {"configured-jwt-precedence"}else if input["mode"]=="key-resolver" {"key-resolver"}else if input["mode"]=="configured-jwt" {"configured-jwt"}else if input["mode"]=="configured-jwt-missing" {"configured-jwt-missing"}else if input["mode"]=="configured-changed" {"configured-changed"}else if input["mode"]=="configured" {"configured"}else if input["mode"]=="no-signup" {"no-signup"}else if input["mode"]=="validation" {"validation"}else if input["mode"]=="trusted-claims" {"trusted-claims"}else if input["mode"]=="signed-request-slo" {"signed-request-slo"}else if input["mode"]=="signed-slo" {"signed-slo"}else if input["mode"]=="domain" {"domain"}else if input["mode"]=="shared" {"shared"}else if input["mode"]=="slo" {"slo"}else{"default"};let auth=auths.get(mode).unwrap().clone();let dns=dns.clone();let idp=idp.clone();let config=config.clone();let database=database.clone();let policy=policy.clone();let keys=keys.clone();let provisioning=provisioning.clone();let mutation=mutation.clone();let resolution=resolution.clone();let limits=limits.clone();async move {
 if input["action"]=="restart"{*auth.lock().await=Arc::new(instance(&config,&database,mode,dns.address,&policy,&idp.base,&keys,&provisioning,&mutation,&resolution,&limits).await.unwrap());return Json(serde_json::json!({"restarted":true})).into_response();}
 let auth=auth.lock().await.clone();
 if input["action"]=="limit-policy" {*limits.limit.lock().unwrap()=input["limit"].as_f64().unwrap();limits.events.lock().unwrap().clear();return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="limit-events" {return Json(limits.events.lock().unwrap().clone()).into_response();}
 if input["action"]=="user-exists" {return Json(auth.store().get_user_by_email(input["email"].as_str().unwrap()).await.unwrap().is_some()).into_response();}
 if input["action"]=="resolution-policy" {*resolution.decision.lock().unwrap()=input["decision"].clone();resolution.deny_sessions.store(input["denySessions"].as_bool().unwrap_or(false),std::sync::atomic::Ordering::SeqCst);resolution.fail_after_user.store(input["failAfterUser"].as_bool().unwrap_or(false),std::sync::atomic::Ordering::SeqCst);if input["clear"].as_bool()==Some(true){resolution.events.lock().unwrap().clear();}return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="resolution-events" {return Json(resolution.events.lock().unwrap().clone()).into_response();}
 if input["action"]=="mutation-policy" {mutation.denied.store(input["denied"].as_bool().unwrap_or(false),std::sync::atomic::Ordering::SeqCst);if input["clear"].as_bool()==Some(true){mutation.events.lock().unwrap().clear();}return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="mutation-events" {return Json(mutation.events.lock().unwrap().clone()).into_response();}
 if input["action"]=="role-reset" {provisioning.roles.lock().unwrap().clear();return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="role-events" {return Json(provisioning.roles.lock().unwrap().clone()).into_response();}
 if input["action"]=="member-row" {let row=auth.store().get_member(input["organizationId"].as_str().unwrap(),input["userId"].as_str().unwrap()).await.unwrap();return Json(row.map(|row|serde_json::json!({"id":row.id,"userId":row.user_id,"organizationId":row.organization_id,"role":row.role}))).into_response();}
 if input["action"]=="provisioning-reset" {provisioning.events.lock().unwrap().clear();return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="provisioning-events" {return Json(provisioning.events.lock().unwrap().clone()).into_response();}
 if input["action"]=="key-reset" {keys.events.lock().unwrap().clear();keys.enabled.store(true,std::sync::atomic::Ordering::SeqCst);return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="key-enabled" {keys.enabled.store(input["enabled"].as_bool().unwrap(),std::sync::atomic::Ordering::SeqCst);return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="key-events" {return Json(keys.events.lock().unwrap().clone()).into_response();}
 if input["action"]=="validation-reset" {policy.events.lock().unwrap().clear();policy.deny_returning.store(false,std::sync::atomic::Ordering::SeqCst);return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="validation-deny" {policy.deny_returning.store(input["enabled"].as_bool().unwrap(),std::sync::atomic::Ordering::SeqCst);return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="validation-events" {return Json(policy.events.lock().unwrap().clone()).into_response();}
 if input["action"]=="sign-saml-logout" {return Json(serde_json::json!({"SAMLResponse":saml_grant::signed_logout(input["xml"].as_str().unwrap(),input["wrongKey"].as_bool().unwrap_or(false)).unwrap()})).into_response();}
 if input["action"]=="social-callback-http" {let mut request=alibi::AuthRequest::new(alibi::HttpMethod::Get,"/callback/gitlab");request.headers=serde_json::from_value(input["headers"].clone()).unwrap();request.set_query_pairs(serde_json::from_value::<std::collections::HashMap<String,String>>(input["query"].clone()).unwrap());return auth.handle_request(request).await.unwrap().into_response();}
 if input["action"]=="sign-out-http"{let mut request=alibi::AuthRequest::new(alibi::HttpMethod::Post,"/sign-out");request.headers=serde_json::from_value(input["headers"].clone()).unwrap();request.headers.insert("content-type".into(),"application/json".into());request.body=Some(b"{}".to_vec());return auth.handle_request(request).await.unwrap().into_response();}
 if input["action"]=="acs-http"||input["action"]=="slo-http"{
 let get=input["method"]=="GET";let params=if get{&input["query"]}else{&input["body"]};
 let form=params.as_object().unwrap().iter().map(|(name,value)|(name.as_str(),value.as_str().unwrap())).collect::<Vec<_>>();
 let encoded=url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
 let mut request=alibi::AuthRequest::new(if get{alibi::HttpMethod::Get}else{alibi::HttpMethod::Post},format!("/sso/saml2/sp/{}/{}",if input["action"]=="slo-http"{"slo"}else{"acs"},input["params"]["providerId"].as_str().unwrap()));
 request.headers=input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()).unwrap_or_default();
 if get{request.set_query_pairs(url::form_urlencoded::parse(encoded.as_bytes()).into_owned());}else{request.headers.insert("content-type".into(),"application/x-www-form-urlencoded".into());request.body=Some(encoded.into_bytes());}
 return auth.handle_request(request).await.unwrap().into_response();}

 if input["action"]=="saml-grant" {return Json(if input.get("verified").is_some() {saml_grant::grant_with_verified(input["authorization"].as_str().unwrap(),input["email"].as_str().unwrap(),input["wrongKey"].as_bool().unwrap_or(false),input.get("verified").and_then(|value|value.as_array()).map(|values|values.iter().map(|value|value.as_str().unwrap()).collect::<Vec<_>>()).as_deref())} else {saml_grant::grant(input["authorization"].as_str().unwrap(),input["email"].as_str().unwrap(),input["wrongKey"].as_bool().unwrap_or(false))}.unwrap()).into_response();}
 if input["action"]=="idp" {*idp.profile.lock().unwrap()=input.get("profile").filter(|profile|profile.is_object()).cloned();*idp.discovery_case.lock().unwrap()=input["discoveryCase"].as_str().unwrap_or("valid").into();*idp.id_token_case.lock().unwrap()=input["idTokenCase"].as_str().unwrap_or("none").into();idp.exchanges.lock().unwrap().clear();if let Some(email)=input["email"].as_str(){*idp.email.lock().unwrap()=email.into();}return Json(serde_json::json!({"base":idp.base})).into_response();}
 if input["action"]=="idp-exchanges"{return Json(idp.exchanges.lock().unwrap().clone()).into_response();}

 if input["action"]=="dns-records"{*dns.records.lock().unwrap()=serde_json::from_value(input["records"].clone()).unwrap();return Json(serde_json::json!({"configured":true})).into_response();}
 if input["action"]=="dns-queries"{return Json(dns.queries.lock().unwrap().clone()).into_response();}

 if input["action"]=="user-row" {
 use alibi::AuthUser as _;
 let row=auth.store().get_user_by_email(input["email"].as_str().unwrap()).await.unwrap();
 return Json(row.map(|row|serde_json::json!({"id":row.id(),"email":row.email()}))).into_response();
 }
 if input["action"]=="row" {
 let row=auth.store().get_sso_provider(input["providerId"].as_str().unwrap()).await.unwrap();
 let mut row=serde_json::to_value(row).unwrap();if mode!="domain" {if let Some(object)=row.as_object_mut(){_=object.remove("domainVerified");}}
 return Json(row).into_response();
 }
 if input["action"]=="proof" {
 use alibi::AuthVerification as _;
 let row=auth.store().get_latest_verification_by_identifier(input["identifier"].as_str().unwrap()).await.unwrap();
 return Json(row.map(|row|serde_json::json!({"id":row.id(),"identifier":row.identifier(),"value":row.value(),"expiresAt":row.expires_at()}))).into_response();
 }
 if input["action"]=="expire-proof" {
 auth.store().update_verification_by_identifier(input["identifier"].as_str().unwrap(),alibi::UpdateVerification{expires_at:Some(chrono::Utc::now()-chrono::Duration::seconds(1)),..Default::default()}).await.unwrap();
 return Json(serde_json::json!({"expired":true})).into_response();
 }
 if input["action"]=="delete-fault" {
 use alibi::seaorm::sea_orm::ConnectionTrait;
 database.execute_unprepared(if input["enabled"]==true {"CREATE TRIGGER sso_delete_fault BEFORE DELETE ON \"ssoProvider\" BEGIN SELECT RAISE(ABORT, 'forced provider deletion failure'); END"}else{"DROP TRIGGER sso_delete_fault"}).await.unwrap();
 return Json(serde_json::json!({"enabled":input["enabled"]})).into_response();
 }
 if input["action"]=="create-account" {
 use alibi::AuthAccount as _;
 let body=&input["body"];
 let row=auth.store().create_account(alibi::CreateAccount{additional_fields:Default::default(),user_id:body["userId"].as_str().unwrap().into(),provider_id:body["providerId"].as_str().unwrap().into(),account_id:body["accountId"].as_str().unwrap().into(),access_token:None,refresh_token:None,id_token:None,access_token_expires_at:None,refresh_token_expires_at:None,scope:None,password:None}).await.unwrap();
 return Json(serde_json::json!({"id":row.id(),"userId":row.user_id(),"providerId":row.provider_id(),"accountId":row.account_id()})).into_response();
 }
 if input["action"]=="account-row" || input["action"]=="saml-account-row" || input["action"]=="id-token-account-row" {
 use alibi::AuthAccount as _;
 let row=auth.store().get_account(input["providerId"].as_str().unwrap(),input["accountId"].as_str().unwrap()).await.unwrap();
 return Json(row.map(|row|{let mut output=serde_json::json!({"id":row.id(),"userId":row.user_id(),"providerId":row.provider_id(),"accountId":row.account_id()});if input["action"]=="id-token-account-row" {output["idToken"]=serde_json::json!(row.id_token());}if input["action"]=="saml-account-row" {output["accessToken"]=serde_json::json!(row.access_token());output["refreshToken"]=serde_json::json!(row.refresh_token());}output})).into_response();
 }
 let endpoint=if input["action"]=="sign-out-api"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("session-management","signOut")}else if input["action"]=="social-start"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("oauth","signInSocial").with_body(&input["body"]).unwrap()}else if input["action"]=="social-callback"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("oauth","callbackOAuth").with_params(&serde_json::json!({"id":"gitlab"})).unwrap().with_query(&input["query"]).unwrap()}else if matches!(input["action"].as_str(),Some("org-create"|"org-invite"|"org-role")) {let operation=match input["action"].as_str().unwrap(){"org-create"=>"createOrganization","org-invite"=>"createInvitation",_=>"updateMemberRole"};alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("organization",operation).with_body(&input["body"]).unwrap()}else if input["action"]=="signup"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("email-password","signUpEmail").with_body(&input["body"]).unwrap()}else if input["action"]=="shared-callback"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","callbackSSOShared").with_query(&input["query"]).unwrap()}else if input["action"]=="sp-metadata"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","spMetadata").with_query(&input["query"]).unwrap()}else if input["action"]=="acs"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","acsEndpoint").with_params(&input["params"]).unwrap().with_body(&input["body"]).unwrap()}else if input["action"]=="initiate-slo"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","initiateSLO").with_params(&input["params"]).unwrap().with_body(&input["body"]).unwrap()}else if input["action"]=="slo"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","sloEndpoint").with_params(&input["params"]).unwrap().with_body(&input["body"]).unwrap()}else if input["action"]=="callback"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","callbackSSO").with_params(&input["params"]).unwrap().with_query(&input["query"]).unwrap()}else if input["action"]=="session"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("session-management","getSession")}else if input["action"]=="sign-in"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","signInSSO").with_body(&input["body"]).unwrap()}else if input["action"]=="verify-domain"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","verifyDomain").with_body(&input["body"]).unwrap()}else if input["action"]=="request-domain"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","requestDomainVerification").with_body(&input["body"]).unwrap()}else if input["action"]=="update"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","updateSSOProvider").with_body(&input["body"]).unwrap()}else if input["action"]=="delete"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","deleteSSOProvider").with_body(&input["body"]).unwrap()}else if input["action"]=="list"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","listSSOProviders")}else if input["action"]=="get"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","getSSOProvider").with_query(&input["query"]).unwrap()}else{SsoPlugin::register_sso_provider_endpoint(&input["body"]).unwrap()};
 let result=auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{method:if input["action"]=="slo"{Some(alibi::HttpMethod::Post)}else{None},headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()}).await;
 match result {
 Ok(output)=>output.into_response().unwrap().into_response(),
 Err(error)=>{if !alibi::endpoint::is_endpoint_api_error(&error.error){return alibi::AuthResponse::new(500).into_response();}let mut response=error.error.to_auth_response();if error.body_absent{response.body.clear();}if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}if let Some(headers)=error.headers{for(name,value)in headers.iter(){response.headers.append(name,value);}}response.into_response()}
 }
 }
 })))
}
