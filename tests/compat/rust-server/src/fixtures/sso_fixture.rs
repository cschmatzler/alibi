//! Paired SSO controls call real operations and read the durable adapter.
use crate::TestSchema;
use alibi::{AuthBuilder,AuthConfig,AuthResult,Alibi};
use alibi::plugins::{EmailPasswordPlugin,SessionManagementPlugin,SsoPlugin,SsoConfig};
use alibi::seaorm::DatabaseConnection;
use axum::{Router,Json,routing::post,response::IntoResponse};
use std::sync::Arc;
async fn instance(config:&AuthConfig,database:&DatabaseConnection,domain:bool)->AuthResult<Alibi<TestSchema>> {
 AuthBuilder::<TestSchema>::new(config.clone()).store(crate::backend::store::<TestSchema>(config.clone(),database.clone())).plugin(EmailPasswordPlugin::new()).plugin(SessionManagementPlugin::new()).plugin(SsoPlugin::with_config(SsoConfig{domain_verification:domain,..Default::default()})).build().await
}
pub(crate) async fn router(config:&AuthConfig,database:DatabaseConnection)->AuthResult<Router> {
 let config=config.clone();
 let auths=Arc::new(std::collections::HashMap::from([
 ("default",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,false).await?)))),
 ("domain",Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database,true).await?))))]));
 Ok(Router::new().route("/__test/server-api/sso",post(move|Json(input):Json<serde_json::Value>|{
 let mode=if input["mode"]=="domain" {"domain"}else{"default"};let auth=auths.get(mode).unwrap().clone();let config=config.clone();let database=database.clone();async move {
 if input["action"]=="restart"{*auth.lock().await=Arc::new(instance(&config,&database,mode=="domain").await.unwrap());return Json(serde_json::json!({"restarted":true})).into_response();}
 let auth=auth.lock().await.clone();
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
 if input["action"]=="account-row" {
 use alibi::AuthAccount as _;
 let row=auth.store().get_account(input["providerId"].as_str().unwrap(),input["accountId"].as_str().unwrap()).await.unwrap();
 return Json(row.map(|row|serde_json::json!({"id":row.id(),"userId":row.user_id(),"providerId":row.provider_id(),"accountId":row.account_id()}))).into_response();
 }
 let endpoint=if input["action"]=="signup"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("email-password","signUpEmail").with_body(&input["body"]).unwrap()}else if input["action"]=="request-domain"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","requestDomainVerification").with_body(&input["body"]).unwrap()}else if input["action"]=="update"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","updateSSOProvider").with_body(&input["body"]).unwrap()}else if input["action"]=="delete"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","deleteSSOProvider").with_body(&input["body"]).unwrap()}else if input["action"]=="list"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","listSSOProviders")}else if input["action"]=="get"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","getSSOProvider").with_query(&input["query"]).unwrap()}else{SsoPlugin::register_sso_provider_endpoint(&input["body"]).unwrap()};
 let result=auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()}).await;
 match result {
 Ok(output)=>output.into_response().unwrap().into_response(),
 Err(error)=>{if !alibi::endpoint::is_endpoint_api_error(&error.error){return alibi::AuthResponse::new(500).into_response();}let mut response=if error.body_absent{alibi::AuthResponse::new(error.error.status_code())}else{error.error.to_auth_response()};if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}if let Some(headers)=error.headers{for(name,value)in headers.iter(){response.headers.append(name,value);}}response.into_response()}
 }
 }
 })))
}
