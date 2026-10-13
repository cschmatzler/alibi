//! Paired SSO controls call real operations and read the durable adapter.
use crate::TestSchema;
use alibi::{AuthBuilder,AuthConfig,AuthResult,Alibi};
use alibi::plugins::{EmailPasswordPlugin,SessionManagementPlugin,SsoPlugin};
use alibi::seaorm::DatabaseConnection;
use axum::{Router,Json,routing::post,response::IntoResponse};
use std::sync::Arc;
async fn instance(config:&AuthConfig,database:&DatabaseConnection)->AuthResult<Alibi<TestSchema>> {
 AuthBuilder::<TestSchema>::new(config.clone()).store(crate::backend::store::<TestSchema>(config.clone(),database.clone())).plugin(EmailPasswordPlugin::new()).plugin(SessionManagementPlugin::new()).plugin(SsoPlugin::new()).build().await
}
pub(crate) async fn router(config:&AuthConfig,database:DatabaseConnection)->AuthResult<Router> {
 let config=config.clone();
 let auth=Arc::new(tokio::sync::Mutex::new(Arc::new(instance(&config,&database).await?)));
 Ok(Router::new().route("/__test/server-api/sso",post(move|Json(input):Json<serde_json::Value>|{
 let auth=auth.clone();let config=config.clone();let database=database.clone();async move {
 if input["action"]=="restart"{*auth.lock().await=Arc::new(instance(&config,&database).await.unwrap());return Json(serde_json::json!({"restarted":true})).into_response();}
 let auth=auth.lock().await.clone();
 if input["action"]=="row" {
 let row=auth.store().get_sso_provider(input["providerId"].as_str().unwrap()).await.unwrap();
 let mut row=serde_json::to_value(row).unwrap();if let Some(object)=row.as_object_mut(){_=object.remove("domainVerified");}
 return Json(row).into_response();
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
 let endpoint=if input["action"]=="signup"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("email-password","signUpEmail").with_body(&input["body"]).unwrap()}else if input["action"]=="delete"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","deleteSSOProvider").with_body(&input["body"]).unwrap()}else if input["action"]=="list"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","listSSOProviders")}else if input["action"]=="get"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","getSSOProvider").with_query(&input["query"]).unwrap()}else{SsoPlugin::register_sso_provider_endpoint(&input["body"]).unwrap()};
 let result=auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()}).await;
 match result {
 Ok(output)=>output.into_response().unwrap().into_response(),
 Err(error)=>{if !alibi::endpoint::is_endpoint_api_error(&error.error){return alibi::AuthResponse::new(500).into_response();}let mut response=if error.body_absent{alibi::AuthResponse::new(error.error.status_code())}else{error.error.to_auth_response()};if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}if let Some(headers)=error.headers{for(name,value)in headers.iter(){response.headers.append(name,value);}}response.into_response()}
 }
 }
 })))
}
