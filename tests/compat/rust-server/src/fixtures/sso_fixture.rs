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
 let endpoint=if input["action"]=="signup"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("email-password","signUpEmail").with_body(&input["body"]).unwrap()}else if input["action"]=="get"{alibi::endpoint::ServerEndpoint::<serde_json::Value>::new("sso","getSSOProvider").with_query(&input["query"]).unwrap()}else{SsoPlugin::register_sso_provider_endpoint(&input["body"]).unwrap()};
 let result=auth.dispatch_endpoint(endpoint,alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()}).await;
 match result {
 Ok(output)=>output.into_response().unwrap().into_response(),
 Err(error)=>{let mut response=if error.body_absent{alibi::AuthResponse::new(error.error.status_code())}else{error.error.to_auth_response()};if let Some(body)=error.body{response.body=serde_json::to_vec(&*body).unwrap();}if let Some(headers)=error.headers{for(name,value)in headers.iter(){response.headers.append(name,value);}}response.into_response()}
 }
 }
 })))
}
