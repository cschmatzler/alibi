use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin, SsoPlugin};
use alibi::seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use alibi::utils::json::JsValue;
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthResult};
use axum::{Json, Router, response::IntoResponse, routing::post};
use serde_json::{Value, json};
use std::sync::Arc;
#[path = "../../../../support/sso_date_fields.rs"]
mod application;
async fn instance(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Alibi<crate::TestSchema>> {
    let mut config = config.clone();
    application::configure(&mut config);
    AuthBuilder::new(config.clone())
        .store(crate::backend::store(config, database))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::new())
        .build()
        .await
}
pub(crate) async fn router(base: &AuthConfig) -> AuthResult<Router> {
    let database = alibi::seaorm::sea_orm::Database::connect("sqlite::memory:")
        .await
        .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
    let mut configured = base.clone();
    application::configure(&mut configured);
    let store = crate::backend::store::<crate::TestSchema>(configured, database.clone());
    alibi::store::SchemaMigrator::migrate(&store).await?;
    let auth = Arc::new(tokio::sync::Mutex::new(Arc::new(
        instance(base, database.clone()).await?,
    )));
    let config = base.clone();
    Ok(Router::new().route("/__test/server-api/sso-dates",post(move|Json(input):Json<Value>|{let auth=auth.clone();let config=config.clone();let database=database.clone();async move {
        if input["action"]=="restart" { *auth.lock().await=Arc::new(instance(&config,database).await.unwrap());return Json(json!({"restarted":true})).into_response(); }
        if input["action"]=="physical" {
            let rows=database.query_all_raw(Statement::from_string(database.get_database_backend(),"SELECT application_anniversary FROM ssoProvider")).await.unwrap();
            return Json(rows.iter().map(|row|json!({"application_anniversary":row.try_get::<String>("","application_anniversary").unwrap()})).collect::<Vec<_>>()).into_response();
        }
        let operation=match input["action"].as_str(){Some("signup")=>"signUpEmail",Some("update")=>"updateSSOProvider",Some("get")=>"getSSOProvider",Some("list")=>"listSSOProviders",_=>"registerSSOProvider"};
        let mut endpoint=ServerEndpoint::<Value>::new(if operation=="signUpEmail"{"email-password"}else{"sso"},operation);
        if let Some(body)=input.get("body"){
            let mut body=JsValue::from(body.clone());if input["sdkDate"]==true {if let JsValue::Object(values)=&mut body {let date=chrono::DateTime::parse_from_rfc3339(values["anniversary"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=values.insert("anniversary".into(),JsValue::Date(date));}}
            endpoint=endpoint.with_body_value(body);
        }
        if operation=="getSSOProvider"{endpoint=endpoint.with_query(&json!({"providerId":"date-provider"})).unwrap();}
        let auth=auth.lock().await.clone();let result=auth.dispatch_endpoint(endpoint,EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),..Default::default()}).await;
        match result{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()}
    }})))
}
