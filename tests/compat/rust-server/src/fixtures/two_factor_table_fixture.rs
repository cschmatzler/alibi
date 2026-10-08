//! Observe native default storage when table/field mapping is unsupported.
use crate::TestSchema;
use alibi::{
    AuthBuilder, AuthConfig, AuthResult,
    integrations::axum::AxumIntegration,
    plugins::{
        EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
        two_factor::{SendTwoFactorOtp, TwoFactorConfig},
    },
    wire::UserView,
};
use alibi_seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, Statement},
};
use axum::{Json, Router, extract::Query, routing::get};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Clone, Default)]
struct Delivery(Arc<Mutex<HashMap<String, String>>>);
#[async_trait::async_trait]
impl SendTwoFactorOtp for Delivery {
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
        if let Some(email) = &user.email {
            self.0.lock().unwrap().insert(email.clone(), otp.into());
        }
        Ok(())
    }
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let delivery = Delivery::default();
    let config = base
        .clone()
        .base_path("/__test/profiles/two-factor-custom-table/api/auth");
    // There is no native table/field override. Do not manufacture renamed rows.
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                database.clone(),
            ))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                send_otp: Some(Arc::new(delivery.clone())),
                ..Default::default()
            }))
            .build()
            .await?,
    );
    let routes = auth.clone().axum_router().with_state(auth);
    Ok(Router::new().nest("/__test/profiles/two-factor-custom-table/api/auth",routes).route("/__test/two-factor-custom-table/otp",get(move |Query(query):Query<HashMap<String,String>>|{let delivery=delivery.clone();async move {Json(json!({"otp":delivery.0.lock().unwrap().get(query.get("email").unwrap())}))}})).route("/__test/two-factor-custom-table/state",get(move |Query(query):Query<HashMap<String,String>>|{let database=database.clone();async move {
 let rows=database.query_all_raw(Statement::from_string(database.get_database_backend(),"SELECT name FROM sqlite_master WHERE type='table'")).await.unwrap();
 let tables=rows.iter().map(|row|row.try_get::<String>("","name").unwrap()).collect::<Vec<_>>();
 let custom_exists=tables.iter().any(|name|name=="application_second_factor");
 let physical=if custom_exists {database.query_all_raw(Statement::from_sql_and_values(database.get_database_backend(),"SELECT id,application_owner,application_secret,application_backups FROM application_second_factor WHERE application_owner = ?",[query.get("userId").unwrap().clone().into()])).await.unwrap()}else{Vec::new()};
 let rows=physical.iter().map(|row|json!({"id":row.try_get::<String>("","id").unwrap(),"userId":row.try_get::<String>("","application_owner").unwrap(),"secretPresent":!row.try_get::<String>("","application_secret").unwrap().is_empty(),"backupPresent":!row.try_get::<String>("","application_backups").unwrap().is_empty()})).collect::<Vec<_>>();
 Json(json!({"customTableExists":custom_exists,"defaultTableExists":tables.iter().any(|name|name=="two_factors"),"rows":rows}))
 }})))
}
