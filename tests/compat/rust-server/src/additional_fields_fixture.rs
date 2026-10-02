//! Real application entity bindings before user/account field support.
use crate::additional_field_models::{
    ApplicationSchema, application_account, application_session, application_user,
};
use axum::{Json, Router, routing::get};
use better_auth::field_policy::FieldConfig;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, OpenApiPlugin, SessionManagementPlugin,
    UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_seaorm::SeaOrmStore;
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, EntityTrait, Schema,
};
use better_auth_seaorm::store::entities::verification;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct Fixture {
    database: DatabaseConnection,
}
impl Fixture {
    pub(super) async fn reset(&self) -> AuthResult<()> {
        application_session::Entity::delete_many()
            .exec(&self.database)
            .await
            .map_err(db_error)?;
        application_account::Entity::delete_many()
            .exec(&self.database)
            .await
            .map_err(db_error)?;
        verification::Entity::delete_many()
            .exec(&self.database)
            .await
            .map_err(db_error)?;
        application_user::Entity::delete_many()
            .exec(&self.database)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}
fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
pub(super) async fn router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(db_error)?;
    let backend = database.get_database_backend();
    let schema = Schema::new(backend);
    for statement in [
        schema.create_table_from_entity(application_user::Entity),
        schema.create_table_from_entity(application_session::Entity),
        schema.create_table_from_entity(application_account::Entity),
        schema.create_table_from_entity(verification::Entity),
    ] {
        database
            .execute_raw(backend.build(&statement))
            .await
            .map_err(db_error)?;
    }
    let path = "/__test/profiles/additional-fields/api/auth";
    let mut settings = config.clone().base_path(path);
    settings.session.additional_fields.insert(
        "label".into(),
        FieldConfig::new(json!({"type":"string"})).default_value(json!("session-initial")),
    );
    settings.session.additional_fields.insert(
        "hidden".into(),
        FieldConfig::new(json!({"type":"string"}))
            .hidden()
            .default_value(json!("session-secret")),
    );
    let auth = Arc::new(
        AuthBuilder::<ApplicationSchema>::new(settings.clone())
            .store(SeaOrmStore::<ApplicationSchema>::new(
                settings,
                database.clone(),
            ))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(UserManagementPlugin::new())
            .plugin(OpenApiPlugin::new())
            .build()
            .await?,
    );
    let state_database = database.clone();
    let router = Router::new().nest(path, auth.clone().axum_router().with_state(auth))
        .route("/__test/additional-fields/state", get(move || { let database = state_database.clone(); async move {
            let users = application_user::Entity::find().all(&database).await.map_err(db_error)?;
            let sessions = application_session::Entity::find().all(&database).await.map_err(db_error)?;
            let accounts = application_account::Entity::find().all(&database).await.map_err(db_error)?;
            let verifications = verification::Entity::find().all(&database).await.map_err(db_error)?;
            Ok::<_, AuthError>(Json(json!({"users":users,"sessions":sessions,"accounts":accounts,"verifications":verifications})))
        }}));
    Ok((router, Fixture { database }))
}
