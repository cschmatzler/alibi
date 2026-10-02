//! Actual application columns, adapter callbacks and retained output observers.
use crate::additional_field_models::{
    ApplicationSchema, application_account, application_session, application_user,
};
use axum::{Json, Router, extract::Query, routing::get};
use better_auth::field_policy::{FieldConfig, FieldConfigs};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, OpenApiPlugin, PasswordManagementPlugin,
    SessionManagementPlugin, UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthAccount, AuthInitContext, AuthPlugin, AuthRoute, AuthSession, AuthUser,
    store::{AdapterAfterHook, AdapterEvent, AuthStore},
    utils::json::JsValue,
};
use better_auth_seaorm::SeaOrmStore;
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, EntityTrait, Schema,
};
use better_auth_seaorm::store::entities::verification;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;
#[derive(Clone)]
struct Application {
    mode: &'static str,
    database: DatabaseConnection,
    events: Events,
}
#[derive(Clone)]
pub(super) struct Fixture {
    applications: Vec<Application>,
}
impl Fixture {
    pub(super) async fn reset(&self) -> AuthResult<()> {
        for application in &self.applications {
            let database = &application.database;
            application_session::Entity::delete_many()
                .exec(database)
                .await
                .map_err(db_error)?;
            application_account::Entity::delete_many()
                .exec(database)
                .await
                .map_err(db_error)?;
            verification::Entity::delete_many()
                .exec(database)
                .await
                .map_err(db_error)?;
            application_user::Entity::delete_many()
                .exec(database)
                .await
                .map_err(db_error)?;
            application
                .events
                .lock()
                .expect("application receipts")
                .clear();
        }
        Ok(())
    }
}
fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
fn fields(entity: &'static str, mode: &'static str, events: &Events) -> FieldConfigs {
    let output = matches!(mode, "output" | "cached");
    let mut fields = FieldConfigs::new();
    for name in ["label", "hidden", "omitted"] {
        let mut field = FieldConfig::new(json!({"type":"string"}));
        if name != "omitted" {
            field = field.default_value(json!(format!(
                "{entity}-{}",
                if name == "label" { "initial" } else { "secret" }
            )));
        } else if output {
            field = field.default_value(json!("drop"));
        }
        if name == "hidden" {
            field = field.hidden();
        }
        if entity == "user" && name == "label" {
            field = field.field_name("user_label");
        }
        if output {
            let events = events.clone();
            field = field.transform_output(move |value| {
                let events = events.clone();
                async move {
                    let value = value.map(|value| value.to_json_value()).transpose()?;
                    events
                        .lock()
                        .expect("application receipts")
                        .push(json!({"phase":"output","entity":entity,"field":name,"value":value}));
                    tokio::task::yield_now().await;
                    if entity == "user"
                        && name == "label"
                        && value.as_ref().and_then(Value::as_str) == Some("throw")
                    {
                        return Err(AuthError::internal("application output failed"));
                    }
                    Ok(match name {
                        "hidden" => Some(JsValue::from(json!(
                            value
                                .as_ref()
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_uppercase()
                        ))),
                        "omitted" => None,
                        _ => Some(JsValue::from(json!({"stored":value}))),
                    })
                }
            });
        }
        if mode == "plugin" && name == "label" {
            let events = events.clone();
            field = field.transform_output(move |value| {
                let events = events.clone();
                async move {
                    let value = value.map(|value| value.to_json_value()).transpose()?;
                    events.lock().expect("application receipts").push(json!({"phase":"configured-output","entity":entity,"field":"label","value":value}));
                    Ok(Some(JsValue::from(json!({"configured":value}))))
                }
            });
        }
        drop(fields.insert(name.into(), field));
    }
    if entity == "user" {
        let mut readonly = FieldConfig::new(json!({"type":"string"}));
        if mode == "policy" {
            readonly = readonly.read_only();
        }
        if output {
            let events = events.clone();
            readonly = readonly
                .read_only()
                .default_value(json!("initial"))
                .on_update(|| JsValue::from(json!("updated")))
                .transform(move |value| {
                    let value = value.map(JsValue::to_json_value).transpose()?;
                    events.lock().expect("application receipts").push(
                        json!({"phase":"input","entity":entity,"field":"readonly","value":value}),
                    );
                    Ok(Some(JsValue::from(json!(format!(
                        "{}:bound",
                        value.as_ref().and_then(Value::as_str).unwrap_or_default()
                    )))))
                });
        }
        drop(fields.insert("readonly".into(), readonly));
    }
    if entity == "user" && matches!(mode, "policy" | "async-validation") {
        let mut label = FieldConfig::new(json!({"type":"string"})).field_name("user_label");
        label.required = mode == "policy";
        let validation_events = events.clone();
        if mode == "async-validation" {
            label = label.validate_async(move |value| {
                validation_events
                    .lock()
                    .expect("application receipts")
                    .push(
                        json!({"phase":"validation","entity":"user","field":"label","value":value}),
                    );
                async move { Ok(value) }
            });
        } else {
            label = label.validate(move |value| {
                validation_events
                    .lock()
                    .expect("application receipts")
                    .push(
                        json!({"phase":"validation","entity":"user","field":"label","value":value}),
                    );
                match value.as_str() {
                    Some(value) if value != "reject" => Ok(JsValue::from(json!(value.trim()))),
                    _ => Err("Label rejected".into()),
                }
            });
            let input_events = events.clone();
            label = label.transform_adapter_input(move |value| {
                input_events
                    .lock()
                    .expect("application receipts")
                    .push(json!({"phase":"input","entity":"user","field":"label","value":value}));
                async move {
                    tokio::task::yield_now().await;
                    if value.as_ref().and_then(JsValue::as_str) == Some("explode") {
                        return Err(AuthError::internal("application input failed"));
                    }
                    Ok(Some(JsValue::from(json!(format!(
                        "bound:{}",
                        value.as_ref().and_then(JsValue::as_str).unwrap_or_default()
                    )))))
                }
            });
        }
        drop(fields.insert("label".into(), label));
        drop(
            fields.insert(
                "hidden".into(),
                FieldConfig::new(json!({"type":"string"}))
                    .hidden()
                    .read_only()
                    .default_value(json!("user-secret")),
            ),
        );
    }
    fields
}
fn plugin_fields(entity: &'static str, application: &Application) -> FieldConfigs {
    if application.mode != "plugin" {
        return FieldConfigs::new();
    }
    let mut fields = FieldConfigs::new();
    drop(
        fields.insert(
            "label".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_value(json!(format!("plugin-{entity}")))
                .hidden(),
        ),
    );
    if entity == "user" {
        let events = application.events.clone();
        drop(fields.insert("role".into(),FieldConfig::new(json!({"type":"string"})).read_only().default_value(json!("plugin-role")).transform_output(move |value| {
            let events = events.clone();
            async move {
                let value = value.map(|value| value.to_json_value()).transpose()?;
                events.lock().expect("application receipts").push(json!({"phase":"plugin-output","entity":"user","field":"role","value":value}));
                Ok(Some(JsValue::from(json!(format!("observed:{}",value.as_ref().and_then(Value::as_str).unwrap_or("undefined"))))))
            }
        })));
    }
    fields
}
#[async_trait::async_trait]
impl AuthPlugin<ApplicationSchema> for Application {
    fn name(&self) -> &'static str {
        "application-adapter-observer"
    }
    fn user_fields(&self) -> FieldConfigs {
        plugin_fields("user", self)
    }
    fn account_fields(&self) -> FieldConfigs {
        plugin_fields("account", self)
    }
    fn session_fields(&self) -> FieldConfigs {
        plugin_fields("session", self)
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<ApplicationSchema>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<ApplicationSchema>,
        response: better_auth_core::AuthResponse,
    ) -> AuthResult<better_auth_core::AuthResponse> {
        if self.mode == "cached" {
            let snapshot = better_auth_core::cache::runtime::published_session_snapshot(request);
            let record = snapshot
                .as_ref()
                .map(|snapshot| json!({"user":snapshot.user(),"session":snapshot.session()}));
            let user_output = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.user_output());
            let session_output = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.session_output());
            self.events.lock().expect("application receipts").push(json!({
                "phase":"completed", "path":request.path(), "record":record,
                "userOmittedPresent":snapshot.as_ref().map(|_| user_output.is_some_and(|output| output.contains_field("omitted"))),
                "userOmittedUndefined":snapshot.as_ref().map(|_| user_output.is_some_and(|output| output.field_is_undefined("omitted"))),
                "sessionOmittedPresent":snapshot.as_ref().map(|_| session_output.is_some_and(|output| output.contains_field("omitted"))),
                "sessionOmittedUndefined":snapshot.as_ref().map(|_| session_output.is_some_and(|output| output.field_is_undefined("omitted")))
            }));
        }
        Ok(response)
    }
    async fn on_init(&self, context: &mut AuthInitContext<ApplicationSchema>) -> AuthResult<()> {
        context.register_adapter_after_hook(Arc::new(self.clone()));
        Ok(())
    }
}
#[async_trait::async_trait]
impl better_auth_core::CookieCacheVersionResolver for Application {
    async fn resolve(&self, context: &better_auth_core::CacheVersionContext) -> AuthResult<String> {
        let user_output = context.user_output();
        let session_output = context.session_output();
        let user = serde_json::to_value(context.user())?;
        let session = serde_json::to_value(context.session())?;
        self.events.lock().expect("application receipts").push(json!({
            "phase":"version", "user":user,"session":session,
            "userOmittedPresent":user_output.is_some_and(|output| output.contains_field("omitted")),
            "userOmittedUndefined":user.get("omitted").is_none(),
            "sessionOmittedPresent":session_output.is_some_and(|output| output.contains_field("omitted")),
            "sessionOmittedUndefined":session.get("omitted").is_none()
        }));
        tokio::task::yield_now().await;
        Ok(format!(
            "fields:{}:{}",
            user["label"]["stored"].as_str().unwrap_or_default(),
            session["label"]["stored"].as_str().unwrap_or_default()
        ))
    }
}
#[async_trait::async_trait]
impl AdapterAfterHook<ApplicationSchema> for Application {
    async fn after_write(
        &self,
        event: &AdapterEvent<ApplicationSchema>,
        database: &dyn AuthStore<ApplicationSchema>,
    ) -> AuthResult<()> {
        let (entity, action, owner, record, omitted_present, omitted_undefined) = match event {
            AdapterEvent::UserCreated(record) | AdapterEvent::UserUpdated(record) => (
                "user",
                if matches!(event, AdapterEvent::UserCreated(_)) {
                    "create"
                } else {
                    "update"
                },
                record.id().into_owned(),
                serde_json::to_value(record)?,
                record.raw_snapshot().contains_field("omitted"),
                record.raw_snapshot().field_is_undefined("omitted"),
            ),
            AdapterEvent::SessionCreated(record) | AdapterEvent::SessionUpdated(record) => (
                "session",
                if matches!(event, AdapterEvent::SessionCreated(_)) {
                    "create"
                } else {
                    "update"
                },
                record.user_id().into_owned(),
                serde_json::to_value(record)?,
                record.raw_snapshot().contains_field("omitted"),
                record.raw_snapshot().field_is_undefined("omitted"),
            ),
            AdapterEvent::AccountCreated(record) | AdapterEvent::AccountUpdated(record) => (
                "account",
                if matches!(event, AdapterEvent::AccountCreated(_)) {
                    "create"
                } else {
                    "update"
                },
                record.user_id().into_owned(),
                serde_json::to_value(record)?,
                record.raw_snapshot().contains_field("omitted"),
                record.raw_snapshot().field_is_undefined("omitted"),
            ),
        };
        let users = usize::from(database.get_user_by_id(&owner).await?.is_some());
        let accounts = database.get_user_accounts(&owner).await?.len();
        let sessions = database.get_user_sessions(&owner).await?.len();
        self.events.lock().expect("application receipts").push(json!({"phase":"after","entity":entity,"action":action,"record":record,"omittedPresent":omitted_present,"omittedUndefined":omitted_undefined,"persisted":{"users":users,"accounts":accounts,"sessions":sessions}}));
        Ok(())
    }
}
async fn application(config: &AuthConfig, mode: &'static str) -> AuthResult<(Router, Application)> {
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
    let application = Application {
        mode,
        database: database.clone(),
        events: Events::default(),
    };
    let path = if mode == "normal" {
        "/__test/profiles/additional-fields/api/auth".to_owned()
    } else {
        format!("/__test/profiles/additional-{mode}-fields/api/auth")
    };
    let mut settings = config.clone().base_path(&path);
    settings.user.additional_fields = fields("user", mode, &application.events);
    settings.account.additional_fields = fields("account", mode, &application.events);
    settings.session.additional_fields = fields("session", mode, &application.events);
    if mode == "cached" {
        settings.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
            enabled: true,
            version: Some(better_auth_core::CookieCacheVersion::Resolver(Arc::new(
                application.clone(),
            ))),
            ..Default::default()
        });
    }
    let mut builder = AuthBuilder::<ApplicationSchema>::new(settings.clone())
        .store(SeaOrmStore::<ApplicationSchema>::new(settings, database))
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(UserManagementPlugin::new())
        .plugin(OpenApiPlugin::new());
    if mode != "normal" {
        builder = builder.plugin(application.clone());
    }
    let auth = Arc::new(builder.build().await?);
    Ok((
        Router::new().nest(&path, auth.clone().axum_router().with_state(auth)),
        application,
    ))
}
#[derive(Deserialize)]
struct StateQuery {
    profile: Option<String>,
}
impl Application {
    async fn state(&self) -> AuthResult<Value> {
        let users = application_user::Entity::find()
            .all(&self.database)
            .await
            .map_err(db_error)?;
        let sessions = application_session::Entity::find()
            .all(&self.database)
            .await
            .map_err(db_error)?;
        let accounts = application_account::Entity::find()
            .all(&self.database)
            .await
            .map_err(db_error)?;
        let verifications = verification::Entity::find()
            .all(&self.database)
            .await
            .map_err(db_error)?;
        let events = self.events.lock().expect("application receipts").clone();
        Ok(
            json!({"users":users,"sessions":sessions,"accounts":accounts,"verifications":verifications,"events":events}),
        )
    }
}
pub(super) async fn router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
    let mut router = Router::new();
    let mut applications = Vec::new();
    let mut states = std::collections::HashMap::new();
    for mode in [
        "normal",
        "output",
        "policy",
        "async-validation",
        "cached",
        "plugin",
    ] {
        let (application_router, application) = application(config, mode).await?;
        router = router.merge(application_router);
        drop(states.insert(mode, application.clone()));
        applications.push(application);
    }
    let router = router.route(
        "/__test/additional-fields/state",
        get(move |Query(query): Query<StateQuery>| {
            let application = states
                .get(query.profile.as_deref().unwrap_or("normal"))
                .cloned();
            async move {
                let Some(application) = application else {
                    return Ok::<_, AuthError>((
                        axum::http::StatusCode::NOT_FOUND,
                        Json(json!({"message":"Unknown application"})),
                    ));
                };
                Ok((axum::http::StatusCode::OK, Json(application.state().await?)))
            }
        }),
    );
    Ok((router, Fixture { applications }))
}
