//! Actual application columns, adapter callbacks and retained output observers.
use crate::additional_field_models::{
    application_account, application_session, application_user, ApplicationSchema,
};
use crate::backend::entities::verification;
use axum::{
    extract::Query,
    routing::{get, post},
    Json, Router,
};
use better_auth::field_policy::{FieldConfig, FieldConfigs};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink,
};
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, EmailVerificationPlugin, OAuthPlugin,
    OpenApiPlugin, PasswordManagementPlugin, SessionManagementPlugin, UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    store::{AdapterAfterHook, AdapterEvent, AuthStore},
    utils::json::JsValue,
    AuthAccount, AuthInitContext, AuthPlugin, AuthRoute, AuthSession, AuthUser,
};
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};
use better_auth_seaorm::{DatabaseHooks, HookControl};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;
static MAPPER_RECEIPTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
#[derive(Clone)]
struct Application {
    mode: &'static str,
    database: DatabaseConnection,
    events: Events,
    ready: Arc<tokio::sync::Notify>,
    pending: Arc<tokio::sync::Notify>,
    drained: Arc<tokio::sync::Notify>,
}
#[async_trait::async_trait]
impl SendMagicLink for Application {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.events.lock().expect("application delivery").push(json!({
            "phase":"delivery", "delivery":delivery, "metadataPresent":delivery.metadata.is_some()
        }));
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct Fixture {
    applications: Vec<Application>,
}
impl Fixture {
    pub(crate) async fn reset(&self) -> AuthResult<()> {
        MAPPER_RECEIPTS
            .lock()
            .expect("application mapper receipts")
            .clear();
        for application in &self.applications {
            application
                .database
                .execute_unprepared(
                    "DELETE FROM app_session; DELETE FROM app_account; DELETE FROM verifications; DELETE FROM app_user",
                )
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
fn fields(
    entity: &'static str,
    mode: &'static str,
    events: &Events,
    ready: &Arc<tokio::sync::Notify>,
    pending: &Arc<tokio::sync::Notify>,
    drained: &Arc<tokio::sync::Notify>,
) -> FieldConfigs {
    let output = matches!(mode, "output" | "cached" | "provider" | "issuer");
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
        if mode == "normal" && name == "label" {
            let events = events.clone();
            field.required = true;
            field = field.default_callback(move || {
                events
                    .lock()
                    .expect("application receipts")
                    .push(json!({"phase":"default","entity":entity,"field":"label"}));
                JsValue::from(json!(format!("{entity}-initial")))
            });
        }
        if output && name == "label" {
            let events = events.clone();
            field = field.validate_output(move |value| {
                events.lock().expect("application receipts").push(json!({"phase":"output-validation","entity":entity,"field":"label","value":value}));
                Err("Output validation must remain metadata".into())
            });
        }
        if mode == "cached" && entity == "session" && name == "label" {
            let events = events.clone();
            field = field.on_update(move || {
                events
                    .lock()
                    .expect("application receipts")
                    .push(json!({"phase":"on-update","entity":entity,"field":"label"}));
                JsValue::String("session-updated".into())
            });
        }
        if name == "hidden" {
            field = field.hidden();
        }
        if entity == "user" && name == "label" {
            field = field.field_name("user_label");
        }
        if output {
            let ready = ready.clone();
            let pending = pending.clone();
            let drained = drained.clone();
            let events = events.clone();
            field = field.transform_output(move |value| {
                let ready = ready.clone();
                let pending = pending.clone();
                let drained = drained.clone();
                let events = events.clone();
                async move {
                    let value = value.map(|value| value.to_json_value()).transpose()?;
                    events
                        .lock()
                        .expect("application receipts")
                        .push(json!({"phase":"output","entity":entity,"field":name,"value":value}));
                    tokio::task::yield_now().await;
                    if entity == "session" && name == "label" && matches!(value.as_ref().and_then(Value::as_str), Some("collection-slow" | "collection-slower")) {
                        let delay = if value.as_ref().and_then(Value::as_str) == Some("collection-slower") { 400 } else { 200 };
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        let request = better_auth_core::hooks::current_request_hook_context();
                        let mut receipt = json!({"phase":"settled","entity":entity,"field":name,"value":value,"requestScoped":request.as_ref().is_some_and(|context| context.path.ends_with("/change-password"))});
                        if request.as_ref().is_some_and(|context| context.path.ends_with("/list-sessions")) {
                            receipt["requestPath"] = json!(request.as_ref().map(|context| context.path.rsplit("/api/auth").next().unwrap_or(&context.path)));
                        }
                        events.lock().expect("application receipts").push(receipt);
                    }
                    if entity == "session"
                        && name == "label"
                        && value.as_ref().and_then(Value::as_str) == Some("collection-coordinated-slow")
                    {
                        pending.notified().await;
                        let request = better_auth_core::hooks::current_request_hook_context();
                        events.lock().expect("application receipts").push(json!({
                            "phase": "settled", "entity": entity, "field": name, "value": value,
                            "requestScoped": request.as_ref().is_some_and(|context| context.path.ends_with("/change-password")),
                            "requestPath": request.map(|context| context.path),
                        }));
                    }
                    if entity == "session"
                        && name == "omitted"
                        && value.as_ref().and_then(Value::as_str) == Some("collection-coordinated-slow")
                    {
                        drained.notify_one();
                    }
                    if entity == "session"
                        && name == "omitted"
                        && value.as_ref().and_then(Value::as_str) == Some("collection-ready")
                    {
                        ready.notify_one();
                    }
                    if entity == "session"
                        && name == "label"
                        && value.as_ref().and_then(Value::as_str) == Some("collection-coordinated-reject")
                    {
                        ready.notified().await;
                        return Err(AuthError::internal("application output failed"));
                    }
                    if name == "label" && matches!(value.as_ref().and_then(Value::as_str),Some("throw"|"collection-reject")) {
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
    if mode == "provider" && entity == "user" {
        if let Some(hidden) = fields.get_mut("hidden") {
            hidden.input = false;
        }
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
    if entity == "session" && mode == "async-validation" {
        let events = events.clone();
        let label = FieldConfig::new(json!({"type":"string"})).default_value(json!("session-initial")).validate_async(move |value| {
            events.lock().expect("application receipts").push(json!({"phase":"validation","entity":"session","field":"label","value":if matches!(&value,JsValue::Number(number) if *number==0.0) { json!(0) } else { serde_json::to_value(&value).expect("application value") },"negativeZero":matches!(&value,JsValue::Number(number) if *number==0.0 && number.is_sign_negative()),"infinite":matches!(&value,JsValue::Number(number) if !number.is_finite())}));
            async move { Ok(value) }
        });
        drop(fields.insert("label".into(), label));
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
                "userOmittedUndefined":snapshot.as_ref().map(|snapshot| !snapshot.user().extension_fields.contains_key("omitted")),
                "sessionOmittedPresent":snapshot.as_ref().map(|_| session_output.is_some_and(|output| output.contains_field("omitted"))),
                "sessionOmittedUndefined":snapshot.as_ref().map(|snapshot| !snapshot.session().extension_fields.contains_key("omitted"))
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
        if self.mode == "cached"
            && entity == "session"
            && action == "update"
            && record["label"]["stored"] == "after-error"
        {
            return Err(AuthError::internal("application after failed"));
        }
        let users = usize::from(database.get_user_by_id(&owner).await?.is_some());
        let accounts = database.get_user_accounts(&owner).await?.len();
        let sessions = database.get_user_sessions(&owner).await?.len();
        self.events.lock().expect("application receipts").push(json!({"phase":"after","entity":entity,"action":action,"record":record,"omittedPresent":omitted_present,"omittedUndefined":omitted_undefined,"persisted":{"users":users,"accounts":accounts,"sessions":sessions}}));
        Ok(())
    }
}
#[async_trait::async_trait]
impl DatabaseHooks<ApplicationSchema, crate::backend::Backend> for Application {
    async fn after_update_session_missing(
        &self,
        _: &str,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        if self.mode == "cached" {
            self.events
                .lock()
                .expect("application receipts")
                .push(json!({"phase":"after","entity":"session","action":"update","record":null}));
        }
        Ok(())
    }
    async fn before_update_session(
        &self,
        token: &str,
        fields: &mut better_auth::field_policy::FieldValues,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        if self.mode != "cached" {
            return Ok(HookControl::Continue);
        }
        self.events
            .lock()
            .expect("application receipts")
            .push(json!({"phase":"before","entity":"session","fields":fields}));
        let stored = crate::backend::rows::<application_session::Model>(
            &self.database,
            "SELECT * FROM app_session WHERE token = ? LIMIT 1",
            vec![token.to_owned()],
        )
        .await
        .map_err(db_error)?
        .pop();
        let command = fields.get("hidden").and_then(JsValue::as_str).or_else(|| {
            if fields.get("label").is_none() {
                stored.as_ref().and_then(|row| row.hidden.as_deref())
            } else {
                None
            }
        });
        match command {
            Some("cancel") => return Ok(HookControl::Cancel),
            Some("ordinary-error") => return Err(AuthError::internal("application before failed")),
            Some("api-error") => {
                return Err(AuthError::Upstream {
                    status: 403,
                    code: "APP_DENIED",
                    message: "Application denied",
                });
            }
            Some("delete") => {
                self.database
                    .execute_raw(Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        "DELETE FROM app_session WHERE token = ?",
                        [token.into()],
                    ))
                    .await
                    .map_err(db_error)?;
            }
            Some(value @ ("after-error" | "throw")) => {
                let value = value.to_owned();
                drop(fields.insert("label".into(), JsValue::String(value)));
            }
            Some("mutate") => {
                drop(fields.insert("label".into(), JsValue::String("hook-updated".into())));
            }
            _ => {}
        }
        Ok(HookControl::Continue)
    }
}
async fn application(config: &AuthConfig, mode: &'static str) -> AuthResult<(Router, Application)> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(db_error)?;
    for statement in crate::additional_field_models::TABLES {
        database
            .execute_unprepared(statement)
            .await
            .map_err(db_error)?;
    }
    let application = Application {
        mode,
        database: database.clone(),
        events: Events::default(),
        ready: Arc::default(),
        pending: Arc::default(),
        drained: Arc::default(),
    };
    let path = if mode == "normal" {
        "/__test/profiles/additional-fields/api/auth".to_owned()
    } else {
        format!("/__test/profiles/additional-{mode}-fields/api/auth")
    };
    let mut settings = config.clone().base_path(&path);
    settings.account.store_account_cookie = mode == "provider";
    settings.user.additional_fields = fields(
        "user",
        mode,
        &application.events,
        &application.ready,
        &application.pending,
        &application.drained,
    );
    settings.account.additional_fields = fields(
        "account",
        mode,
        &application.events,
        &application.ready,
        &application.pending,
        &application.drained,
    );
    for name in ["password", "accessToken"] {
        drop(
            settings
                .account
                .additional_fields
                .insert(name.into(), FieldConfig::new(json!({"type":"string"}))),
        );
    }
    settings.session.additional_fields = fields(
        "session",
        mode,
        &application.events,
        &application.ready,
        &application.pending,
        &application.drained,
    );
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
        .store(
            crate::backend::store::<ApplicationSchema>(settings, database)
                .hook(application.clone()),
        )
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(
            UserManagementPlugin::new()
                .change_email_enabled(true)
                .delete_user_enabled(true),
        )
        .plugin(EmailVerificationPlugin::new())
        .plugin(if mode == "provider" {
            let mut options = better_auth::plugins::oauth::AtlassianOptions::new(
                "fixture-social-client",
                "fixture-social-secret",
            );
            options.user_info_endpoint = Some(format!("{}/__test/atlassian/me", config.base_url));
            options.map_profile_to_user = Some(|profile| {
                MAPPER_RECEIPTS
                    .lock()
                    .map_err(|error| error.to_string())?
                    .push(profile.clone());
                Ok(better_auth::plugins::oauth::OAuthUserInfo {
                    additional_fields: serde_json::Map::from_iter([
                        ("label".into(), profile["nickname"].clone()),
                        ("hidden".into(), json!("provider-cannot-set-hidden")),
                        ("unknown".into(), json!("provider-unknown")),
                    ]),
                    id: "mapped-public-id-184".into(),
                    email: profile["email"].as_str().unwrap_or_default().into(),
                    name: Some(format!(
                        "Mapped {}",
                        profile["name"].as_str().unwrap_or_default()
                    )),
                    image: profile["picture"].as_str().map(str::to_owned),
                    email_verified: true,
                })
            });
            let mut provider =
                better_auth::plugins::oauth::OAuthProvider::atlassian_with_options(options);
            provider.token_url = format!("{}/__test/atlassian/token", config.base_url);
            provider.override_user_info_on_sign_in = true;
            OAuthPlugin::new().add_provider("atlassian", provider)
        } else {
            OAuthPlugin::new()
        })
        .plugin(OpenApiPlugin::new());
    if mode != "normal" {
        builder = builder.plugin(application.clone());
    }
    if mode == "issuer" {
        builder = builder.plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(Arc::new(application.clone())),
            ..Default::default()
        }));
    }
    let auth = Arc::new(builder.build().await?);
    Ok((
        Router::new().nest(&path, auth.clone().axum_router().with_state(auth)),
        application,
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RewindInput {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    hidden: Option<String>,
    label: Option<String>,
    omitted: Option<String>,
    #[serde(default)]
    release_collection: bool,
}
#[derive(Deserialize)]
struct StateQuery {
    profile: Option<String>,
}
impl Application {
    async fn state(&self) -> AuthResult<Value> {
        let users = crate::backend::rows::<application_user::Model>(
            &self.database,
            "SELECT * FROM app_user",
            vec![],
        )
        .await
        .map_err(db_error)?;
        let sessions = crate::backend::rows::<application_session::Model>(
            &self.database,
            "SELECT * FROM app_session",
            vec![],
        )
        .await
        .map_err(db_error)?;
        let accounts = crate::backend::rows::<application_account::Model>(
            &self.database,
            "SELECT * FROM app_account",
            vec![],
        )
        .await
        .map_err(db_error)?;
        let verifications = crate::backend::rows::<verification::Model>(
            &self.database,
            "SELECT * FROM verifications",
            vec![],
        )
        .await
        .map_err(db_error)?;
        let verifications: Vec<Value> = verifications
            .into_iter()
            .map(|row| {
                json!({
                    "id":row.id,"identifier":row.identifier,"value":row.value,
                    "expiresAt":row.expires_at,"createdAt":row.created_at,"updatedAt":row.updated_at
                })
            })
            .collect();
        let events = self.events.lock().expect("application receipts").clone();
        let mut state = json!({"users":users,"sessions":sessions,"accounts":accounts,"verifications":verifications,"events":events});
        if self.mode == "provider" {
            state["mapperReceipts"] = json!(MAPPER_RECEIPTS
                .lock()
                .expect("application mapper receipts")
                .clone());
        }
        Ok(state)
    }
}
pub(crate) async fn router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
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
        "provider",
        "issuer",
    ] {
        let (application_router, application) = application(config, mode).await?;
        router = router.merge(application_router);
        drop(states.insert(mode, application.clone()));
        applications.push(application);
    }
    let operator_states = states.clone();
    let router = router
        .route(
            "/__test/additional-fields/rewind-session",
            post(
                move |Query(query): Query<StateQuery>, Json(input): Json<RewindInput>| {
                    let application = operator_states
                        .get(query.profile.as_deref().unwrap_or("normal"))
                        .cloned();
                    async move {
                        let application = application
                            .ok_or_else(|| AuthError::bad_request("Unknown application"))?;
                        if let Some(label) = input.label {
                            application
                                .database
                                .execute_raw(Statement::from_sql_and_values(
                                    DbBackend::Sqlite,
                                    "UPDATE app_session SET label = ? WHERE token = ?",
                                    [label.into(), input.token.clone().into()],
                                ))
                                .await
                                .map_err(db_error)?;
                        }
                        if input.release_collection {
                            application.pending.notify_one();
                            application.drained.notified().await;
                        }
                        if let Some(omitted) = input.omitted {
                            application
                                .database
                                .execute_raw(Statement::from_sql_and_values(
                                    DbBackend::Sqlite,
                                    "UPDATE app_session SET omitted = ? WHERE token = ?",
                                    [omitted.into(), input.token.clone().into()],
                                ))
                                .await
                                .map_err(db_error)?;
                        }
                        if let Some(hidden) = input.hidden {
                            application
                                .database
                                .execute_raw(Statement::from_sql_and_values(
                                    DbBackend::Sqlite,
                                    "UPDATE app_session SET hidden = ? WHERE token = ?",
                                    [hidden.into(), input.token.clone().into()],
                                ))
                                .await
                                .map_err(db_error)?;
                        }
                        application
                            .database
                            .execute_raw(Statement::from_sql_and_values(
                                DbBackend::Sqlite,
                                "UPDATE app_session SET expires_at = ? WHERE token = ?",
                                [input.expires_at.into(), input.token.into()],
                            ))
                            .await
                            .map_err(db_error)?;
                        Ok::<_, AuthError>(Json(application.state().await?))
                    }
                },
            ),
        )
        .route(
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
