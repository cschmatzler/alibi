//! Actual initialized verification service, physical SQL and application cache.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, response::IntoResponse, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp,
};
use better_auth::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, MagicLinkTokenGenerator, SendMagicLink,
};
use better_auth::plugins::one_time_token::{
    GenerateOneTimeToken, OneTimeTokenConfig, OneTimeTokenPlugin, OneTimeTokenSession,
};
use better_auth::plugins::password_management::{PasswordManagementConfig, SendResetPassword};
use better_auth::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    AuthRequest, UpdateVerification,
    store::{CacheAdapter, transaction},
    verification::{
        VerificationCreation, VerificationIdentifierHasher, VerificationIdentifierStrategy,
        VerificationSnapshot,
    },
    wire::{AccountView, VerificationView},
};
use better_auth_seaorm::{
    DatabaseConnection, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set},
    store::entities::{account, session, user, verification},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

const PROFILES: [&str; 9] = [
    "plain",
    "hashed",
    "custom",
    "ordered",
    "numeric",
    "cache",
    "mixed",
    "no-cleanup",
    "limit",
];
fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}
fn error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
fn decoded(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!({"raw":raw}))
}
#[derive(Default)]
struct Application {
    cache: Mutex<BTreeMap<String, (String, DateTime<Utc>)>>,
    events: Mutex<Vec<Value>>,
    cache_events: Mutex<Vec<Value>>,
    deliveries: Mutex<Vec<Value>>,
    action: Mutex<Value>,
    fault: Mutex<Value>,
}
impl Application {
    fn cache_state(&self) -> Value {
        json!(self.cache.lock().unwrap().iter().map(|(key,(value,expiry))|json!({"key":key,"value":decoded(value),"expiresAt":expiry})).collect::<Vec<_>>())
    }
    fn reset(&self) {
        self.cache.lock().unwrap().clear();
        self.events.lock().unwrap().clear();
        self.cache_events.lock().unwrap().clear();
        self.deliveries.lock().unwrap().clear();
        *self.action.lock().unwrap() = json!({});
        *self.fault.lock().unwrap() = json!({});
    }
    async fn receipt(
        &self,
        stage: &str,
        data: Value,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        let rows = if let Some(tx) = context.tx {
            verification::Entity::find()
                .order_by_asc(verification::Column::CreatedAt)
                .all(tx)
                .await
        } else {
            verification::Entity::find()
                .order_by_asc(verification::Column::CreatedAt)
                .all(context.db)
                .await
        }
        .map_err(error)?;
        self.events.lock().unwrap().push(json!({"stage":stage,"data":data,"cache":self.cache_state(),"verifications":rows.iter().map(VerificationView::from).collect::<Vec<_>>()}));
        if self.action.lock().unwrap()[stage] == "throw" {
            return Err(AuthError::internal(format!(
                "verification {stage} rejected"
            )));
        }
        Ok(())
    }
    fn control(&self, stage: &str) -> HookControl {
        if self.action.lock().unwrap()[stage] == "cancel" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        }
    }
}
#[async_trait]
impl CacheAdapter for Application {
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> AuthResult<()> {
        self.cache_events.lock().unwrap().push(
            json!({"operation":"set","key":key,"value":decoded(value),"ttl":ttl.num_seconds()}),
        );
        if self.fault.lock().unwrap()["set"].as_bool() == Some(true) {
            return Err(AuthError::internal("verification cache set rejected"));
        }
        self.cache
            .lock()
            .unwrap()
            .insert(key.into(), (value.into(), Utc::now() + ttl));
        Ok(())
    }
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cache_events
            .lock()
            .unwrap()
            .push(json!({"operation":"get","key":key}));
        let mut cache = self.cache.lock().unwrap();
        if cache
            .get(key)
            .is_some_and(|(_, expiry)| *expiry <= Utc::now())
        {
            cache.remove(key);
        }
        Ok(cache.get(key).map(|(value, _)| value.clone()))
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.cache_events
            .lock()
            .unwrap()
            .push(json!({"operation":"delete","key":key}));
        if self.fault.lock().unwrap()["delete"].as_bool() == Some(true) {
            return Err(AuthError::internal("verification cache delete rejected"));
        }
        self.cache.lock().unwrap().remove(key);
        Ok(())
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<String>> {
        self.cache_events
            .lock()
            .unwrap()
            .push(json!({"operation":"consume","key":key}));
        Ok(self
            .cache
            .lock()
            .unwrap()
            .remove(key)
            .filter(|(_, expiry)| *expiry > Utc::now())
            .map(|(value, _)| value))
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        Ok(self
            .cache
            .lock()
            .unwrap()
            .get(key)
            .is_some_and(|(_, expiry)| *expiry > Utc::now()))
    }
    async fn expire(&self, key: &str, ttl: Duration) -> AuthResult<()> {
        if let Some((_, expiry)) = self.cache.lock().unwrap().get_mut(key) {
            *expiry = Utc::now() + ttl;
        }
        Ok(())
    }
    async fn clear(&self) -> AuthResult<()> {
        self.cache.lock().unwrap().clear();
        Ok(())
    }
}
#[async_trait]
impl VerificationIdentifierHasher for Application {
    async fn hash(&self, identifier: &str) -> AuthResult<String> {
        Ok(format!("custom:{}", hash(identifier)))
    }
}
#[async_trait]
impl SeaOrmHooks<TestSchema> for Application {
    async fn before_create_verification_record(
        &self,
        data: &mut VerificationCreation,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.receipt(
            "create-before",
            serde_json::to_value(data.snapshot().data()).unwrap(),
            context,
        )
        .await?;
        if let Some(mutation) = self.action.lock().unwrap().get("mutation") {
            if let Some(value) = mutation["id"].as_str() {
                data.id = Some(value.into());
            }
            if let Some(value) = mutation["identifier"].as_str() {
                data.identifier = value.into();
            }
            if let Some(value) = mutation["value"].as_str() {
                data.value = value.into();
            }
            for (key, target) in [
                ("createdAt", &mut data.created_at),
                ("updatedAt", &mut data.updated_at),
                ("expiresAt", &mut data.expires_at),
            ] {
                if let Some(value) = mutation[key].as_str() {
                    *target = parse_date(value)?;
                }
            }
        }
        Ok(self.control("create-before"))
    }
    async fn after_create_verification_record(
        &self,
        data: &VerificationSnapshot,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.receipt(
            "create-after",
            serde_json::to_value(data.data()).unwrap(),
            context,
        )
        .await
    }
    async fn before_update_verification(
        &self,
        _id: &str,
        data: &mut UpdateVerification,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let mut value = json!({});
        if let Some(patch) = &data.value {
            value["value"] = json!(patch);
        }
        if let Some(expiry) = data.expires_at {
            value["expiresAt"] = json!(expiry.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        }
        self.receipt("update-before", value, context).await?;
        if let Some(mutation) = self.action.lock().unwrap().get("updateMutation") {
            if let Some(value) = mutation["value"].as_str() {
                data.value = Some(value.into());
            }
            if let Some(value) = mutation["expiresAt"].as_str() {
                data.expires_at = Some(parse_date(value)?);
            }
        }
        Ok(self.control("update-before"))
    }
    async fn after_update_verification_record(
        &self,
        data: Option<&VerificationSnapshot>,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.receipt(
            "update-after",
            data.map_or(Value::Null, |value| {
                serde_json::to_value(value.data()).unwrap()
            }),
            context,
        )
        .await
    }
    async fn before_delete_verification(
        &self,
        data: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.receipt(
            "delete-before",
            json!(VerificationView::from(data)),
            context,
        )
        .await?;
        Ok(self.control("delete-before"))
    }
    async fn after_delete_verification(
        &self,
        data: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.receipt("delete-after", json!(VerificationView::from(data)), context)
            .await
    }
}
#[async_trait]
impl SendEmailOtp for Application {
    async fn send(&self, data: &EmailOtpDelivery) -> AuthResult<()> {
        self.deliveries.lock().unwrap().push(
            json!({"type":"otp","email":data.email,"otp":data.otp,"type":data.otp_type.as_str()}),
        );
        Ok(())
    }
}
#[async_trait]
impl SendMagicLink for Application {
    async fn send(&self, data: &MagicLinkDelivery) -> AuthResult<()> {
        let mut value = serde_json::to_value(data).unwrap();
        value["type"] = json!("magic");
        self.deliveries.lock().unwrap().push(value);
        Ok(())
    }
}
#[async_trait]
impl MagicLinkTokenGenerator for Application {
    async fn generate(&self, email: &str) -> AuthResult<String> {
        Ok(format!("magic-proof:{}", hash(email)))
    }
}
#[async_trait]
impl GenerateOneTimeToken for Application {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        _request: Option<&AuthRequest>,
    ) -> AuthResult<String> {
        Ok(format!(
            "ott-proof:{}",
            hash(session.user.email.as_deref().unwrap_or(&session.user.id))
        ))
    }
}
#[async_trait]
impl SendResetPassword for Application {
    async fn send(&self, user: &Value, url: &str, token: &str) -> AuthResult<()> {
        self.deliveries
            .lock()
            .unwrap()
            .push(json!({"type":"reset","user":user,"url":url,"token":token}));
        Ok(())
    }
}
fn parse_date(value: &str) -> AuthResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| AuthError::bad_request(error.to_string()))
}
fn creation(body: &Value) -> AuthResult<VerificationCreation> {
    let input = &body["data"];
    let now = Utc::now();
    Ok(VerificationCreation {
        id: input["id"].as_str().map(str::to_owned),
        identifier: body["identifier"].as_str().unwrap_or_default().into(),
        value: input["value"].as_str().unwrap_or_default().into(),
        expires_at: input["expiresAt"]
            .as_str()
            .map(parse_date)
            .transpose()?
            .unwrap_or(now + Duration::milliseconds(body["expiresInMs"].as_i64().unwrap_or(60500))),
        created_at: input["createdAt"]
            .as_str()
            .map(parse_date)
            .transpose()?
            .unwrap_or(now),
        updated_at: input["updatedAt"]
            .as_str()
            .map(parse_date)
            .transpose()?
            .unwrap_or(now),
    })
}
async fn sql_state(
    auth: &BetterAuth<TestSchema>,
    database: &DatabaseConnection,
) -> AuthResult<Value> {
    let users = user::Entity::find()
        .order_by_asc(user::Column::CreatedAt)
        .all(database)
        .await
        .map_err(error)?;
    let accounts = account::Entity::find()
        .order_by_asc(account::Column::CreatedAt)
        .all(database)
        .await
        .map_err(error)?;
    let sessions = session::Entity::find()
        .order_by_asc(session::Column::CreatedAt)
        .all(database)
        .await
        .map_err(error)?;
    let verifications = verification::Entity::find()
        .order_by_asc(verification::Column::CreatedAt)
        .all(database)
        .await
        .map_err(error)?;
    let accounts = accounts
        .iter()
        .map(|row| {
            let mut value = serde_json::to_value(AccountView::from(row)).unwrap();
            value["password"] = json!(row.password);
            value
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"users":users.iter().map(|row|auth.context().user_view(row)).collect::<Vec<_>>(),"accounts":accounts,"sessions":sessions.iter().map(|row|auth.context().session_view(row)).collect::<Vec<_>>(),"verifications":verifications.iter().map(VerificationView::from).collect::<Vec<_>>()}),
    )
}
#[derive(Clone)]
pub(super) struct Fixture(Arc<Application>);
impl Fixture {
    pub(super) fn reset(&self) {
        self.0.reset();
    }
}
pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let app = Arc::new(Application::default());
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for mode in PROFILES {
        let name = format!("verification-storage-{mode}");
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if mode == "limit" {
            config.advanced.database.default_find_many_limit = 2;
        }
        config.verification.disable_cleanup = mode == "no-cleanup";
        config.verification.store_in_database = mode == "mixed";
        if ["cache", "mixed"].contains(&mode) {
            config.verification.secondary_storage = Some(app.clone());
        }
        config.verification.store_identifier.default = match mode {
            "plain" | "no-cleanup" | "limit" | "numeric" => VerificationIdentifierStrategy::Plain,
            "custom" => VerificationIdentifierStrategy::Custom(app.clone()),
            _ => VerificationIdentifierStrategy::Hashed,
        };
        if mode == "ordered" {
            config
                .verification
                .store_identifier
                .overrides
                .insert("email-".into(), VerificationIdentifierStrategy::Plain);
            config.verification.store_identifier.overrides.insert(
                "email-verification-".into(),
                VerificationIdentifierStrategy::Hashed,
            );
        }
        if mode == "numeric" {
            config
                .verification
                .store_identifier
                .overrides
                .insert("12".into(), VerificationIdentifierStrategy::Hashed);
            config
                .verification
                .store_identifier
                .overrides
                .insert("1".into(), VerificationIdentifierStrategy::Plain);
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(config, database.clone())
                        .with_hooks(vec![app.clone()]),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(PasswordManagementPlugin::with_config(
                    PasswordManagementConfig {
                        send_reset_password: Some(app.clone()),
                        ..Default::default()
                    },
                ))
                .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                    send_verification_otp: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                    send_magic_link: Some(app.clone()),
                    generate_token: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
                    generator: Some(app.clone()),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(name, auth);
    }
    let fixture = Fixture(app.clone());
    let profiles = Arc::new(profiles);
    router = router.route(
        "/__test/server-api/verification-storage",
        post(move |Json(body): Json<Value>| {
            let profiles = profiles.clone();
            let app = app.clone();
            let database = database.clone();
            async move {
                let result: AuthResult<Value> = async {
                    let profile = body["profile"]
                        .as_str()
                        .unwrap_or("verification-storage-plain");
                    let auth = profiles
                        .get(profile)
                        .ok_or_else(|| AuthError::bad_request("unknown profile"))?;
                    let service = auth.context().verifications();
                    let identifier = body["identifier"].as_str().unwrap_or_default();
                    let snapshot = match body["operation"].as_str().unwrap_or_default() {
                        "configure" => {
                            *app.action.lock().unwrap() =
                                body.get("action").cloned().unwrap_or(json!({}));
                            *app.fault.lock().unwrap() =
                                body.get("fault").cloned().unwrap_or(json!({}));
                            app.events.lock().unwrap().clear();
                            app.cache_events.lock().unwrap().clear();
                            app.deliveries.lock().unwrap().clear();
                            return Ok(json!({"status":true}));
                        }
                        "clear-cache" => {
                            app.clear().await?;
                            return Ok(json!({"status":true}));
                        }
                        "state" => {
                            let mut value = sql_state(auth, &database).await?;
                            value["cache"] = app.cache_state();
                            value["events"] = json!(*app.events.lock().unwrap());
                            value["cacheEvents"] = json!(*app.cache_events.lock().unwrap());
                            value["deliveries"] = json!(*app.deliveries.lock().unwrap());
                            return Ok(value);
                        }
                        "create" => service.create(creation(&body)?).await?,
                        "find" => service.find(identifier).await?,
                        "consume" => service.consume(identifier).await?,
                        "delete" => {
                            service.delete(identifier).await?;
                            return Ok(json!({"status":true}));
                        }
                        "update" => {
                            service
                                .update(
                                    identifier,
                                    UpdateVerification {
                                        value: body["data"]["value"].as_str().map(str::to_owned),
                                        expires_at: body["data"]["expiresAt"]
                                            .as_str()
                                            .map(parse_date)
                                            .transpose()?,
                                    },
                                )
                                .await?
                        }
                        "reserve" => {
                            return Ok(json!(service.reserve(creation(&body)?.data()).await?));
                        }
                        "cache-seed" => {
                            app.cache.lock().unwrap().insert(
                                body["key"].as_str().unwrap_or_default().into(),
                                (
                                    body["value"].as_str().unwrap_or_default().into(),
                                    Utc::now() + Duration::milliseconds(60500),
                                ),
                            );
                            return Ok(json!({"status":true}));
                        }
                        "seed" => {
                            let data = creation(&body)?;
                            let model = verification::ActiveModel {
                                id: Set(data.id.unwrap_or_else(|| {
                                    better_auth_core::utils::id::generate_id(32)
                                })),
                                identifier: Set(data.identifier),
                                value: Set(data.value),
                                expires_at: Set(data.expires_at),
                                created_at: Set(data.created_at),
                                updated_at: Set(data.updated_at),
                            }
                            .insert(&database)
                            .await
                            .map_err(error)?;
                            Some(VerificationSnapshot::from_model(&model))
                        }
                        "transaction" => {
                            let auth = auth.clone();
                            let store = auth.store().clone();
                            let candidate = creation(&body)?;
                            let rollback = body["rollback"].as_bool() == Some(true);
                            transaction(store.as_ref(), move |tx| {
                                Box::pin(async move {
                                    let result = auth
                                        .context()
                                        .verifications()
                                        .create_in_transaction(tx, candidate)
                                        .await?;
                                    if rollback {
                                        return Err(AuthError::internal(
                                            "verification transaction rejected",
                                        ));
                                    }
                                    Ok(result)
                                })
                            })
                            .await?
                        }
                        _ => return Err(AuthError::bad_request("unknown fixture operation")),
                    };
                    Ok(snapshot.map_or(Value::Null, |value| {
                        serde_json::to_value(value.data()).unwrap()
                    }))
                }
                .await;
                let mut response = match result {
                    Ok(value) => Json(value).into_response(),
                    Err(error) => {
                        let message = match &error {
                            AuthError::Internal(message) => message.clone(),
                            _ => error.to_string(),
                        };
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"message":message})),
                        )
                            .into_response()
                    }
                };
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json;charset=utf-8"),
                );
                response
            }
        }),
    );
    Ok((router, fixture))
}
