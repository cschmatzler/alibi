//! Real application password policy, HTTP range service and physical database evidence.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AdminPlugin, EmailPasswordConfig, EmailPasswordPlugin, PasswordManagementPlugin,
    SessionManagementPlugin,
    email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp},
    haveibeenpwned::{HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient},
    password_management::{PasswordManagementConfig, SendResetPassword, set_password},
    phone_number::{PhoneNumberConfig, PhoneNumberPlugin, PhoneOtpDelivery, SendPhoneOtp},
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    AuthRequest, HttpMethod, PasswordHasher, ScryptHasher,
    wire::{AccountView, VerificationView},
};
use better_auth_seaorm::{
    DatabaseConnection, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, QueryOrder, Set},
    store::entities::{account, session, user, verification},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

struct ServiceResponse {
    body: String,
    status: u16,
    content_type: String,
}
impl Default for ServiceResponse {
    fn default() -> Self {
        Self {
            body: String::new(),
            status: 200,
            content_type: "text/plain".into(),
        }
    }
}
#[derive(Default)]
struct Application {
    service: Mutex<ServiceResponse>,
    events: Mutex<Vec<Value>>,
    receipts: Mutex<Vec<Value>>,
    hash_failure: Mutex<bool>,
}
impl Application {
    fn event(&self, value: Value) {
        self.events.lock().unwrap().push(value);
    }
}
#[async_trait]
impl PasswordHasher for Application {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        self.event(json!({"stage":"hash-enter","password":password}));
        let hash = ScryptHasher.hash(password).await?;
        self.event(json!({"stage":"hash-result","password":password,"hash":hash}));
        if *self.hash_failure.lock().unwrap() {
            return Err(AuthError::Upstream {
                status: 403,
                code: "ORIGINAL_HASH_REJECTED",
                message: "Original password hash rejected",
            });
        }
        Ok(hash)
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        ScryptHasher.verify(hash, password).await
    }
}
#[async_trait]
impl SeaOrmHooks<TestSchema> for Application {
    async fn before_create_user(
        &self,
        user: &mut better_auth_core::CreateUser,
        _context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.event(json!({"stage":"user-create","name":user.name,"email":user.email}));
        Ok(HookControl::Continue)
    }
}
#[async_trait]
impl SendResetPassword for Application {
    async fn send(&self, user: &Value, url: &str, token: &str) -> AuthResult<()> {
        self.event(json!({"stage":"reset-delivery","user":user,"url":url,"token":token}));
        Ok(())
    }
}
#[async_trait]
impl SendEmailOtp for Application {
    async fn send(&self, delivery: &EmailOtpDelivery) -> AuthResult<()> {
        self.event(json!({"stage":"email-otp","email":delivery.email,"otp":delivery.otp,"type":delivery.otp_type.as_str()}));
        Ok(())
    }
}
struct PhoneSender {
    app: Arc<Application>,
    reset: bool,
}
#[async_trait]
impl SendPhoneOtp for PhoneSender {
    async fn send(&self, delivery: &PhoneOtpDelivery) -> AuthResult<()> {
        self.app.event(json!({"stage":if self.reset {"phone-reset-otp"} else {"phone-otp"},"phoneNumber":delivery.phone_number,"code":delivery.code}));
        Ok(())
    }
}
fn database_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}

pub(super) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let app = Arc::new(Application::default());
    let service_app = app.clone();
    let service=Router::new().fallback(move |method:Method,uri:OriginalUri,headers:HeaderMap,body:Bytes| {
        let app=service_app.clone();async move {
            let header=|name:&str|headers.get(name).and_then(|value|value.to_str().ok());
            app.receipts.lock().unwrap().push(json!({"method":method.as_str(),"path":uri.path(),"query":uri.query().map_or(String::new(),|query|format!("?{query}")),
                "headers":{"addPadding":header("add-padding"),"userAgent":header("user-agent"),"authorization":header("authorization"),"cookie":header("cookie")},
                "body":String::from_utf8_lossy(&body)}));
            app.event(json!({"stage":"range"}));
            let service=app.service.lock().unwrap();
            (StatusCode::from_u16(service.status).unwrap(),[("content-type",service.content_type.clone())],service.body.clone()).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let address = listener
        .local_addr()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let _service = tokio::spawn(async move { axum::serve(listener, service).await });
    let client = PwnedPasswordClient::new(
        reqwest::Client::new(),
        url::Url::parse(&format!("http://{address}/range/"))
            .map_err(|error| AuthError::internal(error.to_string()))?,
    );
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for name in [
        "pwned-default",
        "pwned-disabled",
        "pwned-empty",
        "pwned-custom",
        "pwned-message",
        "pwned-empty-message",
        "pwned-no-auto",
        "pwned-virtual",
        "pwned-wildcard",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = base.clone().base_path(&path);
        let callback_app = app.clone();
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(config, database.clone())
                        .with_hooks(vec![app.clone()]),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::with_config(EmailPasswordConfig {
                    auto_sign_in: name != "pwned-no-auto",
                    enable_username: false,
                    password_hasher: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(SessionManagementPlugin::new())
                .plugin(PasswordManagementPlugin::with_config(
                    PasswordManagementConfig {
                        send_reset_password: Some(app.clone()),
                        password_hasher: Some(app.clone()),
                        revoke_sessions_on_password_reset: true,
                        on_password_reset: Some(Arc::new(move |user| {
                            let app = callback_app.clone();
                            Box::pin(async move {
                                app.event(json!({"stage":"password-reset","user":user}));
                                Ok(())
                            })
                        })),
                        ..Default::default()
                    },
                ))
                .plugin(AdminPlugin::new())
                .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                    send_verification_otp: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                    send_otp: Some(Arc::new(PhoneSender {
                        app: app.clone(),
                        reset: false,
                    })),
                    send_password_reset_otp: Some(Arc::new(PhoneSender {
                        app: app.clone(),
                        reset: true,
                    })),
                    ..Default::default()
                }))
                .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
                    enabled: name != "pwned-disabled",
                    paths: match name {
                        "pwned-empty" => Some(vec![]),
                        "pwned-custom" => {
                            Some(vec!["/set-password".into(), "/sign-in/email".into()])
                        }
                        _ => None,
                    },
                    custom_password_compromised_message: match name {
                        "pwned-message" => Some("Application forbids leaked passwords".into()),
                        "pwned-empty-message" => Some(String::new()),
                        _ => None,
                    },
                    client: client.clone(),
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        let _ = profiles.insert(name.to_owned(), auth);
    }
    let profiles = Arc::new(profiles);
    let state_profiles = profiles.clone();
    let state_app = app.clone();
    let state_db = database.clone();
    router=router.route("/__test/compromised-password/state",get(move || {let profiles=state_profiles.clone();let app=state_app.clone();let db=state_db.clone();async move {
        let result:AuthResult<Value>=async {
            let auth=profiles.get("pwned-default").unwrap();
            let users=user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&db).await.map_err(database_error)?;
            let accounts=account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&db).await.map_err(database_error)?;
            let sessions=session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&db).await.map_err(database_error)?;
            let verifications=verification::Entity::find().order_by_asc(verification::Column::CreatedAt).all(&db).await.map_err(database_error)?;
            let accounts=accounts.iter().map(|row| {let mut value=serde_json::to_value(AccountView::from(row)).unwrap();value["password"]=json!(row.password);value}).collect::<Vec<_>>();
            Ok(json!({"users":users.iter().map(|row|auth.context().user_view(row)).collect::<Vec<_>>(),"accounts":accounts,
                "sessions":sessions.iter().map(|row|auth.context().session_view(row)).collect::<Vec<_>>(),"verifications":verifications.iter().map(VerificationView::from).collect::<Vec<_>>(),
                "events":*app.events.lock().unwrap(),"receipts":*app.receipts.lock().unwrap()}))
        }.await;match result {Ok(value)=>Json(value).into_response(),Err(error)=>error.into_response()}
    }}));
    router=router.route("/__test/compromised-password",post(move |headers:HeaderMap,Json(body):Json<Value>| {
        let profiles=profiles.clone();let app=app.clone();let database=database.clone();let client=client.clone();async move {
            let result:AuthResult<Value>=async {
                let operation=body["operation"].as_str().unwrap_or_default();
                if operation=="range" {
                    *app.hash_failure.lock().unwrap()=body["hashFailure"].as_bool().unwrap_or(false);
                    *app.service.lock().unwrap()=ServiceResponse {body:body["body"].as_str().unwrap_or_default().into(),status:body["status"].as_u64().unwrap_or(200) as u16,
                        content_type:body["contentType"].as_str().unwrap_or("text/plain").into()};
                    app.events.lock().unwrap().clear();app.receipts.lock().unwrap().clear();return Ok(json!({"status":true}));
                }
                if operation=="helper" {return Ok(json!({"compromised":client.is_password_compromised(body["password"].as_str().unwrap_or_default()).await?}));}
                let profile=body["profile"].as_str().unwrap_or("pwned-default");
                let auth: &Arc<BetterAuth<TestSchema>>=profiles.get(profile).ok_or_else(||AuthError::bad_request("unknown profile"))?;
                if operation=="clear-password" {
                    let row=account::Entity::find_by_id(body["accountId"].as_str().unwrap_or_default()).one(&database).await.map_err(database_error)?.ok_or_else(||AuthError::bad_request("missing credential"))?;
                    let mut row=row.into_active_model();row.password=Set(None);row.updated_at=Set(chrono::Utc::now());let _row=row.update(&database).await.map_err(database_error)?;
                    return Ok(json!({"status":true}));
                }
                if operation=="set" {
                    let mut request=AuthRequest::new(HttpMethod::Post,"/__test/compromised-password");
                    for (name,value) in &headers {if let Ok(value)=value.to_str() {let _=request.headers.insert(name.as_str().to_owned(),value.to_owned());}}
                    set_password(&request,body["newPassword"].as_str().unwrap_or_default(),auth.context()).await?;return Ok(json!({"status":true}));
                }
                Err(AuthError::bad_request("unknown fixture operation"))
            }.await;
            match result {Ok(value)=>Json(value).into_response(),Err(error)=>error.into_response()}
        }
    }));
    Ok(router)
}
