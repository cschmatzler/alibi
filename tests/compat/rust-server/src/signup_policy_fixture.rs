//! Actual application policies and scrypt callbacks at the public HTTP boundary.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp,
};
use better_auth::plugins::email_verification::SendVerificationEmail;
use better_auth::plugins::password_management::SendResetPassword;
use better_auth::plugins::{
    EmailPasswordConfig, EmailPasswordPlugin, EmailVerificationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    PasswordHasher, ScryptHasher,
    wire::{AccountView, UserView, VerificationView},
};
use better_auth_seaorm::{
    DatabaseConnection, SeaOrmStore,
    sea_orm::{EntityTrait, QueryOrder},
    store::entities::{account, session, user, verification},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Application {
    mode: Mutex<String>,
    events: Mutex<Vec<Value>>,
}
impl Application {
    fn mode(&self) -> String {
        self.mode.lock().unwrap().clone()
    }
    fn event(&self, value: Value) {
        self.events.lock().unwrap().push(value);
    }
    fn fail(&self, phase: &str) -> AuthResult<()> {
        if self.mode() == format!("{phase}-error") {
            return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                format!("Actual configured {phase} failed"),
            ))));
        }
        if self.mode() == format!("{phase}-api") {
            let (code, message) = match phase {
                "hash" => ("HASH_REJECTED", "Configured hash rejected"),
                "verify" => ("VERIFY_REJECTED", "Configured verifier rejected"),
                "reset-callback" => ("RESET_REJECTED", "Configured reset callback rejected"),
                _ => ("APPLICATION_REJECTED", "Configured application rejected"),
            };
            return Err(AuthError::Upstream {
                status: 403,
                code,
                message,
            });
        }
        Ok(())
    }
}
#[async_trait]
impl PasswordHasher for Application {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        self.event(json!({"stage":"hash-enter","password":password}));
        let hash = ScryptHasher.hash(password).await?;
        self.event(json!({"stage":"hash-result","password":password,"hash":hash}));
        self.fail("hash")?;
        Ok(hash)
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        self.event(json!({"stage":"verify-enter","password":password,"hash":hash}));
        let valid = ScryptHasher.verify(hash, password).await?;
        self.event(json!({"stage":"verify-result","password":password,"hash":hash,"valid":valid}));
        self.fail("verify")?;
        Ok(valid)
    }
}
#[async_trait]
impl SendVerificationEmail for Application {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        self.event(json!({"stage":"verification-email","user":user,"url":url,"token":token}));
        Ok(())
    }
}
#[async_trait]
impl SendEmailOtp for Application {
    async fn send(&self, delivery: &EmailOtpDelivery) -> AuthResult<()> {
        self.event(json!({"stage":"otp","email":delivery.email,"otp":delivery.otp,"type":delivery.otp_type.as_str()}));
        Ok(())
    }
}
fn request_observation() -> Value {
    better_auth_core::hooks::current_request_hook_context().map_or(Value::Null, |request| {
        let path = request.path.rsplit("/api/auth").next().unwrap_or(&request.path);
        json!({"method":format!("{:?}",request.method).to_uppercase(),"path":path,
            "marker":request.headers.get("x-test-policy-marker"),"contentType":request.headers.get("content-type")})
    })
}
#[async_trait]
impl SendResetPassword for Application {
    async fn send(&self, user: &Value, url: &str, token: &str) -> AuthResult<()> {
        self.event(json!({"stage":"reset-delivery","user":user,"url":url,"token":token,"request":request_observation()}));
        self.fail("reset-sender")
    }
}
fn database_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}

pub(super) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let app = Arc::new(Application::default());
    let mut router = Router::new();
    let mut profiles: HashMap<String, Arc<BetterAuth<TestSchema>>> = HashMap::new();
    for name in [
        "signup-standard",
        "signup-disabled",
        "signup-password-disabled",
        "signup-no-auto",
        "signup-required",
        "signup-custom",
        "signup-policy",
        "signup-username",
        "signup-otp",
        "signup-background",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = base.clone().base_path(&path);
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
            .rate_limit(RateLimitConfig { enabled: false, ..Default::default() })
            .plugin(EmailPasswordPlugin::with_config(EmailPasswordConfig {
                enable_signup: name != "signup-disabled",
                enable_username: name == "signup-username",
                auto_sign_in: !["signup-no-auto", "signup-custom", "signup-username", "signup-background"].contains(&name),
                require_email_verification: ["signup-required", "signup-otp"].contains(&name),
                password_min_length: if name == "signup-policy" {10} else {8},
                password_max_length: if name == "signup-policy" {20} else {128},
                password_hasher: Some(app.clone()),
                ..Default::default()
            }))
            .plugin(SessionManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new().custom_send_verification_email(app.clone()))
            .plugin(PasswordManagementPlugin::new().reset_token_expiry_hours(1)
                .password_hasher(app.clone()).send_reset_password(app.clone())
                .revoke_sessions_on_password_reset(name == "signup-policy")
                .on_password_reset({let app = app.clone(); Arc::new(move |user| {
                    let app = app.clone(); Box::pin(async move {
                        app.event(json!({"stage":"password-reset","user":user,"request":request_observation()}));
                        app.fail("reset-callback")
                    })
                })}));
        if name == "signup-otp" {
            builder = builder.plugin(EmailOtpPlugin::new(EmailOtpConfig {
                send_verification_otp: Some(app.clone()),
                override_default_email_verification: true,
                ..Default::default()
            }));
        }
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        let _ = profiles.insert(name.to_owned(), auth);
    }
    let profiles = Arc::new(profiles);
    let state_profiles = profiles.clone();
    let state_app = app.clone();
    let state_db = database.clone();
    router = router.route("/__test/signup-policy/state", get(move |Query(query): Query<HashMap<String,String>>| {
        let profiles = state_profiles.clone(); let app = state_app.clone(); let db = state_db.clone();
        async move {
            let result: AuthResult<Value> = async {
                let auth = profiles.get(query.get("profile").map_or("signup-standard", String::as_str))
                    .ok_or_else(||AuthError::bad_request("unknown fixture profile"))?;
                let users = user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&db).await.map_err(database_error)?;
                let accounts = account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&db).await.map_err(database_error)?;
                let sessions = session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&db).await.map_err(database_error)?;
                let verifications = verification::Entity::find().order_by_asc(verification::Column::CreatedAt).all(&db).await.map_err(database_error)?;
                let accounts = accounts.iter().map(|row| {let mut value=serde_json::to_value(AccountView::from(row)).unwrap();
                    value["password"]=json!(row.password); value}).collect::<Vec<_>>();
                Ok(json!({"users":users.iter().map(|row|auth.context().user_view(row)).collect::<Vec<_>>(),
                    "accounts":accounts,"sessions":sessions.iter().map(|row|auth.context().session_view(row)).collect::<Vec<_>>(),
                    "verifications":verifications.iter().map(VerificationView::from).collect::<Vec<_>>(),"events":*app.events.lock().unwrap()}))
            }.await;
            match result {Ok(value)=>Json(value).into_response(),Err(error)=>error.into_response()}
        }
    }));
    router = router.route(
        "/__test/signup-policy",
        post(move |Json(body): Json<Value>| {
            let profiles = profiles.clone();
            let app = app.clone();
            async move {
                let result: AuthResult<Value> = async {
                    match body["operation"].as_str().unwrap_or_default() {
                        "mode" => {
                            *app.mode.lock().unwrap() =
                                body["mode"].as_str().unwrap_or("normal").to_owned();
                            app.events.lock().unwrap().clear();
                            Ok(json!({"status":true,"mode":app.mode()}))
                        }
                        "clear-password" => {
                            let auth = profiles
                                .get(body["profile"].as_str().unwrap_or("signup-standard"))
                                .unwrap();
                            drop(
                                auth.store()
                                    .update_account(
                                        body["accountId"].as_str().unwrap(),
                                        better_auth_core::UpdateAccount {
                                            password: None,
                                            ..Default::default()
                                        },
                                    )
                                    .await?,
                            );
                            Ok(json!({"status":true}))
                        }
                        _ => Err(AuthError::bad_request("unknown fixture operation")),
                    }
                }
                .await;
                match result {
                    Ok(value) => Json(value).into_response(),
                    Err(error) => error.into_response(),
                }
            }
        }),
    );
    Ok(router)
}
