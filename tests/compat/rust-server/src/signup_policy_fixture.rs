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
    AuthRequest, BackgroundTaskCompletion, BackgroundTaskHandler, PasswordHasher, ScryptHasher,
    wire::{AccountView, UserView, VerificationView},
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

#[derive(Default)]
struct Application {
    mode: Mutex<String>,
    events: Mutex<Vec<Value>>,
    release_existing: tokio::sync::Notify,
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
                "existing" => ("EXISTING_REJECTED", "Configured existing-user rejected"),
                "synthetic" => ("SYNTHETIC_REJECTED", "Configured synthetic-user rejected"),
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
impl BackgroundTaskHandler for Application {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        self.event(json!({"stage":"background-register"}));
        drop(completion);
        if self.mode() == "background-error" {
            return Err(AuthError::internal("Actual background observer failed"));
        }
        Ok(())
    }
}
#[async_trait]
impl SeaOrmHooks<TestSchema> for Application {
    async fn before_create_user(
        &self,
        _user: &mut better_auth_core::CreateUser,
        _context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if self.mode() == "user-forbidden" {
            self.event(json!({"stage":"user-create-denied"}));
            return Err(AuthError::Upstream {
                status: 403,
                code: "USER_CREATION_DENIED",
                message: "Configured user creation denied",
            });
        }
        if self.mode() == "user-cancel" {
            self.event(json!({"stage":"user-create-cancelled"}));
            return Ok(HookControl::Cancel);
        }
        if self.mode() == "user-error" {
            self.event(json!({"stage":"user-create-error"}));
            return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "Actual configured user creation failed",
            ))));
        }
        Ok(HookControl::Continue)
    }
}
fn signup_request_observation(request: &AuthRequest) -> Value {
    json!({"method":format!("{:?}",request.method()).to_uppercase(),"path":request.path(),
        "marker":request.headers.get("x-test-policy-marker"),"contentType":request.headers.get("content-type")})
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
        let mut config = base.clone().base_path(&path);
        if name == "signup-background" {
            config.background_tasks = Some(app.clone());
        }
        let mut password_management = PasswordManagementPlugin::new()
            .send_reset_password(app.clone())
            .revoke_sessions_on_password_reset(name == "signup-policy")
            .on_password_reset({let app = app.clone(); Arc::new(move |user| {
                let app = app.clone(); Box::pin(async move {
                    app.event(json!({"stage":"password-reset","user":user,"request":request_observation()}));
                    app.fail("reset-callback")
                })
            })});
        if name == "signup-policy" {
            password_management =
                password_management.reset_token_expiry(chrono::Duration::seconds(90));
        }
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(config, database.clone()).with_hooks(vec![app.clone()]))
            .rate_limit(RateLimitConfig { enabled: false, ..Default::default() })
            .plugin(EmailPasswordPlugin::with_config(EmailPasswordConfig {
                enabled: name != "signup-password-disabled",
                enable_signup: name != "signup-disabled",
                enable_username: name == "signup-username",
                auto_sign_in: !["signup-no-auto", "signup-custom", "signup-username", "signup-background"].contains(&name),
                require_email_verification: ["signup-required", "signup-otp"].contains(&name),
                password_min_length: if name == "signup-policy" {10} else {8},
                password_max_length: if name == "signup-policy" {20} else {128},
                password_hasher: Some(app.clone()),
                on_existing_user_signup: Some({let app=app.clone(); Arc::new(move |user, request| {
                    let app=app.clone(); Box::pin(async move {
                        app.event(json!({"stage":"existing-user","user":user,"request":signup_request_observation(&request)}));
                        if app.mode() == "existing-block" { app.release_existing.notified().await; }
                        app.fail("existing")?;
                        app.event(json!({"stage":"existing-complete"}));
                        Ok(())
                    })
                })}),
                custom_synthetic_user: (name == "signup-custom").then(|| {
                    let app=app.clone(); Arc::new(move |input: better_auth::plugins::email_password::SyntheticUserContext| {
                        app.event(json!({"stage":"synthetic-user","coreFields":input.core_fields,
                            "additionalFields":input.additional_fields,"id":input.id}));
                        app.fail("synthetic")?;
                        let mut fields=input.core_fields;
                        let requested=fields.get("name").and_then(Value::as_str).unwrap_or_default();
                        let name=format!("Synthetic {requested}");
                        drop(fields.insert("name".into(),json!(name)));
                        drop(fields.insert("id".into(),json!(input.id)));
                        drop(fields.insert("emailVerified".into(),json!(true)));
                        drop(fields.insert("image".into(),json!("https://images.example/synthetic.png")));
                        drop(fields.insert("role".into(),json!("admin")));
                        drop(fields.insert("privateCredential".into(),json!("unreturned-application-data")));
                        Ok(fields)
                    }) as Arc<better_auth::plugins::email_password::CustomSyntheticUserCallback>
                }),
            }))
            .plugin(SessionManagementPlugin::new())
            .plugin(if name == "signup-otp" {EmailVerificationPlugin::new()} else {
                EmailVerificationPlugin::new().custom_send_verification_email(app.clone())
            })
            .plugin(password_management);
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
    let control_database = database.clone();
    router = router.route(
        "/__test/signup-policy",
        post(move |Json(body): Json<Value>| {
            let profiles = profiles.clone();
            let app = app.clone();
            let database = control_database.clone();
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
                            let _auth = profiles
                                .get(body["profile"].as_str().unwrap_or("signup-standard"))
                                .unwrap();
                            let row =
                                account::Entity::find_by_id(body["accountId"].as_str().unwrap())
                                    .one(&database)
                                    .await
                                    .map_err(database_error)?
                                    .unwrap();
                            let mut row = row.into_active_model();
                            row.password = Set(body["password"].as_str().map(str::to_owned));
                            row.updated_at = Set(chrono::Utc::now());
                            drop(row.update(&database).await.map_err(database_error)?);
                            Ok(json!({"status":true}))
                        }
                        "release-existing" => {
                            app.release_existing.notify_waiters();
                            Ok(json!({"status":true}))
                        }
                        "wait-stage" => {
                            let deadline =
                                tokio::time::Instant::now() + std::time::Duration::from_secs(4);
                            while !app
                                .events
                                .lock()
                                .unwrap()
                                .iter()
                                .any(|event| event["stage"] == body["stage"])
                            {
                                if tokio::time::Instant::now() >= deadline {
                                    return Err(AuthError::internal(
                                        "Application callback did not reach requested stage",
                                    ));
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                            }
                            Ok(json!({"events":*app.events.lock().unwrap()}))
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
