//! Local SMS delivery and actual configured phone runtimes.
use crate::fixtures::passwordless_numeric_fixture::numeric_setting;
use crate::{CompatTwoFactorOtpSender, TestSchema};
use alibi::plugins::phone_number::{
    PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberValidator, PhoneNumberVerification,
    PhoneOtpDelivery, PhoneOtpVerifier, PhoneSignupIdentity, PhoneVerificationHook, SendPhoneOtp,
};
use alibi::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin,
};
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthResult};
use alibi::{integrations::axum::AxumIntegration, middleware::RateLimitConfig};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

struct NotificationApplication {
    release: tokio::sync::watch::Sender<bool>,
    held: std::sync::Mutex<bool>,
    events: std::sync::Mutex<Vec<Value>>,
    scheduled: std::sync::atomic::AtomicUsize,
}
impl Default for NotificationApplication {
    fn default() -> Self {
        Self {
            release: tokio::sync::watch::channel(true).0,
            held: std::sync::Mutex::new(false),
            events: std::sync::Mutex::new(Vec::new()),
            scheduled: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
struct NotificationHandler {
    app: Arc<NotificationApplication>,
    reject: bool,
}
impl alibi::BackgroundTaskHandler for NotificationHandler {
    fn handle(&self, completion: alibi::BackgroundTaskCompletion) -> AuthResult<()> {
        self.app
            .scheduled
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::spawn(async move {
            let _ = completion.await;
        });
        if self.reject {
            Err(alibi::AuthError::internal(
                "Application scheduling observation rejected",
            ))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct Controls {
    outbox: Arc<Mutex<HashMap<String, Value>>>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
    callbacks: Arc<Mutex<Vec<Value>>>,
    verifier_mode: Arc<Mutex<String>>,
    reset_mode: Arc<Mutex<String>>,
    reset_events: Arc<Mutex<Vec<Value>>>,
    notification: Arc<NotificationApplication>,
    validator_events: Arc<Mutex<Vec<String>>>,
}
impl Controls {
    pub(super) async fn reset(&self) {
        self.outbox.lock().await.clear();
        self.challenges.lock().await.clear();
        self.callbacks.lock().await.clear();
        *self.verifier_mode.lock().await = "success".to_owned();
        *self.reset_mode.lock().await = "success".to_owned();
        self.reset_events.lock().await.clear();
    }
}
struct Sender {
    controls: Controls,
    purpose: &'static str,
    custom: bool,
    notification: bool,
}
#[async_trait]
impl SendPhoneOtp for Sender {
    async fn send(
        &self,
        delivery: &PhoneOtpDelivery,
        _context: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        let identifier = if self.purpose == "password-reset" {
            format!("{}-request-password-reset", delivery.phone_number)
        } else {
            delivery.phone_number.clone()
        };
        let context =
            crate::fixtures::passwordless_context::snapshot(_context, &identifier).await?;
        let mut value = json!({"code":delivery.code});
        if let Some(context) = context {
            value["context"] = context;
        }
        _ = self
            .controls
            .outbox
            .lock()
            .await
            .insert(format!("{}:{}", self.purpose, delivery.phone_number), value);
        if self.custom {
            _ = self
                .controls
                .challenges
                .lock()
                .await
                .insert(delivery.phone_number.clone(), delivery.code.clone());
        }
        if self.notification {
            let app = self.controls.notification.clone();
            let mut released = app.release.subscribe();
            let held = *app.held.lock().unwrap();
            let request=_context.request.as_ref().map(|request|json!({"path":request.url().map(|url|url.path()).unwrap_or(request.path()),"method":format!("{:?}",request.method()).to_uppercase(),"marker":request.headers.get("x-phone-delivery-marker")}));
            let receipt = json!({"purpose":self.purpose,"phoneNumber":delivery.phone_number,"code":delivery.code,"request":request});
            let mut started = receipt.clone();
            started["stage"] = json!("started");
            app.events.lock().unwrap().push(started);
            while !*released.borrow_and_update() {
                released
                    .changed()
                    .await
                    .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
            }
            let mut completed = receipt;
            completed["stage"] = json!(if held { "rejected" } else { "completed" });
            app.events.lock().unwrap().push(completed);
            if held {
                return Err(alibi::AuthError::internal(
                    "Application SMS delivery rejected",
                ));
            }
        }
        Ok(())
    }
}
struct Identity;
impl PhoneSignupIdentity for Identity {
    fn temporary_email(&self, phone: &str) -> String {
        format!("{phone}@phone.fixture.test")
    }
    fn temporary_name(&self, phone: &str) -> Option<String> {
        Some(phone.into())
    }
}
struct GuardValidator(Controls);
#[async_trait]
impl PhoneNumberValidator for GuardValidator {
    async fn is_valid(&self, phone: &str) -> AuthResult<bool> {
        self.0.validator_events.lock().await.push(phone.to_owned());
        Err(alibi::AuthError::internal(
            "Validator must not run before required sender guard",
        ))
    }
}
struct Validator;
#[async_trait]
impl PhoneNumberValidator for Validator {
    async fn is_valid(&self, phone: &str) -> AuthResult<bool> {
        Ok(phone.starts_with('+')
            && (9..=16).contains(&phone.len())
            && phone[1..].bytes().all(|value| value.is_ascii_digit()))
    }
}
struct Verifier(Controls);
#[async_trait]
impl PhoneOtpVerifier for Verifier {
    async fn verify(
        &self,
        delivery: &PhoneOtpDelivery,
        _context: &alibi::CallbackContext,
    ) -> AuthResult<bool> {
        if let Some(snapshot) =
            crate::fixtures::passwordless_context::snapshot(_context, &delivery.phone_number)
                .await?
        {
            _ = self.0.outbox.lock().await.insert(
                format!("verifier:{}", delivery.phone_number),
                json!({"context":snapshot}),
            );
        }
        if _context
            .context::<TestSchema>()
            .unwrap()
            .config
            .base_path
            .contains("phone-custom-errors")
        {
            match self.0.verifier_mode.lock().await.as_str() {
                "coded" => {
                    return Err(alibi::AuthError::Api {
                        status: 403,
                        code: Some("PHONE_VERIFIER_REJECTED".into()),
                        message: "Application verifier rejected".into(),
                    });
                }
                "ordinary" => {
                    return Err(alibi::AuthError::internal("Application verifier failed"));
                }
                _ => {}
            }
        }
        let mut challenges = self.0.challenges.lock().await;
        if challenges.get(&delivery.phone_number) != Some(&delivery.code) {
            return Ok(false);
        }
        _ = challenges.remove(&delivery.phone_number);
        Ok(true)
    }
}
struct Callback(Controls);
#[async_trait]
impl PhoneVerificationHook for Callback {
    async fn verified(
        &self,
        result: &PhoneNumberVerification,
        _context: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        let mut event = json!({"phoneNumber":result.phone_number,"userId":result.user.id});
        if let Some(snapshot) =
            crate::fixtures::passwordless_context::snapshot(_context, &result.phone_number).await?
        {
            event["context"] = snapshot;
            let auth = _context.context::<TestSchema>().unwrap();
            event["verifiedOwner"] = json!(
                auth.database
                    .get_user_by_id_record(&result.user.id)
                    .await?
                    .is_some_and(
                        |owner| alibi::AuthUser::phone_number_verified(&owner) == Some(true)
                    )
            );
        }
        self.0.callbacks.lock().await.push(event);
        if _context
            .context::<TestSchema>()
            .unwrap()
            .config
            .base_path
            .contains("phone-callback-reject")
        {
            return Err(alibi::AuthError::Api {
                status: 403,
                code: Some("PHONE_CALLBACK_REJECTED".into()),
                message: "Application verification callback rejected".into(),
            });
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct Runtime {
    pub auth: Arc<Alibi<TestSchema>>,
    pub plugin: PhoneNumberPlugin,
}
pub(super) type Runtimes = Arc<HashMap<String, Runtime>>;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryQuery {
    phone_number: String,
    #[serde(rename = "type")]
    purpose: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsumeRequest {
    profile: String,
    phone_number: String,
    code: String,
}

pub(super) async fn build(
    config: &AuthConfig,
    database: DatabaseConnection,
    controls: Controls,
    two_factor_outbox: Arc<Mutex<HashMap<String, String>>>,
) -> AuthResult<(Router, Runtimes)> {
    let mut router = Router::new();
    let mut runtimes = HashMap::new();
    for name in [
        "phone-notification-awaited",
        "phone-notification-background",
        "phone-notification-schedule-error",
        "phone-no-otp-sender",
        "phone-no-reset-sender",
        "phone-default",
        "phone-signup",
        "phone-proof",
        "phone-custom",
        "phone-custom-errors",
        "phone-callback-reject",
        "phone-reset-callback",
        "phone-numeric-length-zero",
        "phone-numeric-length-fraction",
        "phone-numeric-length-negative",
        "phone-numeric-length-nan",
        "phone-numeric-length-negative-infinity",
        "phone-numeric-attempts-zero",
        "phone-numeric-attempts-fraction",
        "phone-numeric-attempts-negative",
        "phone-numeric-attempts-nan",
        "phone-numeric-attempts-infinity",
        "phone-numeric-attempts-negative-infinity",
        "phone-numeric-lifetime-zero",
        "phone-numeric-lifetime-fraction",
        "phone-numeric-lifetime-negative",
        "phone-numeric-lifetime-nan",
        "phone-numeric-lifetime-infinity",
        "phone-numeric-lifetime-negative-infinity",
    ] {
        let custom = name.starts_with("phone-custom");
        let mut config = config
            .clone()
            .base_path(format!("/__test/profiles/{name}/api/auth"));
        if name.starts_with("phone-notification-") && name != "phone-notification-awaited" {
            config = config.background_tasks(Arc::new(NotificationHandler {
                app: controls.notification.clone(),
                reject: name == "phone-notification-schedule-error",
            }));
        }
        let plugin = PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: if name == "phone-no-otp-sender" {
                None
            } else {
                Some(Arc::new(Sender {
                    controls: controls.clone(),
                    purpose: "verification",
                    custom,
                    notification: name.starts_with("phone-notification-"),
                }))
            },
            send_password_reset_otp: if name == "phone-no-reset-sender" {
                None
            } else {
                Some(Arc::new(Sender {
                    controls: controls.clone(),
                    purpose: "password-reset",
                    custom: false,
                    notification: name.starts_with("phone-notification-"),
                }))
            },
            require_verification: name == "phone-proof" || name.starts_with("phone-notification-"),
            sign_up_on_verification: (name != "phone-default")
                .then(|| Arc::new(Identity) as Arc<dyn PhoneSignupIdentity>),
            phone_number_validator: if name == "phone-no-otp-sender" {
                Some(Arc::new(GuardValidator(controls.clone())))
            } else {
                custom.then(|| Arc::new(Validator) as Arc<dyn PhoneNumberValidator>)
            },
            verify_otp: custom
                .then(|| Arc::new(Verifier(controls.clone())) as Arc<dyn PhoneOtpVerifier>),
            callback_on_verification: Some(Arc::new(Callback(controls.clone()))),
            otp_length: numeric_setting(name, "length", 6.0),
            allowed_attempts: numeric_setting(name, "attempts", 3.0),
            expires_in: numeric_setting(name, "lifetime", 300.0),
        });
        let mut passwords = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(
            name == "phone-proof" || name == "phone-reset-callback",
        );
        if name == "phone-reset-callback" {
            let controls = controls.clone();
            passwords = passwords.on_password_reset(Arc::new(move |user| {
                let controls = controls.clone();
                Box::pin(async move {
                    let request = alibi::hooks::current_request_hook_context().map(|context| json!({"method":format!("{:?}",context.method).to_uppercase(),"url":context.url,"marker":context.headers.get("x-reset-marker")}));
                    controls.reset_events.lock().await.push(json!({"userId":user["id"],"request":request}));
                    if controls.reset_mode.lock().await.as_str() == "reject" { return Err(alibi::AuthError::Api { status: 403, code: Some("PHONE_RESET_REJECTED".into()), message: "Application reset callback rejected".into() }); }
                    Ok(())
                })
            }));
        }
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config.clone(),
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(passwords)
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::new().custom_send_otp(Arc::new(
                    CompatTwoFactorOtpSender {
                        outbox: two_factor_outbox.clone(),
                    },
                )))
                .plugin(plugin.clone())
                .build()
                .await?,
        );
        router = router.nest(
            &config.base_path,
            auth.clone().axum_router().with_state(auth.clone()),
        );
        _ = runtimes.insert(name.into(), Runtime { auth, plugin });
    }
    let callbacks = controls.clone();
    let verifier_controls = controls.clone();
    let reset_controls = controls.clone();
    let consume_runtimes = Arc::new(runtimes);
    let selected_runtimes = consume_runtimes.clone();
    let validator_controls = controls.clone();
    let notification_read = controls.notification.clone();
    let notification_write = controls.notification.clone();
    router = router.route("/__test/phone-notifications",get(move ||{let app=notification_read.clone();async move {Json(json!({"events":*app.events.lock().unwrap(),"scheduled":app.scheduled.load(std::sync::atomic::Ordering::SeqCst)}))}}).post(move |Json(body):Json<Value>|{let app=notification_write.clone();async move {
        match body["operation"].as_str().unwrap() {"arm"=>{app.events.lock().unwrap().clear();app.scheduled.store(0,std::sync::atomic::Ordering::SeqCst);*app.held.lock().unwrap()=true;app.release.send_replace(false);},"release"=>{app.release.send_replace(true);},"restore"=>{*app.held.lock().unwrap()=false;app.release.send_replace(true);},_=>{}}
        Json(json!({"events":*app.events.lock().unwrap(),"scheduled":app.scheduled.load(std::sync::atomic::Ordering::SeqCst)}))
    }}))
        .route("/__test/phone-validator-events",get(move || {let controls=validator_controls.clone();async move {Json(controls.validator_events.lock().await.clone())}}))
        .route("/__test/phone-verifier-control", post(move |Json(body): Json<Value>| {
            let controls = verifier_controls.clone();
            async move { *controls.verifier_mode.lock().await = body["mode"].as_str().unwrap_or("success").to_owned(); Json(json!({"status":true})) }
        }))
        .route("/__test/phone-reset-control", post(move |Json(body): Json<Value>| {
            let controls = reset_controls.clone();
            async move {
                if let Some(mode) = body["mode"].as_str() { *controls.reset_mode.lock().await = mode.to_owned(); }
                Json(json!({"mode":controls.reset_mode.lock().await.clone(),"events":controls.reset_events.lock().await.clone()}))
            }
        }))
        .route(
            "/__test/phone-callbacks",
            get(move || {
                let callbacks = callbacks.clone();
                async move { Json(callbacks.callbacks.lock().await.clone()) }
            }),
        )
        .route(
            "/__test/phone-consume-otp",
            post(move |Json(body): Json<ConsumeRequest>| {
                let runtimes = selected_runtimes.clone();
                async move {
                    let result = async {
                        let selected = runtimes.get(&body.profile).ok_or_else(|| {
                            alibi::AuthError::bad_request("unknown fixture profile")
                        })?;
                        selected
                            .plugin
                            .consume_otp(selected.auth.context(), &body.phone_number, &body.code)
                            .await?;
                        Ok::<_, alibi::AuthError>(json!({"status":true}))
                    }
                    .await;
                    match result {
                        Ok(value) => Json(value).into_response(),
                        Err(error) => (
                            axum::http::StatusCode::from_u16(error.status_code()).unwrap(),
                            Json(
                                serde_json::from_slice::<Value>(&error.to_auth_response().body)
                                    .unwrap(),
                            ),
                        )
                            .into_response(),
                    }
                }
            }),
        );
    router = router.route(
        "/__test/phone-otp",
        get(move |Query(query): Query<DeliveryQuery>| {
            let controls = controls.clone();
            async move {
                Json(
                    controls
                        .outbox
                        .lock()
                        .await
                        .get(&format!(
                            "{}:{}",
                            query.purpose.as_deref().unwrap_or("verification"),
                            query.phone_number
                        ))
                        .cloned()
                        .unwrap_or(Value::Null),
                )
            }
        }),
    );
    Ok((router, consume_runtimes))
}
