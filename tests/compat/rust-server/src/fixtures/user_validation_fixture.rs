//! Trusted application identity policy at the real HTTP/store boundary.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        AdminPlugin, AnonymousPlugin, EmailPasswordConfig, EmailPasswordPlugin,
        SessionManagementPlugin,
        anonymous::{AnonymousConfig, AnonymousIdentity},
        email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp},
        magic_link::{MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink},
        oauth::{OAuthPlugin, OAuthProvider},
        one_tap::{OneTapClientId, OneTapConfig, OneTapPlugin},
        phone_number::{
            PhoneNumberConfig, PhoneNumberPlugin, PhoneOtpDelivery, PhoneSignupIdentity,
            SendPhoneOtp,
        },
        siwe::{Eip191Verifier, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiwePlugin},
    },
};
use better_auth_core::{
    AuthRequest, AuthUser, CreateUser, PasswordHasher, ScryptHasher,
    hooks::{RequestHookContext, TransformedRequestBody, ValidatedRequestBody},
    user_validation::{
        UserInfoValidator, UserValidationData, UserValidationRejection, UserValidationSource,
    },
    wire::{AccountView, VerificationView},
};
use better_auth_seaorm::{
    DatabaseConnection, DatabaseHooks, HookControl,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, sea_query::Expr},
    store::entities::{account, session, user, verification, wallet_address},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Default)]
pub(crate) struct Application {
    mode: Mutex<String>,
    events: Mutex<Vec<Value>>,
    deliveries: Mutex<HashMap<String, Value>>,
    sequence: AtomicUsize,
    release: tokio::sync::Notify,
}
impl Application {
    pub(crate) fn reset(&self) {
        self.sequence.store(0, Ordering::SeqCst);
        self.events.lock().unwrap().clear();
        self.deliveries.lock().unwrap().clear();
        *self.mode.lock().unwrap() = "normal".into();
    }
    fn mode(&self) -> String {
        self.mode.lock().unwrap().clone()
    }
    fn event(&self, value: Value) {
        self.events.lock().unwrap().push(value);
    }
    fn deliver(&self, key: String, value: Value) {
        let _ = self.deliveries.lock().unwrap().insert(key, value);
    }
}
fn candidate(user: &CreateUser) -> Value {
    let fields = serde_json::to_value(user).unwrap();
    let result = fields
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| {
            let mut words = key.split('_');
            let mut name = words.next().unwrap().to_owned();
            for word in words {
                let mut chars = word.chars();
                if let Some(first) = chars.next() {
                    name.extend(first.to_uppercase());
                    name.extend(chars);
                }
            }
            let value = if key == "created_at" {
                json!(
                    user.created_at
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                )
            } else if key == "updated_at" {
                json!(
                    user.updated_at
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                )
            } else {
                value.clone()
            };
            (name, value)
        })
        .collect::<serde_json::Map<_, _>>();
    Value::Object(result)
}
fn context_path(request: &RequestHookContext) -> String {
    request
        .extensions
        .get::<better_auth_core::plugin::ResolvedEndpoint>()
        .map_or_else(|| request.path.clone(), |endpoint| endpoint.path.clone())
}
#[async_trait]
impl UserInfoValidator for Application {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        request: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let mode = self.mode();
        let body = request
            .extensions
            .get::<TransformedRequestBody>()
            .map(|value| value.0.clone())
            .or_else(|| {
                request
                    .extensions
                    .get::<ValidatedRequestBody>()
                    .map(|value| value.0.clone())
            })
            .or_else(|| {
                request
                    .body
                    .as_deref()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .and_then(|body| better_auth_core::utils::json::parse_value(body).ok())
            });
        self.event(json!({"stage":"validation","user":candidate(&data.user),"source":data.source,"context":{
            "path":context_path(request),"body":body.map(|body|body.to_json_value().unwrap()),
            "request":{"method":format!("{:?}",request.method).to_uppercase(),"path":request.path,
                "marker":request.headers.get("x-test-validation-marker"),"contentType":request.headers.get("content-type")}}}));
        if mode == "hold" {
            self.release.notified().await;
        }
        if mode == "deny-empty-name" && data.user.name.as_deref() == Some("") {
            return Ok(Some(UserValidationRejection {
                error: "identity_denied".into(),
                error_description: Some("Configured identity rejected".into()),
            }));
        }
        match mode.as_str() {
            "hold" | "deny" | "deny-default" | "empty-error" => {
                return Ok(Some(UserValidationRejection {
                    error: if mode == "empty-error" {
                        ""
                    } else {
                        "identity_denied"
                    }
                    .into(),
                    error_description: (mode != "deny-default").then(|| {
                        if mode == "empty-error" {
                            "Unused description"
                        } else {
                            "Configured identity rejected"
                        }
                        .into()
                    }),
                }));
            }
            "throw" => return Err(AuthError::internal("Private application exception")),
            "api-error" => {
                return Err(AuthError::Api {
                    status: 401,
                    code: Some("PRIVATE_CALLBACK_CODE".into()),
                    message: "Private callback detail".into(),
                });
            }
            "mutate" => {
                data.user.name = Some("Validated Identity".into());
                data.user.email = Some("MUTATED@VALIDATION.FIXTURE.TEST".into());
                data.user.email_verified = Some(true);
                data.user.image = Some("https://images.example/validated.png".into());
                data.user.created_at = Some("2001-01-01T00:00:00.000Z".parse().unwrap());
            }
            _ => {}
        }
        Ok(None)
    }
}
#[async_trait]
impl PasswordHasher for Application {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        self.event(json!({"stage":"hash-enter","password":password}));
        let hash = ScryptHasher.hash(password).await?;
        self.event(json!({"stage":"hash-result","password":password,"hash":hash}));
        Ok(hash)
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        ScryptHasher.verify(hash, password).await
    }
}
#[async_trait]
impl DatabaseHooks<TestSchema, crate::backend::Backend> for Application {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.event(json!({"stage":"user-create-before","user":candidate(user),"path":context.request.as_ref().map(context_path)}));
        Ok(if self.mode() == "hook-deny" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_create_user(
        &self,
        user: &<TestSchema as better_auth_core::AuthSchema>::User,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        self.event(json!({"stage":"user-create-after","userId":user.id(),"path":context.request.as_ref().map(context_path)}));
        Ok(())
    }
    async fn before_create_account(
        &self,
        _: &mut better_auth_core::CreateAccount,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.event(json!({"stage":"account-create-before","path":context.request.as_ref().map(context_path)}));
        Ok(HookControl::Continue)
    }
    async fn before_create_session(
        &self,
        _: &mut better_auth_core::CreateSession,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.event(json!({"stage":"session-create-before","path":context.request.as_ref().map(context_path)}));
        Ok(HookControl::Continue)
    }
}
#[async_trait]
impl AnonymousIdentity for Application {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some(format!(
            "Anonymous-{}@Validation.Fixture.Test",
            self.sequence.fetch_add(1, Ordering::SeqCst) + 1
        )))
    }
    async fn name(&self, _: &AuthRequest) -> AuthResult<Option<String>> {
        Ok(Some("Configured Anonymous".into()))
    }
}
#[async_trait]
impl SendMagicLink for Application {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(
            format!("magic:{}", delivery.email),
            serde_json::to_value(delivery)?,
        );
        Ok(())
    }
}
#[async_trait]
impl SendEmailOtp for Application {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(
            format!("otp:{}:{}", delivery.otp_type.as_str(), delivery.email),
            json!({"email":delivery.email,"otp":delivery.otp,"type":delivery.otp_type.as_str()}),
        );
        Ok(())
    }
}
#[async_trait]
impl SendPhoneOtp for Application {
    async fn send(
        &self,
        delivery: &PhoneOtpDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(
            format!("phone:{}", delivery.phone_number),
            json!({"phoneNumber":delivery.phone_number,"code":delivery.code}),
        );
        Ok(())
    }
}
impl PhoneSignupIdentity for Application {
    fn temporary_email(&self, phone: &str) -> String {
        format!("{phone}@Phone.Validation.Fixture.Test")
    }
    fn temporary_name(&self, phone: &str) -> Option<String> {
        Some(phone.into())
    }
}
#[async_trait]
impl SiweNonceProvider for Application {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok(format!(
            "ValidationNonce{:016}",
            self.sequence.fetch_add(1, Ordering::SeqCst)
        ))
    }
}
fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Arc<Application>)> {
    let app = Arc::new(Application::default());
    let mut router = Router::new();
    let mut profiles = HashMap::<String, Arc<BetterAuth<TestSchema>>>::new();
    for name in [
        "validation",
        "validation-no-auto",
        "validation-required",
        "validation-disabled",
        "validation-no-policy",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.user_validation =
            (name != "validation-no-policy").then(|| app.clone() as Arc<dyn UserInfoValidator>);
        config.account.account_linking.trusted_providers = vec!["google".into(), "gitlab".into()];
        let mut google =
            OAuthProvider::google("google-default-client", "local-google-default-secret");
        google.id_token.as_mut().unwrap().jwks_source =
            crate::fixtures::one_tap_fixture::local_keys(&base.base_url);
        let gitlab = OAuthProvider::gitlab_with_issuer(
            "fixture-social-client",
            "fixture-social-secret",
            &format!("{}/__test/social-provider/gitlab", base.base_url),
        );
        let mut siwe = SiweConfig::new(
            "HTTPS://Fixture.Example/ignored",
            app.clone(),
            Arc::new(Eip191Verifier),
        );
        siwe.anonymous = false;
        siwe.email_domain_name = Some("Wallet.Fixture.Test".into());
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    crate::backend::store::<TestSchema>(config, database.clone())
                        .with_hooks(vec![app.clone()]),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::with_config(EmailPasswordConfig {
                    enable_username: false,
                    auto_sign_in: name != "validation-no-auto",
                    require_email_verification: name == "validation-required",
                    enable_signup: name != "validation-disabled",
                    password_hasher: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(AdminPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                    identity: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                    send_magic_link: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                    send_verification_otp: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                    send_otp: Some(app.clone()),
                    sign_up_on_verification: Some(app.clone()),
                    ..Default::default()
                }))
                .plugin(OneTapPlugin::with_config(OneTapConfig {
                    client_id: Some(OneTapClientId::Single("one-tap-plugin-client".into())),
                    jwks_source: Some(crate::fixtures::one_tap_fixture::local_keys(&base.base_url)),
                    ..Default::default()
                }))
                .plugin(SiwePlugin::new(siwe))
                .plugin(
                    OAuthPlugin::new()
                        .add_provider("google", google)
                        .add_provider("gitlab", gitlab),
                )
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        let _ = profiles.insert(name.into(), auth);
    }
    let profiles = Arc::new(profiles);
    let state_profiles = profiles.clone();
    let state_app = app.clone();
    let db = database.clone();
    router = router.route("/__test/user-validation/state",get(move || {let profiles=state_profiles.clone();let app=state_app.clone();let db=db.clone();async move {
        let result: AuthResult<Value> = async {
            let auth=profiles.get("validation").unwrap();
            let users=user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&db).await.map_err(db_error)?;
            let accounts=account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&db).await.map_err(db_error)?;
            let sessions=session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&db).await.map_err(db_error)?;
            let proofs=verification::Entity::find().order_by_asc(verification::Column::CreatedAt).all(&db).await.map_err(db_error)?;
            let wallets=wallet_address::Entity::find().order_by_asc(wallet_address::Column::CreatedAt).all(&db).await.map_err(db_error)?;
            let accounts=accounts.iter().map(|row|{let mut value=serde_json::to_value(AccountView::from(row)).unwrap();value["password"]=json!(row.password);value}).collect::<Vec<_>>();
            Ok(json!({"users":users.iter().map(|row|auth.context().user_view(row)).collect::<Vec<_>>(),"accounts":accounts,
                "sessions":sessions.iter().map(|row|auth.context().session_view(row)).collect::<Vec<_>>(),"verifications":proofs.iter().map(VerificationView::from).collect::<Vec<_>>(),
                "wallets":wallets.iter().map(|row|json!({"id":row.id,"userId":row.user_id,"address":row.address,"chainId":row.chain_id.0,"isPrimary":row.is_primary,"createdAt":row.created_at})).collect::<Vec<_>>(),"events":*app.events.lock().unwrap()}))
        }.await;match result {Ok(value)=>Json(value).into_response(),Err(error)=>error.into_response()}
    }}));
    let delivery_app = app.clone();
    router = router.route(
        "/__test/user-validation/delivery",
        get(move |Query(query): Query<HashMap<String, String>>| {
            let app = delivery_app.clone();
            async move {
                Json(
                    app.deliveries
                        .lock()
                        .unwrap()
                        .get(query.get("key").map_or("", String::as_str))
                        .cloned()
                        .unwrap_or(Value::Null),
                )
            }
        }),
    );
    let control_app = app.clone();
    router = router.route(
        "/__test/user-validation",
        post(move |Json(body): Json<Value>| {
            let app = control_app.clone();
            let profiles = profiles.clone();
            let db = database.clone();
            async move {
                let result: AuthResult<Value> = async {
                    match body["operation"].as_str().unwrap_or_default() {
                        "mode" => {
                            *app.mode.lock().unwrap() =
                                body["mode"].as_str().unwrap_or("normal").into();
                            app.events.lock().unwrap().clear();
                            Ok(json!({"status":true,"mode":app.mode()}))
                        }
                        "release" => {
                            app.release.notify_waiters();
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
                        "proof-expiry" => {
                            verification::Entity::update_many()
                                .col_expr(
                                    verification::Column::ExpiresAt,
                                    Expr::value(
                                        body["expiresAt"]
                                            .as_str()
                                            .unwrap()
                                            .parse::<chrono::DateTime<chrono::Utc>>()
                                            .unwrap(),
                                    ),
                                )
                                .filter(
                                    verification::Column::Identifier
                                        .eq(body["identifier"].as_str().unwrap()),
                                )
                                .exec(&db)
                                .await
                                .map_err(db_error)?;
                            Ok(json!({"status":true}))
                        }
                        "server-create" => {
                            let auth = profiles
                                .get(body["profile"].as_str().unwrap_or("validation"))
                                .unwrap();
                            let create = CreateUser::new()
                                .with_name("Server Candidate")
                                .with_email(body["email"].as_str().unwrap())
                                .with_email_verified(false);
                            let user = if body["source"].is_null() {
                                auth.context().database.create_user(create).await?
                            } else {
                                auth.context()
                                    .database
                                    .create_user_with_source(
                                        create,
                                        serde_json::from_value::<UserValidationSource>(
                                            body["source"].clone(),
                                        )?,
                                    )
                                    .await?
                            };
                            Ok(serde_json::to_value(auth.context().user_view(&user))?)
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
    Ok((router, app))
}
