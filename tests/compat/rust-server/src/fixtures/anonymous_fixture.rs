//! Application-owned anonymous identity/link handlers and actual stored-state observer.
use crate::anonymous_user_model::{ApplicationSchema as TestSchema, Model as ApplicationUser};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        AnonymousPlugin, EmailPasswordPlugin, EmailVerificationPlugin, OAuthPlugin, PasskeyPlugin,
        SessionManagementPlugin,
        anonymous::{AnonymousConfig, AnonymousIdentity, AnonymousLink, LinkAnonymousAccount},
        email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp},
        email_verification::SendVerificationEmail,
        magic_link::{MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink},
        oauth::OAuthProvider,
        one_tap::{OneTapClientId, OneTapConfig, OneTapPlugin},
        phone_number::{
            PhoneNumberConfig, PhoneNumberPlugin, PhoneOtpDelivery, PhoneSignupIdentity,
            SendPhoneOtp,
        },
    },
};
use better_auth_core::{AuthRequest, AuthSession, CreateSession, CreateUser};
use better_auth_seaorm::{
    DatabaseConnection, DatabaseHooks, HookControl,
    sea_orm::{EntityTrait, QueryOrder},
    store::entities::{account, session},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
pub(crate) struct Fixture {
    sequence: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<Value>>>,
    deliveries: Arc<Mutex<HashMap<String, Value>>>,
}
impl Fixture {
    pub(crate) fn reset(&self) {
        self.sequence.store(0, Ordering::SeqCst);
        self.events.lock().expect("anonymous receipt lock").clear();
        self.deliveries
            .lock()
            .expect("anonymous delivery lock")
            .clear();
    }
}
struct Application {
    database: DatabaseConnection,
    mode: &'static str,
    fixture: Fixture,
}
impl Application {
    fn deliver(&self, key: String, value: Value) {
        let _ = self
            .fixture
            .deliveries
            .lock()
            .expect("anonymous delivery lock")
            .insert(key, value);
    }
}
#[async_trait]
impl SendMagicLink for Application {
    async fn send(
        &self,
        value: &MagicLinkDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(format!("magic:{}", value.email), json!({"email":value.email,"url":value.url,"token":value.token,"metadata":value.metadata}));
        Ok(())
    }
}
#[async_trait]
impl SendEmailOtp for Application {
    async fn send(
        &self,
        value: &EmailOtpDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(
            format!("{}:{}", value.otp_type.as_str(), value.email),
            json!({"email":value.email,"otp":value.otp,"type":value.otp_type.as_str()}),
        );
        Ok(())
    }
}
#[async_trait]
impl SendPhoneOtp for Application {
    async fn send(
        &self,
        value: &PhoneOtpDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(
            format!("phone:{}", value.phone_number),
            json!({"phoneNumber":value.phone_number,"code":value.code}),
        );
        Ok(())
    }
}
impl PhoneSignupIdentity for Application {
    fn temporary_email(&self, phone: &str) -> String {
        format!("{phone}@phone.fixture.test")
    }
    fn temporary_name(&self, phone: &str) -> Option<String> {
        Some(phone.into())
    }
}
#[async_trait]
impl SendVerificationEmail for Application {
    async fn send(
        &self,
        user: &better_auth_core::wire::UserView,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        if let Some(email) = user.email.as_ref() {
            self.deliver(
                format!("verification:{email}"),
                json!({"email":email,"url":url,"token":token}),
            );
        }
        Ok(())
    }
}
#[async_trait]
impl AnonymousIdentity for Application {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some(if self.mode == "invalid-email" {
            "not an email".into()
        } else {
            format!(
                "anonymous-{}@fixture.test",
                self.fixture.sequence.fetch_add(1, Ordering::SeqCst) + 1
            )
        }))
    }
    async fn name(&self, _request: &AuthRequest) -> AuthResult<Option<String>> {
        tokio::task::yield_now().await;
        Ok(Some(
            if self.mode == "empty-name" {
                ""
            } else {
                "Configured Anonymous"
            }
            .into(),
        ))
    }
}
#[async_trait]
impl LinkAnonymousAccount for Application {
    async fn link(&self, accounts: &AnonymousLink, request: &AuthRequest) -> AuthResult<()> {
        tokio::task::yield_now().await;
        self.fixture.events.lock().expect("anonymous receipt lock").push(json!({
            "mode": self.mode, "path": request.path(),
            "anonymousUser": { "user": accounts.anonymous_user, "session": accounts.anonymous_session },
            "newUser": { "user": accounts.new_user, "session": accounts.new_session },
        }));
        if self.mode == "link-ordinary" {
            return Err(AuthError::internal("Configured anonymous transfer denied"));
        }
        if self.mode == "link-uncoded" {
            return Err(AuthError::Api {
                status: 403,
                code: None,
                message: "Configured anonymous transfer denied".into(),
            });
        }
        if self.mode == "link-error" {
            return Err(AuthError::Api {
                status: 403,
                code: Some("APPLICATION_LINK_DENIED".into()),
                message: "Configured anonymous transfer denied".into(),
            });
        }
        if matches!(
            self.mode,
            "custom" | "custom-cache" | "recovery" | "recovery-disabled"
        ) {
            use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
            self.database
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE users SET cargo_label=? WHERE id=?",
                    vec![
                        format!(
                            "Transferred {}",
                            accounts.anonymous_user.extension_fields["cargoLabel"]
                                .as_str()
                                .unwrap_or_default()
                        )
                        .into(),
                        accounts.new_user.id.clone().into(),
                    ],
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        Ok(())
    }
}
struct Hooks {
    mode: &'static str,
}
#[async_trait]
impl DatabaseHooks<TestSchema, crate::backend::Backend> for Hooks {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        if context
            .request
            .as_ref()
            .is_some_and(|request| request.path == "/sign-in/anonymous")
        {
            if self.mode == "user-cancel" {
                return Ok(HookControl::Cancel);
            }
            if self.mode == "user-forbidden" {
                return Err(AuthError::forbidden(
                    "user creation cancelled by database hook",
                ));
            }
        }
        Ok(HookControl::Continue)
    }
    async fn before_create_session(
        &self,
        _session: &mut CreateSession,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        if context
            .request
            .as_ref()
            .is_some_and(|request| request.path == "/sign-in/anonymous")
        {
            if self.mode == "session-cancel" {
                return Ok(HookControl::Cancel);
            }
            if self.mode == "session-forbidden" {
                return Err(AuthError::forbidden(
                    "session creation cancelled by database hook",
                ));
            }
        }
        Ok(HookControl::Continue)
    }
    async fn after_create_session(
        &self,
        session: &<TestSchema as better_auth_core::AuthSchema>::Session,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        if (self.mode == "snapshot" || self.mode.starts_with("custom"))
            && context
                .request
                .as_ref()
                .is_some_and(|request| request.path == "/sign-up/email")
        {
            _ = crate::backend::hook_execute(
                context.db,
                "UPDATE users SET name=? WHERE id=?",
                vec![
                    "Stored Hook Name".to_owned(),
                    session.user_id().into_owned(),
                ],
            )
            .await?;
            if self.mode.starts_with("custom") {
                _ = crate::backend::hook_execute(
                    context.db,
                    "UPDATE users SET cargo_label=?, cargo_hidden=? WHERE id=?",
                    vec![
                        "Application Stored".into(),
                        "Stored Secret".into(),
                        session.user_id().into_owned(),
                    ],
                )
                .await?;
            }
        }
        Ok(())
    }
}
fn date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
    for column in ["cargo_label", "cargo_hidden"] {
        database
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("ALTER TABLE users ADD COLUMN {column} TEXT"),
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
    }
    let fixture = Fixture::default();
    let mut router = Router::new();
    for mode in [
        "standard",
        "disabled",
        "link-error",
        "user-cancel",
        "user-forbidden",
        "session-cancel",
        "session-forbidden",
        "snapshot",
        "invalid-email",
        "empty-name",
        "methods",
        "custom",
        "custom-methods",
        "custom-cache",
        "link-ordinary",
        "link-uncoded",
        "recovery",
        "recovery-disabled",
    ] {
        let path = format!("/__test/profiles/anonymous-{mode}/api/auth");
        let mut settings = config.clone().base_path(&path);
        if mode.starts_with("custom") || mode.starts_with("recovery") {
            use better_auth::field_policy::FieldConfig;
            settings.user.additional_fields.insert(
                "cargoLabel".into(),
                FieldConfig::new(json!({"type":"string"}))
                    .field_name("cargo_label")
                    .default_callback(|| {
                        better_auth_core::utils::json::JsValue::String(
                            "Application Original".into(),
                        )
                    }),
            );
            settings.user.additional_fields.insert(
                "cargoHidden".into(),
                FieldConfig::new(json!({"type":"string"}))
                    .field_name("cargo_hidden")
                    .default_value(json!("Application Secret"))
                    .hidden(),
            );
        }
        if mode == "custom-cache" {
            settings.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
                enabled: true,
                ..Default::default()
            });
        }
        let application = Arc::new(Application {
            database: database.clone(),
            mode,
            fixture: fixture.clone(),
        });
        let provider = OAuthProvider::gitlab_with_issuer(
            "fixture-social-client",
            "fixture-social-secret",
            &format!("{}/__test/social-provider/gitlab", config.base_url),
        );
        let mut builder = AuthBuilder::<TestSchema>::new(settings.clone())
            .store(
                crate::backend::store::<TestSchema>(settings, database.clone())
                    .with_hooks(vec![Arc::new(Hooks { mode })]),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(OAuthPlugin::new().add_provider("gitlab", provider))
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                identity: Some(application.clone()),
                on_link_account: Some(application.clone()),
                disable_delete_anonymous_user: mode == "disabled" || mode == "recovery-disabled",
                ..Default::default()
            }));
        if mode.ends_with("methods") {
            builder = builder
                .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                    send_magic_link: Some(application.clone()),
                    ..Default::default()
                }))
                .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                    send_verification_otp: Some(application.clone()),
                    ..Default::default()
                }))
                .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                    send_otp: Some(application.clone()),
                    sign_up_on_verification: Some(application.clone()),
                    ..Default::default()
                }))
                .plugin(
                    EmailVerificationPlugin::new()
                        .send_on_sign_up(false)
                        .auto_sign_in_after_verification(true)
                        .custom_send_verification_email(application),
                )
                .plugin(PasskeyPlugin::new())
                .plugin(OneTapPlugin::with_config(OneTapConfig {
                    client_id: Some(OneTapClientId::Single("one-tap-plugin-client".into())),
                    jwks_source: Some(crate::fixtures::one_tap_fixture::local_keys(
                        &config.base_url,
                    )),
                    ..Default::default()
                }));
        }
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let controls = Arc::new(crate::backend::store::<TestSchema>(
        config.clone(),
        database.clone(),
    ));
    router = router.route(
        "/__test/anonymous/prepare",
        post(move |Json(value): Json<Value>| {
            let controls = controls.clone();
            async move {
                use better_auth_core::store::{AccountStore, SessionStore};
                let user_id = value["userId"]
                    .as_str()
                    .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
                if value["expireOriginal"].as_bool() == Some(true)
                    || value["expireAll"].as_bool() == Some(true)
                {
                    for session in controls
                        .get_user_sessions(user_id)
                        .await
                        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
                    {
                        controls
                            .update_session_expiry(
                                session.token().as_ref(),
                                Utc::now() - chrono::Duration::seconds(60),
                            )
                            .await
                            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                    }
                }
                if value["expireAll"].as_bool() == Some(true) {
                    return Ok::<_, axum::http::StatusCode>(Json(json!({"success":true})));
                }
                for (seconds, agent) in [
                    (-60, "historical"),
                    (86400, "recovery-first"),
                    (172800, "recovery-second"),
                ] {
                    controls
                        .create_session(CreateSession {
                            additional_fields: Default::default(),
                            token: None,
                            user_id: user_id.into(),
                            expires_at: Utc::now() + chrono::Duration::seconds(seconds),
                            ip_address: Some(String::new()),
                            user_agent: Some(agent.into()),
                            impersonated_by: None,
                            active_organization_id: None,
                            active_team_id: None,
                        })
                        .await
                        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                }
                controls
                    .create_account(better_auth_core::CreateAccount {
                        additional_fields: Default::default(),
                        user_id: user_id.into(),
                        account_id: "anonymous-application-account".into(),
                        provider_id: "fixture-application".into(),
                        access_token: None,
                        refresh_token: None,
                        id_token: None,
                        access_token_expires_at: None,
                        refresh_token_expires_at: None,
                        scope: None,
                        password: None,
                    })
                    .await
                    .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok::<_, axum::http::StatusCode>(Json(json!({"success":true})))
            }
        }),
    );
    let delivery = fixture.clone();
    router = router.route(
        "/__test/anonymous/delivery",
        get(move |Query(query): Query<HashMap<String, String>>| {
            let delivery = delivery.clone();
            async move {
                Json(
                    query
                        .get("key")
                        .and_then(|key| {
                            delivery
                                .deliveries
                                .lock()
                                .expect("anonymous delivery lock")
                                .get(key)
                                .cloned()
                        })
                        .unwrap_or(Value::Null),
                )
            }
        }),
    );
    let observer = fixture.clone();
    router = router.route("/__test/anonymous/state", get(move || {
        let database = database.clone(); let observer = observer.clone(); async move {
            let users = crate::backend::rows::<ApplicationUser>(&database, "SELECT * FROM users ORDER BY created_at ASC", vec![]).await;
            let accounts = account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&database).await;
            let sessions = session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&database).await;
            match (users, accounts, sessions) {
                (Ok(users), Ok(accounts), Ok(sessions)) => Ok(Json(json!({
                    "users": users.into_iter().map(|row| json!({"id":row.id,"name":row.name,"email":row.email,"emailVerified":row.email_verified,"image":row.image,"isAnonymous":row.is_anonymous.unwrap_or(false),"cargoLabel":row.cargo_label,"cargoHidden":row.cargo_hidden,"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
                    "accounts": accounts.into_iter().map(|row| json!({"id":row.id,"userId":row.user_id,"accountId":row.account_id,"providerId":row.provider_id,"accessToken":row.access_token,"refreshToken":row.refresh_token,"idToken":row.id_token,"scope":row.scope,"accessTokenExpiresAt":row.access_token_expires_at.map(date),"refreshTokenExpiresAt":row.refresh_token_expires_at.map(date),"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
                    "sessions": sessions.into_iter().map(|row| json!({"id":row.id,"userId":row.user_id,"token":row.token,"expiresAt":date(row.expires_at),"createdAt":date(row.created_at),"updatedAt":date(row.updated_at),"ipAddress":row.ip_address,"userAgent":row.user_agent})).collect::<Vec<_>>(),
                    "events": observer.events.lock().expect("anonymous receipt lock").clone(),
                }))),
                _ => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }));
    Ok((router, fixture))
}
