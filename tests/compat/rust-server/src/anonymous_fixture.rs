//! Application-owned anonymous identity/link handlers and actual stored-state observer.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, extract::Query, routing::get};
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
    DatabaseConnection, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Statement},
    store::entities::{account, session, user},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
pub(super) struct Fixture {
    sequence: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<Value>>>,
    deliveries: Arc<Mutex<HashMap<String, Value>>>,
}
impl Fixture {
    pub(super) fn reset(&self) {
        self.sequence.store(0, Ordering::SeqCst);
        self.events.lock().expect("anonymous receipt lock").clear();
        self.deliveries
            .lock()
            .expect("anonymous delivery lock")
            .clear();
    }
}
struct Application {
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
        if self.mode == "link-error" {
            return Err(AuthError::Api {
                status: 403,
                code: Some("APPLICATION_LINK_DENIED".into()),
                message: "Configured anonymous transfer denied".into(),
            });
        }
        Ok(())
    }
}
struct Hooks {
    mode: &'static str,
}
#[async_trait]
impl SeaOrmHooks<TestSchema> for Hooks {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        context: &SeaOrmHookContext<'_>,
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
        context: &SeaOrmHookContext<'_>,
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
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.mode == "snapshot"
            && context
                .request
                .as_ref()
                .is_some_and(|request| request.path == "/sign-up/email")
        {
            context
                .db
                .execute_raw(Statement::from_sql_and_values(
                    context.db.get_database_backend(),
                    "UPDATE users SET name=? WHERE id=?",
                    [
                        "Stored Hook Name".into(),
                        session.user_id().into_owned().into(),
                    ],
                ))
                .await
                .map_err(|error| {
                    AuthError::Database(better_auth_core::DatabaseError::Query(error.to_string()))
                })?;
        }
        Ok(())
    }
}
fn date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}
pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
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
    ] {
        let path = format!("/__test/profiles/anonymous-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let application = Arc::new(Application {
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
                SeaOrmStore::<TestSchema>::new(settings, database.clone())
                    .with_hooks(vec![Arc::new(Hooks { mode })]),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(OAuthPlugin::new().add_provider("gitlab", provider))
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                identity: Some(application.clone()),
                on_link_account: Some(application.clone()),
                disable_delete_anonymous_user: mode == "disabled",
                ..Default::default()
            }));
        if mode == "methods" {
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
                    jwks_source: Some(crate::one_tap_fixture::local_keys(&config.base_url)),
                    ..Default::default()
                }));
        }
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
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
            let users = user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&database).await;
            let accounts = account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&database).await;
            let sessions = session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&database).await;
            match (users, accounts, sessions) {
                (Ok(users), Ok(accounts), Ok(sessions)) => Ok(Json(json!({
                    "users": users.into_iter().map(|row| json!({"id":row.id,"name":row.name,"email":row.email,"emailVerified":row.email_verified,"image":row.image,"isAnonymous":row.is_anonymous.unwrap_or(false),"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
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
