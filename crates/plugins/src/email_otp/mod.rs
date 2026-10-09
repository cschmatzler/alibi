//! Passwordless email authentication and verification using single-use codes.
//!
//! [`EmailOtpPlugin::create_verification_otp`] and
//! [`EmailOtpPlugin::get_verification_otp`] are server-only operations. Neither
//! operation registers an HTTP endpoint.

mod endpoint;
mod handlers;

mod helpers;

mod storage;

mod types;

use alibi_core::AuthError;
use alibi_core::{AuthContext, AuthRequest, AuthResponse, AuthResult};
use async_trait::async_trait;
pub use endpoint::EmailOtpRead;
use std::sync::Arc;
pub use storage::{EmailOtpCodec, EmailOtpStorage};
pub use types::{EmailOtpDelivery, EmailOtpType, OtpResendStrategy};

/// Delivers a code to its intended mailbox with the real native callback context.
/// Delivery awaits and propagates errors by default; configured background work
/// owns its context and logs failures while retaining the issued verification.
#[async_trait]
pub trait SendEmailOtp: Send + Sync {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        context: &alibi_core::CallbackContext,
    ) -> AuthResult<()>;
}

/// Optional application code generator. Returning `None` selects the default
/// cryptographically random numeric generator.
#[async_trait]
pub trait EmailOtpGenerator: Send + Sync {
    async fn generate(
        &self,
        email: &str,
        otp_type: EmailOtpType,
        context: &alibi_core::CallbackContext,
    ) -> AuthResult<Option<String>>;
}

/// Configuration for email OTP verification, login, password reset and email change.
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct EmailOtpConfig {
    pub send_verification_otp: Option<Arc<dyn SendEmailOtp>>,
    pub generate_otp: Option<Arc<dyn EmailOtpGenerator>>,
    /// Raw numeric length. Safe positive fractions round up; NaN generates an
    /// empty code. Nonpositive and resource-unsafe lengths fail generation.
    pub otp_length: f64,
    /// Lifetime in seconds. Fractions retain JavaScript millisecond rounding;
    /// invalid dates fail before persistence.
    pub expires_in: f64,
    /// Raw attempt budget compared with the persisted integer counter. Zero and
    /// NaN use three; negative values reject even an unused proof.
    pub allowed_attempts: f64,
    pub rate_limit: alibi_core::EndpointRateLimit,
    pub storage: EmailOtpStorage,
    pub resend_strategy: OtpResendStrategy,
    pub disable_sign_up: bool,
    pub send_verification_on_sign_up: bool,
    pub override_default_email_verification: bool,
    pub change_email_enabled: bool,
    pub verify_current_email: bool,
    pub auto_sign_in_after_verification: bool,
    pub before_email_verification: Option<super::email_verification::EmailVerificationHook>,
    pub after_email_verification: Option<super::email_verification::EmailVerificationHook>,
    pub password_hasher: Option<Arc<dyn alibi_core::PasswordHasher>>,
    pub revoke_sessions_on_password_reset: bool,
    pub on_password_reset: Option<Arc<super::password_management::OnPasswordResetCallback>>,
}

impl std::fmt::Debug for EmailOtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpConfig").finish_non_exhaustive()
    }
}

impl Default for EmailOtpConfig {
    fn default() -> Self {
        Self {
            send_verification_otp: None,
            generate_otp: None,
            otp_length: 6.0,
            expires_in: 300.0,
            allowed_attempts: 3.0,
            rate_limit: alibi_core::EndpointRateLimit {
                window_seconds: 60.0,
                max_requests: 3.0,
            },
            storage: EmailOtpStorage::Plain,
            resend_strategy: OtpResendStrategy::Rotate,
            disable_sign_up: false,
            send_verification_on_sign_up: false,
            override_default_email_verification: false,
            change_email_enabled: false,
            verify_current_email: false,
            auto_sign_in_after_verification: false,
            before_email_verification: None,
            after_email_verification: None,
            password_hasher: None,
            revoke_sessions_on_password_reset: false,
            on_password_reset: None,
        }
    }
}

#[derive(Clone)]
pub struct EmailOtpPlugin {
    config: EmailOtpConfig,
}

impl std::fmt::Debug for EmailOtpPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpPlugin").finish_non_exhaustive()
    }
}

impl EmailOtpPlugin {
    #[must_use]
    pub const fn new(config: EmailOtpConfig) -> Self {
        Self { config }
    }

    fn verification_settings(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> VerificationSettings {
        let inherited = ctx
            .extensions
            .get::<super::email_verification::EmailVerificationConfig>();
        VerificationSettings {
            before: inherited
                .as_ref()
                .and_then(|config| config.before_email_verification.clone())
                .or_else(|| self.config.before_email_verification.clone()),
            after: inherited
                .as_ref()
                .and_then(|config| config.after_email_verification.clone())
                .or_else(|| self.config.after_email_verification.clone()),
            auto_sign_in: inherited
                .as_ref()
                .is_some_and(|config| config.auto_sign_in_after_verification)
                || self.config.auto_sign_in_after_verification,
        }
    }

    fn password_settings(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> PasswordSettings {
        let passwords = ctx
            .extensions
            .get::<super::email_password::EmailPasswordConfig>();
        let resets = ctx
            .extensions
            .get::<super::password_management::PasswordManagementConfig>();
        let (minimum, maximum) = super::email_password::password_length_limits(ctx);
        PasswordSettings {
            minimum,
            maximum,
            hasher: resets
                .as_ref()
                .and_then(|config| config.password_hasher.clone())
                .or_else(|| {
                    let config = passwords.as_ref()?;
                    config.password_hasher.clone()
                })
                .or_else(|| self.config.password_hasher.clone()),
            on_reset: resets
                .as_ref()
                .and_then(|config| config.on_password_reset.clone())
                .or_else(|| self.config.on_password_reset.clone()),
            revoke_sessions: resets
                .as_ref()
                .is_some_and(|config| config.revoke_sessions_on_password_reset)
                || self.config.revoke_sessions_on_password_reset,
        }
    }

    /// Create and persist a code without delivering it or checking whether the
    /// mailbox has an account. This operation is available only to server code.
    ///
    /// # Errors
    ///
    /// Returns an error if OTP generation, encoding, or persistence fails.
    pub async fn create_verification_otp(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        email: &str,
        otp_type: EmailOtpType,
    ) -> AuthResult<String> {
        self.issue_code(ctx, None, &email.to_lowercase(), otp_type, None)
            .await
    }

    /// Retrieve a live plaintext/decryptable code without consuming it.
    /// Hashed storage rejects this operation, since a hash cannot reveal a code.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or the configured OTP representation cannot be recovered.
    pub async fn get_verification_otp(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        email: &str,
        otp_type: EmailOtpType,
    ) -> AuthResult<Option<String>> {
        let identifier = types::identifier(otp_type, &email.to_lowercase());
        let Some(value) =
            super::authentication_helpers::find_verification(ctx, &identifier).await?
        else {
            return Ok(None);
        };
        if value.is_expired() {
            return Ok(None);
        }
        let (stored, _) = types::split_value(value.value()?);
        self.config
            .storage
            .retrieve(stored, &ctx.config)
            .await
            .map_err(|error| match error {
                error if error.status_code() != 500 => error,
                AuthError::Api { .. }
                | AuthError::Upstream { .. }
                | AuthError::CallbackFailure(_) => error,
                error => AuthError::CallbackFailure(Box::new(error)),
            })
    }
}

struct VerificationSettings {
    before: Option<super::email_verification::EmailVerificationHook>,
    after: Option<super::email_verification::EmailVerificationHook>,
    auto_sign_in: bool,
}

struct PasswordSettings {
    minimum: usize,
    maximum: usize,
    hasher: Option<Arc<dyn alibi_core::PasswordHasher>>,
    on_reset: Option<Arc<super::password_management::OnPasswordResetCallback>>,
    revoke_sessions: bool,
}

alibi_core::impl_auth_plugin! {
    EmailOtpPlugin, "email-otp";
    routes {
        post "/email-otp/send-verification-otp" => send_verification, "sendEmailVerificationOTP";
        post "/email-otp/check-verification-otp" => check_verification, "verifyEmailWithOTP";
        post "/email-otp/verify-email" => verify_email, "verifyEmailOTP";
        post "/sign-in/email-otp" => sign_in, "signInWithEmailOTP";
        post "/email-otp/request-password-reset" => request_password_reset, "requestPasswordResetWithEmailOTP";
        post "/forget-password/email-otp" => request_password_reset, "forgetPasswordWithEmailOTP";
        post "/email-otp/reset-password" => reset_password, "resetPasswordWithEmailOTP";
        post "/email-otp/request-email-change" => request_email_change, "requestEmailChangeWithEmailOTP";
        post "/email-otp/change-email" => change_email, "changeEmailWithEmailOTP";
    }
    extra {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx)
    }

        fn rate_limits(&self) -> Vec<alibi_core::PluginRateLimit> {
            vec![alibi_core::PluginRateLimit { matches: |path| matches!(path, "/email-otp/send-verification-otp" | "/email-otp/check-verification-otp" | "/email-otp/verify-email" | "/sign-in/email-otp" | "/email-otp/request-password-reset" | "/email-otp/reset-password" | "/forget-password/email-otp" | "/email-otp/request-email-change" | "/email-otp/change-email"), limit: alibi_core::EndpointRateLimit {
                window_seconds: if self.config.rate_limit.window_seconds == 0.0 || self.config.rate_limit.window_seconds.is_nan() { 60.0 } else { self.config.rate_limit.window_seconds },
                max_requests: if self.config.rate_limit.max_requests == 0.0 || self.config.rate_limit.max_requests.is_nan() { 3.0 } else { self.config.rate_limit.max_requests },
            } }]
        }
        fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> { endpoint::definitions() }

        fn validate_endpoint(&self, call: &alibi_core::endpoint::EndpointCall, _ctx: &AuthContext<S>) -> AuthResult<alibi_core::endpoint::EndpointInput> { endpoint::validate(call) }

        async fn on_endpoint(&self, call: &alibi_core::endpoint::EndpointCall, ctx: &AuthContext<S>) -> AuthResult<alibi_core::endpoint::EndpointResponse> { self.call_endpoint(call, ctx).await }

        async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
            ctx.set_metadata("email-otp.enabled", serde_json::json!(true));
            if self.config.override_default_email_verification {
                ctx.set_email_verification_override(Arc::new(self.clone()));
            }
            Ok(())
        }

        async fn after_request(
            &self,
            req: &AuthRequest,
            ctx: &AuthContext<S>,
            response: AuthResponse,
        ) -> AuthResult<AuthResponse> {
            if response.status < 400 && req.path().starts_with("/sign-up")
                && self.config.send_verification_on_sign_up
                && !self.config.override_default_email_verification
            {
                let value: serde_json::Value = serde_json::from_slice(&response.body)?;
                if let Some(email) = value.get("user").and_then(|user| user.get("email")).and_then(serde_json::Value::as_str) {
                    let otp = self.issue_code(ctx, Some(req), email, EmailOtpType::EmailVerification, None).await?;
                    self.deliver(ctx, Some(req), email, otp, EmailOtpType::EmailVerification).await?;
                }
            }
            Ok(response)
        }
    }
}

#[async_trait]
impl<S: alibi_core::AuthSchema> alibi_core::VerificationEmailOverride<S> for EmailOtpPlugin {
    async fn send(
        &self,
        user: &alibi_core::wire::UserView,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        let Some(email) = user.email.as_deref() else {
            return Ok(());
        };
        let body = serde_json::json!({"email":email,"type":"email-verification"});
        let mut req = AuthRequest::new(
            alibi_core::HttpMethod::Post,
            "/email-otp/send-verification-otp",
        );
        req.body = Some(serde_json::to_vec(&body)?);
        _ = self
            .send_verification_with_request(&req, request, ctx)
            .await?;
        Ok(())
    }

    async fn send_in_transaction(
        &self,
        user: &alibi_core::wire::UserView,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        tx: &dyn alibi_core::store::AuthTransaction<S>,
    ) -> AuthResult<()> {
        let Some(email) = user.email.as_deref() else {
            return Ok(());
        };
        let email = crate::authentication_helpers::parse_email(email)?;
        let (otp, value) = self
            .prepare_code(ctx, request, &email, EmailOtpType::EmailVerification, None)
            .await?;
        _ = ctx.verifications().create_in_transaction(tx, value).await?;
        self.deliver(ctx, request, &email, otp, EmailOtpType::EmailVerification)
            .await
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{self, create_auth_json_request_no_query};
    use alibi_core::{
        AuthError, AuthPlugin, AuthSession, AuthUser, AuthVerification, CreateAccount, CreateUser,
        CreateVerification, HttpMethod,
    };
    use chrono::Duration;
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Outbox(Mutex<Vec<EmailOtpDelivery>>);

    #[async_trait]
    impl SendEmailOtp for Outbox {
        async fn send(
            &self,
            delivery: &EmailOtpDelivery,
            _context: &alibi_core::CallbackContext,
        ) -> AuthResult<()> {
            self.0.lock().unwrap().push(delivery.clone());
            Ok(())
        }
    }

    struct RejectingSender(Arc<Outbox>, bool);

    #[async_trait]
    impl SendEmailOtp for RejectingSender {
        async fn send(
            &self,
            delivery: &EmailOtpDelivery,
            _context: &alibi_core::CallbackContext,
        ) -> AuthResult<()> {
            self.0.0.lock().unwrap().push(delivery.clone());
            if self.1 {
                Err(AuthError::Upstream {
                    status: 409,
                    code: "DELIVERY_REJECTED",
                    message: "fixture delivery failed",
                })
            } else {
                Err(AuthError::bad_request("fixture delivery failed"))
            }
        }
    }

    struct CounterGenerator(AtomicUsize);

    #[async_trait]
    impl EmailOtpGenerator for CounterGenerator {
        async fn generate(
            &self,
            _: &str,
            _: EmailOtpType,
            _: &alibi_core::CallbackContext,
        ) -> AuthResult<Option<String>> {
            Ok(Some(format!(
                "{:06}",
                self.0.fetch_add(1, Ordering::SeqCst) + 100_000
            )))
        }
    }

    struct CancelVerificationUpdate(Arc<AtomicUsize>);

    #[async_trait]
    impl
        alibi_seaorm::DatabaseHooks<
            alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
            alibi_seaorm::SeaOrmBackend,
        > for CancelVerificationUpdate
    {
        async fn before_update_verification(
            &self,
            _: &str,
            _: &mut alibi_core::UpdateVerification,
            _: &alibi_seaorm::SeaOrmHookContext<'_>,
        ) -> AuthResult<alibi_seaorm::HookControl> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(alibi_seaorm::HookControl::Cancel)
        }
    }

    fn configured() -> (EmailOtpConfig, Arc<Outbox>) {
        let outbox = Arc::new(Outbox::default());
        (
            EmailOtpConfig {
                send_verification_otp: Some(Arc::<Outbox>::clone(&outbox)),
                generate_otp: Some(Arc::new(CounterGenerator(AtomicUsize::new(0)))),
                ..Default::default()
            },
            outbox,
        )
    }

    async fn post(
        plugin: &EmailOtpPlugin,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        path: &str,
        body: Value,
    ) -> AuthResponse {
        let req = create_auth_json_request_no_query(HttpMethod::Post, path, None, Some(body));
        match plugin.on_request(&req, ctx).await {
            Ok(Some(response)) => response,
            Ok(None) => AuthResponse::text(404, "missing test route"),
            Err(error) => error.to_auth_response(),
        }
    }

    // The pinned endpoint awaits runInBackgroundOrAwait: a rejected notification
    // leaves its real proof available and does not replace the successful response.
    #[tokio::test]
    async fn notification_failure_retains_the_issued_otp_for_single_use_signin() {
        for (policy, coded) in [
            (alibi_core::AwaitedNotificationErrorPolicy::Propagate, false),
            (alibi_core::AwaitedNotificationErrorPolicy::Propagate, true),
            (
                alibi_core::AwaitedNotificationErrorPolicy::LogAndContinue,
                false,
            ),
            (
                alibi_core::AwaitedNotificationErrorPolicy::LogAndContinue,
                true,
            ),
        ] {
            let mut ctx = test_helpers::create_test_context().await;
            ctx.config = Arc::new((*ctx.config).clone().awaited_notification_errors(policy));
            let (mut config, outbox) = configured();
            config.send_verification_otp = Some(Arc::new(RejectingSender(
                Arc::<Outbox>::clone(&outbox),
                coded,
            )));
            let plugin = EmailOtpPlugin::new(config);
            let email = "delivery-failure@fixture.test";
            let issued = post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                json!({"email":email,"type":"sign-in"}),
            )
            .await;
            if policy == alibi_core::AwaitedNotificationErrorPolicy::Propagate {
                assert_eq!(issued.status, if coded { 409 } else { 400 });
                if coded {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&issued.body)
                            .unwrap()
                            .get("code")
                            .and_then(Value::as_str),
                        Some("DELIVERY_REJECTED")
                    );
                }
            } else {
                assert_eq!(issued.status, 200);
                assert_eq!(
                    serde_json::from_slice::<Value>(&issued.body).unwrap(),
                    json!({"success":true})
                );
            }
            let delivery = outbox.0.lock().unwrap().first().unwrap().clone();
            assert_eq!(delivery.email, email);
            let identifier = format!("sign-in-otp-{email}");
            let proof = ctx
                .database
                .get_latest_verification_by_identifier(&identifier)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.value(), format!("{}:0", delivery.otp));
            assert!(
                ctx.database
                    .get_user_by_email(email)
                    .await
                    .unwrap()
                    .is_none()
            );
            let received = post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":email,"otp":delivery.otp}),
            )
            .await;
            assert_eq!(received.status, 200);
            let user = ctx
                .database
                .get_user_by_email(email)
                .await
                .unwrap()
                .unwrap();
            assert!(user.email_verified());
            assert_eq!(
                ctx.database
                    .get_user_sessions(&user.id())
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                ctx.database
                    .get_latest_verification_by_identifier(&identifier)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                post(
                    &plugin,
                    &ctx,
                    "/sign-in/email-otp",
                    json!({"email":email,"otp":delivery.otp})
                )
                .await
                .status,
                400
            );
            assert_eq!(outbox.0.lock().unwrap().len(), 1);
        }
    }

    // Upstream checkVerificationOTP rejects once when a database update hook
    // returns false. Hook cancellation must not be retried as CAS contention.
    #[tokio::test]
    async fn cancelled_attempt_update_rejects_once_without_hanging_or_consuming_proof() {
        use alibi_seaorm::store::__private_test_support::{
            bundled_schema::BundledSchema, migrator,
        };
        use alibi_seaorm::{Database, SeaOrmStore};
        let config = Arc::new(test_helpers::create_test_config());
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(
            SeaOrmStore::<BundledSchema>::new(Arc::clone(&config), database)
                .hook(CancelVerificationUpdate(Arc::clone(&calls))),
        );
        let ctx = AuthContext::new(config, store);
        _ = ctx
            .database
            .create_user(CreateUser::new().with_email("veto@example.com"))
            .await
            .unwrap();
        let (config_2, _) = configured();
        let plugin = EmailOtpPlugin::new(config_2);
        let otp = plugin
            .create_verification_otp(&ctx, "veto@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        let identifier = "email-verification-otp-veto@example.com";
        let before = ctx
            .database
            .get_latest_verification_by_identifier(identifier)
            .await
            .unwrap()
            .unwrap();
        let rejected = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            post(
                &plugin,
                &ctx,
                "/email-otp/check-verification-otp",
                json!({"email":"veto@example.com","type":"email-verification","otp":"incorrect"}),
            ),
        )
        .await
        .expect("A cancelled attempt update must return rather than retry forever");
        assert_eq!(rejected.status, 400);
        assert_eq!(
            serde_json::from_slice::<Value>(&rejected.body).unwrap(),
            json!({"code":"INVALID_OTP","message":"Invalid OTP"})
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let after = ctx
            .database
            .get_latest_verification_by_identifier(identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.id(), before.id());
        assert_eq!(after.value(), before.value());
        assert_eq!(after.expires_at(), before.expires_at());
        let accepted = post(
            &plugin,
            &ctx,
            "/email-otp/check-verification-otp",
            json!({"email":"veto@example.com","type":"email-verification","otp":otp}),
        )
        .await;
        assert_eq!(accepted.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&accepted.body).unwrap(),
            json!({"success":true})
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // Upstream: email-otp/routes.ts :: sendVerificationOTP anti-enumeration branch.
    #[tokio::test]
    async fn unknown_verification_and_reset_mailboxes_leave_no_code_or_delivery() {
        let ctx = test_helpers::create_test_context().await;
        let (config, outbox) = configured();
        let plugin = EmailOtpPlugin::new(config);
        for otp_type in [
            EmailOtpType::EmailVerification,
            EmailOtpType::ForgetPassword,
        ] {
            let response = post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                json!({"email":"missing@example.com","type":otp_type}),
            )
            .await;
            assert_eq!(response.status, 200);
            assert!(
                ctx.database
                    .get_latest_verification_by_identifier(&types::identifier(
                        otp_type,
                        "missing@example.com"
                    ))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(outbox.0.lock().unwrap().is_empty());
    }

    // Upstream: email-otp/routes.ts :: signInEmailOTP + atomicVerifyOTP.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn sign_in_creates_verified_user_and_owned_session_then_rejects_replay() {
        use alibi_core::utils::cookie_utils::{
            related_cookie_name, sign_cookie_value, verify_cookie_value,
        };

        for lifetime in [604_800, 90] {
            for (preference, persistent) in [
                (None, true),
                (Some(""), true),
                (Some("false"), false),
                (Some("true"), false),
            ] {
                let mut auth_config = test_helpers::create_test_config();
                auth_config.session.expires_in = Duration::seconds(lifetime);
                auth_config.session.cookie_name = "otp-fixture.session_token".to_owned();
                let ctx = test_helpers::create_test_context_with_config(auth_config).await;
                let (config, outbox) = configured();
                let plugin = EmailOtpPlugin::new(config);
                assert_eq!(
                    post(
                        &plugin,
                        &ctx,
                        "/email-otp/send-verification-otp",
                        json!({"email":"Owner@Example.com","type":"sign-in"})
                    )
                    .await
                    .status,
                    200
                );
                let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
                assert_eq!(delivery.email, "owner@example.com");
                let body =
                    json!({"email":"OWNER@example.com","otp":delivery.otp,"name":"Mailbox Owner"});
                let mut request = create_auth_json_request_no_query(
                    HttpMethod::Post,
                    "/sign-in/email-otp",
                    None,
                    Some(body.clone()),
                );
                if let Some(value) = preference {
                    _ = request.headers.insert(
                        "cookie".to_owned(),
                        format!(
                            "{}={}",
                            related_cookie_name(&ctx.config, "dont_remember"),
                            sign_cookie_value(value, &ctx.config.secret)
                        ),
                    );
                }
                let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
                assert_eq!(response.status, 200);
                let payload: Value = serde_json::from_slice(&response.body).unwrap();
                let token = payload.get("token").and_then(Value::as_str).unwrap();
                let user = ctx
                    .database
                    .get_user_by_email("owner@example.com")
                    .await
                    .unwrap()
                    .unwrap();
                assert!(user.email_verified());
                assert_eq!(user.name(), Some("Mailbox Owner"));
                let session = ctx.database.get_session(token).await.unwrap().unwrap();
                assert_eq!(session.user_id(), user.id());
                assert!(
                    ((session.expires_at() - session.created_at()).num_milliseconds()
                        - lifetime * 1_000)
                        .abs()
                        < 1_000,
                    "preference {preference:?} must preserve the configured persisted session lifetime",
                );
                let cookies = response
                    .headers
                    .get_all("set-cookie")
                    .map(|header| cookie::Cookie::parse(header.clone()).unwrap())
                    .collect::<Vec<_>>();
                let session_cookie = cookies
                    .iter()
                    .find(|cookie| cookie.name() == "otp-fixture.session_token")
                    .unwrap();
                assert_eq!(
                    session_cookie
                        .max_age()
                        .map(cookie::time::Duration::whole_seconds),
                    persistent.then_some(lifetime),
                    "signed preference {preference:?}, configured lifetime {lifetime}",
                );
                assert_eq!(session_cookie.http_only(), Some(true));
                assert_eq!(session_cookie.path(), Some("/"));
                assert_eq!(
                    verify_cookie_value(session_cookie.value(), &ctx.config.secret).as_deref(),
                    Some(token)
                );
                let preference_cookie = cookies
                    .iter()
                    .find(|cookie| cookie.name() == "otp-fixture.dont_remember");
                assert_eq!(preference_cookie.is_some(), !persistent);
                if let Some(cookie) = preference_cookie {
                    assert_eq!(
                        verify_cookie_value(cookie.value(), &ctx.config.secret).as_deref(),
                        Some("true")
                    );
                    assert_eq!(cookie.max_age(), None);
                    assert_eq!(cookie.http_only(), Some(true));
                }
                assert!(
                    ctx.database
                        .get_latest_verification_by_identifier("sign-in-otp-owner@example.com")
                        .await
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    post(&plugin, &ctx, "/sign-in/email-otp", body).await.status,
                    400
                );
            }
        }
    }

    // Upstream: atomicVerifyOTP attempt count is enforced before code validation.
    #[tokio::test]
    async fn invalid_attempts_preserve_deadline_and_exhaust_the_budget() {
        let ctx = test_helpers::create_test_context().await;
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        let code = plugin
            .create_verification_otp(&ctx, "attempts@example.com", EmailOtpType::SignIn)
            .await
            .unwrap();
        let key = "sign-in-otp-attempts@example.com";
        let original = ctx
            .database
            .get_latest_verification_by_identifier(key)
            .await
            .unwrap()
            .unwrap();
        for attempts in 1..=3 {
            let response = post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":"attempts@example.com","otp":"wrong"}),
            )
            .await;
            assert_eq!(response.status, 400);
            let value = ctx
                .database
                .get_latest_verification_by_identifier(key)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(value.expires_at(), original.expires_at());
            assert_eq!(types::split_value(value.value()).1, attempts);
        }
        let response = post(
            &plugin,
            &ctx,
            "/sign-in/email-otp",
            json!({"email":"attempts@example.com","otp":code}),
        )
        .await;
        assert_eq!(response.status, 403);
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(key)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_user_by_email("attempts@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: checkVerificationOTP is non-consuming; verifyEmailOTP consumes.
    #[tokio::test]
    async fn checking_does_not_verify_or_consume_then_verification_persists_state() {
        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("verify@example.com"))
            .await
            .unwrap();
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        let otp = plugin
            .create_verification_otp(&ctx, "verify@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/check-verification-otp",
                json!({"email":"verify@example.com","type":"email-verification","otp":otp})
            )
            .await
            .status,
            200
        );
        assert!(
            !ctx.database
                .get_user_by_id(&user.id())
                .await
                .unwrap()
                .unwrap()
                .email_verified()
        );
        assert!(
            plugin
                .get_verification_otp(&ctx, "verify@example.com", EmailOtpType::EmailVerification)
                .await
                .unwrap()
                .is_some()
        );
        let response = post(
            &plugin,
            &ctx,
            "/email-otp/verify-email",
            json!({"email":"verify@example.com","otp":otp}),
        )
        .await;
        assert_eq!(response.status, 200);
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(payload.get("token"), Some(&Value::Null));
        assert!(
            ctx.database
                .get_user_by_id(&user.id())
                .await
                .unwrap()
                .unwrap()
                .email_verified()
        );
        assert!(
            plugin
                .get_verification_otp(&ctx, "verify@example.com", EmailOtpType::EmailVerification)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: expired code has a distinct error and is removed before consuming.
    #[tokio::test]
    async fn expired_and_cross_scope_codes_cannot_authenticate() {
        let ctx = test_helpers::create_test_context().await;
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: "sign-in-otp-expired@example.com".into(),
                value: "654321:0".into(),
                expires_at: chrono::Utc::now() - Duration::seconds(1),
            })
            .await
            .unwrap();
        let expired = post(
            &plugin,
            &ctx,
            "/sign-in/email-otp",
            json!({"email":"expired@example.com","otp":"654321"}),
        )
        .await;
        let payload: Value = serde_json::from_slice(&expired.body).unwrap();
        assert_eq!(
            payload.get("code").and_then(Value::as_str),
            Some("OTP_EXPIRED")
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier("sign-in-otp-expired@example.com")
                .await
                .unwrap()
                .is_none()
        );
        let code = plugin
            .create_verification_otp(
                &ctx,
                "wrong-scope@example.com",
                EmailOtpType::EmailVerification,
            )
            .await
            .unwrap();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":"wrong-scope@example.com","otp":code})
            )
            .await
            .status,
            400
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":"foreign@example.com","otp":code})
            )
            .await
            .status,
            400
        );
        assert!(
            ctx.database
                .get_user_by_email("wrong-scope@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: a mailbox proof promotes an unverified row only after deleting
    // every standing account/session that predates proof of ownership.
    #[tokio::test]
    async fn existing_unverified_account_loses_password_oauth_and_old_sessions() {
        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("promote@example.com"))
            .await
            .unwrap();
        for provider in ["credential", "google"] {
            _ = ctx
                .database
                .create_account(CreateAccount {
                    additional_fields: alibi_core::field_policy::FieldValues::default(),
                    user_id: user.id().to_string(),
                    account_id: format!("{provider}-identity"),
                    provider_id: provider.into(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: (provider == "credential").then_some("old-password-hash".into()),
                })
                .await
                .unwrap();
        }
        let old_session = ctx
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        let otp = plugin
            .create_verification_otp(&ctx, "promote@example.com", EmailOtpType::SignIn)
            .await
            .unwrap();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":"promote@example.com","otp":otp})
            )
            .await
            .status,
            200
        );
        let promoted = ctx
            .database
            .get_user_by_id(&user.id())
            .await
            .unwrap()
            .unwrap();
        assert!(promoted.email_verified());
        assert_eq!(
            ctx.database
                .get_user_accounts(&user.id())
                .await
                .unwrap()
                .len(),
            0
        );
        assert!(
            ctx.database
                .get_session(old_session.token())
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: atomicVerifyOTP has exactly one successful concurrent consumer.
    #[tokio::test]
    async fn concurrent_sign_in_cannot_reuse_a_code() {
        let ctx = test_helpers::create_test_context().await;
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        let otp = plugin
            .create_verification_otp(&ctx, "race@example.com", EmailOtpType::SignIn)
            .await
            .unwrap();
        let body = json!({"email":"race@example.com","otp":otp});
        let (first, second) = tokio::join!(
            post(&plugin, &ctx, "/sign-in/email-otp", body.clone()),
            post(&plugin, &ctx, "/sign-in/email-otp", body)
        );
        let mut statuses = [first.status, second.status];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 400]);
    }

    // Upstream: parseUserInput ignores fields contributed by an absent plugin.
    // Persisted fields are checked because response projection alone can hide writes.
    #[tokio::test]
    async fn signup_ignores_unregistered_username_fields() {
        let ctx = test_helpers::create_test_context().await;
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        for (index, username, display) in [
            (0, json!("ab"), json!("Ignored Display")),
            (1, json!(7), json!({"unexpected":true})),
        ] {
            let email = format!("unregistered-{index}@example.com");
            let otp = plugin
                .create_verification_otp(&ctx, &email, EmailOtpType::SignIn)
                .await
                .unwrap();
            let response = post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":email,"otp":otp,"username":username,"displayUsername":display}),
            )
            .await;
            assert_eq!(
                response.status,
                200,
                "{}",
                String::from_utf8_lossy(&response.body)
            );
            let user = ctx
                .database
                .get_user_by_email(&email)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(user.username(), None);
            assert_eq!(user.display_username(), None);
            assert!(user.email_verified());
            assert_eq!(
                ctx.database
                    .get_user_sessions(&user.id())
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                ctx.database
                    .get_latest_verification_by_identifier(&format!("sign-in-otp-{email}"))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    // Upstream: reusable plain OTPs keep attempts and extend expiry; hashes cannot
    // recover a plaintext for delivery, and must therefore rotate even in reuse mode.
    #[tokio::test]
    async fn reuse_extends_existing_code_and_hashed_storage_rotates() {
        let ctx = test_helpers::create_test_context().await;
        let (mut config, outbox) = configured();
        config.resend_strategy = OtpResendStrategy::Reuse;
        let mut plugin = EmailOtpPlugin::new(config);
        let request = json!({"email":"reuse@example.com","type":"sign-in"});
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                request.clone()
            )
            .await
            .status,
            200
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                request.clone()
            )
            .await
            .status,
            200
        );
        let codes = outbox
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|delivery| delivery.otp.clone())
            .collect::<Vec<_>>();
        assert_eq!(codes.first(), codes.last());
        plugin.config.storage = EmailOtpStorage::Hashed;
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                request.clone()
            )
            .await
            .status,
            200
        );
        assert_eq!(
            post(&plugin, &ctx, "/email-otp/send-verification-otp", request)
                .await
                .status,
            200
        );
        let codes_2 = outbox
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|delivery| delivery.otp.clone())
            .collect::<Vec<_>>();
        assert_ne!(codes_2.get(2), codes_2.get(3));
        assert!(
            plugin
                .get_verification_otp(&ctx, "reuse@example.com", EmailOtpType::SignIn)
                .await
                .is_err()
        );
        let raw = ctx
            .database
            .get_latest_verification_by_identifier("sign-in-otp-reuse@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(!codes_2.iter().any(|code| raw.value().contains(code)));
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":"reuse@example.com","otp":codes_2.last().unwrap()})
            )
            .await
            .status,
            200
        );
    }

    // Upstream: change-email identifier binds both current and target mailboxes.
    #[tokio::test]
    async fn changing_email_rejects_another_users_code_and_keeps_current_session() {
        let ctx = test_helpers::create_test_context().await;
        let owner = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("owner@example.com")
                    .with_email_verified(true),
            )
            .await
            .unwrap();
        let stranger = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("stranger@example.com")
                    .with_email_verified(true),
            )
            .await
            .unwrap();
        let owner_session = ctx
            .session_manager()
            .create_session(&owner, None, None)
            .await
            .unwrap();
        let stranger_session = ctx
            .session_manager()
            .create_session(&stranger, None, None)
            .await
            .unwrap();
        let (mut config, outbox) = configured();
        config.change_email_enabled = true;
        let plugin = EmailOtpPlugin::new(config);
        let req = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/email-otp/request-email-change",
            Some(owner_session.token()),
            Some(json!({"newEmail":"target@example.com"})),
        );
        assert_eq!(
            plugin.on_request(&req, &ctx).await.unwrap().unwrap().status,
            200
        );
        let code = outbox.0.lock().unwrap().last().unwrap().otp.clone();
        let req_2 = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/email-otp/change-email",
            Some(stranger_session.token()),
            Some(json!({"newEmail":"target@example.com","otp":code})),
        );
        assert_eq!(
            plugin
                .on_request(&req_2, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&stranger.id())
                .await
                .unwrap()
                .unwrap()
                .email(),
            Some("stranger@example.com")
        );
        let req_3 = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/email-otp/change-email",
            Some(owner_session.token()),
            Some(json!({"newEmail":"target@example.com","otp":code})),
        );
        assert_eq!(
            plugin
                .on_request(&req_3, &ctx)
                .await
                .unwrap()
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&owner.id())
                .await
                .unwrap()
                .unwrap()
                .email(),
            Some("target@example.com")
        );
        assert_eq!(
            ctx.database
                .get_session(owner_session.token())
                .await
                .unwrap()
                .unwrap()
                .user_id(),
            owner.id()
        );
    }

    // Ciphertext produced by the installed 1.7.6 symmetricEncrypt runtime. This
    // proves the persistence encoding independently of our encryption round-trip.
    #[tokio::test]
    async fn encrypted_codec_reads_upstream_ciphertext_and_hides_plaintext() {
        let fixture = "89c516b9ba08b2f347ecf25375ca9524bca3e8c57ec3982eaf21996f87742a4a739b47adfce936e33fe71e424a45";
        let storage = EmailOtpStorage::Encrypted;
        assert_eq!(
            storage
                .retrieve(
                    fixture,
                    &alibi_core::AuthConfig::new("upstream-otp-codec-fixture-secret")
                )
                .await
                .unwrap(),
            Some("654321".into())
        );
        let encrypted = storage
            .store(
                "654321",
                &alibi_core::AuthConfig::new("upstream-otp-codec-fixture-secret"),
            )
            .await
            .unwrap();
        assert_ne!(encrypted, "654321");
        assert!(
            storage
                .verify(
                    &encrypted,
                    "654321",
                    &alibi_core::AuthConfig::new("upstream-otp-codec-fixture-secret")
                )
                .await
                .unwrap()
        );
        assert!(
            !storage
                .verify(
                    &encrypted,
                    "000000",
                    &alibi_core::AuthConfig::new("upstream-otp-codec-fixture-secret")
                )
                .await
                .unwrap()
        );
        assert!(
            storage
                .verify(
                    &encrypted,
                    "654321",
                    &alibi_core::AuthConfig::new("wrong-secret")
                )
                .await
                .is_err()
        );
    }

    // Upstream: password policy runs before consumption; reset callbacks see the
    // pre-verification user and configured session revocation applies afterward.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn reset_updates_password_runs_hook_and_revokes_owned_sessions() {
        use alibi_core::AuthAccount;
        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("reset@example.com"))
            .await
            .unwrap();
        let session = ctx
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let account = ctx
            .database
            .create_account(CreateAccount {
                additional_fields: alibi_core::field_policy::FieldValues::default(),
                user_id: user.id().to_string(),
                account_id: user.id().to_string(),
                provider_id: "credential".into(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some("old-hash".into()),
            })
            .await
            .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (mut config, outbox) = configured();
        let calls_for_hook = Arc::clone(&calls);
        config.on_password_reset = Some(Arc::new(move |user_2| {
            let calls_2 = Arc::clone(&calls_for_hook);
            Box::pin(async move {
                calls_2.lock().unwrap().push(user_2);
                Ok(())
            })
        }));
        config.revoke_sessions_on_password_reset = true;
        let plugin = EmailOtpPlugin::new(config);
        for path in [
            "/email-otp/request-password-reset",
            "/forget-password/email-otp",
        ] {
            assert_eq!(
                post(&plugin, &ctx, path, json!({"email":"RESET@example.com"}))
                    .await
                    .status,
                200
            );
        }
        let otp = outbox.0.lock().unwrap().last().unwrap().otp.clone();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/reset-password",
                json!({"email":"reset@example.com","otp":otp,"password":"short"})
            )
            .await
            .status,
            400
        );
        assert!(
            plugin
                .get_verification_otp(&ctx, "reset@example.com", EmailOtpType::ForgetPassword)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/reset-password",
                json!({"email":"reset@example.com","otp":otp,"password":"replacement-password"})
            )
            .await
            .status,
            200
        );
        let updated = ctx
            .database
            .get_account("credential", account.account_id())
            .await
            .unwrap()
            .unwrap();
        alibi_core::utils::password::verify_password(
            None,
            "replacement-password",
            updated.password().unwrap(),
        )
        .await
        .unwrap();
        assert!(
            ctx.database
                .get_session(session.token())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_user_by_id(&user.id())
                .await
                .unwrap()
                .unwrap()
                .email_verified()
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/reset-password",
                json!({"email":"reset@example.com","otp":otp,"password":"replacement-password"})
            )
            .await
            .status,
            400
        );
    }

    // Upstream: an OTP reset can create the credential for a passwordless account;
    // unknown mailboxes do not receive reset codes.
    #[tokio::test]
    async fn reset_creates_missing_credential_and_unknown_reset_is_indistinguishable() {
        use alibi_core::AuthAccount;

        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("passwordless@example.com")
                    .with_email_verified(true),
            )
            .await
            .unwrap();
        let (config, outbox) = configured();
        let plugin = EmailOtpPlugin::new(config);
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/request-password-reset",
                json!({"email":"absent@example.com"})
            )
            .await
            .status,
            200
        );
        assert!(outbox.0.lock().unwrap().is_empty());
        let otp = plugin
            .create_verification_otp(
                &ctx,
                "passwordless@example.com",
                EmailOtpType::ForgetPassword,
            )
            .await
            .unwrap();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/reset-password",
                json!({"email":"passwordless@example.com","otp":otp,"password":"new-password123"})
            )
            .await
            .status,
            200
        );
        let accounts = ctx.database.get_user_accounts(&user.id()).await.unwrap();
        assert_eq!(accounts.len(), 1);

        assert_eq!(accounts.first().unwrap().account_id(), user.id());
        assert_eq!(accounts.first().unwrap().provider_id(), "credential");
    }

    // Upstream: checks preserve a correct code even if the mailbox has no user,
    // while wrong checks count toward the same budget and expired checks delete it.
    #[tokio::test]
    async fn nonconsuming_checks_count_attempts_and_reject_unowned_and_expired_mailboxes() {
        let ctx = test_helpers::create_test_context().await;
        let (mut config, _) = configured();
        config.allowed_attempts = 1.0;
        let plugin = EmailOtpPlugin::new(config);
        let otp = plugin
            .create_verification_otp(&ctx, "unknown@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        let checked = post(
            &plugin,
            &ctx,
            "/email-otp/check-verification-otp",
            json!({"email":"unknown@example.com","type":"email-verification","otp":otp}),
        )
        .await;
        let payload: Value = serde_json::from_slice(&checked.body).unwrap();
        assert_eq!(payload.get("code"), Some(&json!("USER_NOT_FOUND")));
        assert_eq!(
            plugin
                .get_verification_otp(&ctx, "unknown@example.com", EmailOtpType::EmailVerification)
                .await
                .unwrap(),
            Some(otp)
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/check-verification-otp",
                json!({"email":"unknown@example.com","type":"email-verification","otp":"wrong"})
            )
            .await
            .status,
            400
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/check-verification-otp",
                json!({"email":"unknown@example.com","type":"email-verification","otp":"wrong"})
            )
            .await
            .status,
            403
        );
        assert!(
            plugin
                .get_verification_otp(&ctx, "unknown@example.com", EmailOtpType::EmailVerification)
                .await
                .unwrap()
                .is_none()
        );
        _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: "email-verification-otp-expired-check@example.com".into(),
                value: "654321:0".into(),
                expires_at: chrono::Utc::now() - Duration::seconds(1),
            })
            .await
            .unwrap();
        assert!(
            plugin
                .get_verification_otp(
                    &ctx,
                    "expired-check@example.com",
                    EmailOtpType::EmailVerification
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
        post(
            &plugin,
            &ctx,
            "/email-otp/check-verification-otp",
            json!({"email":"expired-check@example.com","type":"email-verification","otp":"654321"})
        )
        .await
        .status,
        400
    );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(
                    "email-verification-otp-expired-check@example.com"
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: verification invokes before/after hooks around the persisted change
    // and auto sign-in creates an actual owned session. Hook errors consume the OTP.
    #[tokio::test]
    async fn verification_hooks_and_auto_signin_observe_order_and_ownership() {
        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("hooks@example.com"))
            .await
            .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (mut config, _) = configured();
        config.auto_sign_in_after_verification = true;
        let before = Arc::clone(&seen);
        config.before_email_verification = Some(Arc::new(move |user_2| {
            let before = Arc::clone(&before);
            let verified = user_2.email_verified;
            Box::pin(async move {
                before.lock().unwrap().push(("before", verified));
                Ok(())
            })
        }));
        let after = Arc::clone(&seen);
        config.after_email_verification = Some(Arc::new(move |user_3| {
            let after = Arc::clone(&after);
            let verified = user_3.email_verified;
            Box::pin(async move {
                after.lock().unwrap().push(("after", verified));
                Ok(())
            })
        }));
        let mut plugin = EmailOtpPlugin::new(config);
        let otp = plugin
            .create_verification_otp(&ctx, "hooks@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        let response = post(
            &plugin,
            &ctx,
            "/email-otp/verify-email",
            json!({"email":"hooks@example.com","otp":otp}),
        )
        .await;
        assert_eq!(response.status, 200);
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        let token = payload.get("token").and_then(Value::as_str).unwrap();
        assert_eq!(
            ctx.database
                .get_session(token)
                .await
                .unwrap()
                .unwrap()
                .user_id(),
            user.id()
        );
        assert_eq!(*seen.lock().unwrap(), [("before", false), ("after", true)]);
        plugin.config.before_email_verification = Some(Arc::new(|_| {
            Box::pin(async { Err(AuthError::forbidden("blocked by verification policy")) })
        }));
        let otp_2 = plugin
            .create_verification_otp(&ctx, "hooks@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/verify-email",
                json!({"email":"hooks@example.com","otp":otp_2})
            )
            .await
            .status,
            403
        );
        assert!(
            plugin
                .get_verification_otp(&ctx, "hooks@example.com", EmailOtpType::EmailVerification)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: changeEmail.verifyCurrentEmail consumes current-mailbox proof before
    // issuing a code bound to both mailboxes; occupied targets remain undisclosed.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn email_change_requires_current_proof_and_hides_existing_target() {
        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("proof@example.com"))
            .await
            .unwrap();
        _ = ctx
            .database
            .create_user(CreateUser::new().with_email("occupied@example.com"))
            .await
            .unwrap();
        let session = ctx
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let (mut config, outbox) = configured();
        config.change_email_enabled = true;
        config.verify_current_email = true;
        let plugin = EmailOtpPlugin::new(config);
        let request = |body| {
            create_auth_json_request_no_query(
                HttpMethod::Post,
                "/email-otp/request-email-change",
                Some(session.token()),
                Some(body),
            )
        };
        assert_eq!(
            plugin
                .on_request(&request(json!({"newEmail":"target@example.com"})), &ctx)
                .await
                .unwrap_err()
                .status_code(),
            400
        );
        assert!(outbox.0.lock().unwrap().is_empty());
        let current = plugin
            .create_verification_otp(&ctx, "proof@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        assert_eq!(
            plugin
                .on_request(
                    &request(json!({"newEmail":"occupied@example.com","otp":current})),
                    &ctx
                )
                .await
                .unwrap()
                .unwrap()
                .status,
            200
        );
        assert!(outbox.0.lock().unwrap().is_empty());
        assert!(
            plugin
                .get_verification_otp(&ctx, "proof@example.com", EmailOtpType::EmailVerification)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(
                    "change-email-otp-proof@example.com-occupied@example.com"
                )
                .await
                .unwrap()
                .is_none()
        );
        let current_2 = plugin
            .create_verification_otp(&ctx, "proof@example.com", EmailOtpType::EmailVerification)
            .await
            .unwrap();
        assert_eq!(
            plugin
                .on_request(
                    &request(json!({"newEmail":"target@example.com","otp":current_2})),
                    &ctx
                )
                .await
                .unwrap()
                .unwrap()
                .status,
            200
        );
        let code = outbox.0.lock().unwrap().last().unwrap().otp.clone();
        let confirm = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/email-otp/change-email",
            Some(session.token()),
            Some(json!({"newEmail":"target@example.com","otp":code})),
        );
        assert_eq!(
            plugin
                .on_request(&confirm, &ctx)
                .await
                .unwrap()
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&user.id())
                .await
                .unwrap()
                .unwrap()
                .email(),
            Some("target@example.com")
        );
    }

    // Golden error vectors from the 1.7.6 runtime. Optional nulls are invalid;
    // the schema reports every failed field before authentication middleware.
    #[tokio::test]
    async fn request_validation_matches_pinned_runtime_error_vectors() {
        let ctx = test_helpers::create_test_context().await;
        let (config, _) = configured();
        let plugin = EmailOtpPlugin::new(config);
        for (path, body, message) in [
            (
                "/email-otp/send-verification-otp",
                json!({}),
                "[body.email] Invalid input: expected string, received undefined; [body.type] Invalid option: expected one of \"email-verification\"|\"sign-in\"|\"forget-password\"|\"change-email\"",
            ),
            (
                "/sign-in/email-otp",
                json!({"email":5,"otp":false,"name":null,"image":1}),
                "[body.email] Invalid input: expected string, received number; [body.otp] Invalid input: expected string, received boolean; [body.name] Invalid input: expected string, received null; [body.image] Invalid input: expected string, received number",
            ),
            (
                "/email-otp/change-email",
                json!({}),
                "[body.newEmail] Invalid input: expected string, received undefined; [body.otp] Invalid input: expected string, received undefined",
            ),
        ] {
            let response = post(&plugin, &ctx, path, body).await;
            assert_eq!(response.status, 400);
            let payload: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(
                payload,
                json!({"message":message,"code":"VALIDATION_ERROR"})
            );
        }
        for email in [
            "a@b.c",
            ".a@example.com",
            "a..b@example.com",
            "a!b@example.com",
            "a'@example.com",
        ] {
            assert_eq!(
                post(
                    &plugin,
                    &ctx,
                    "/email-otp/send-verification-otp",
                    json!({"email":email,"type":"sign-in"})
                )
                .await
                .status,
                400
            );
        }
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                json!({"email":"a'b@example.com","type":"change-email"})
            )
            .await
            .status,
            400
        );
    }

    // Upstream: sendVerificationOnSignUp runs after a successful sign-up response,
    // and disabled signup never issues a delivered login for an unknown mailbox.
    #[tokio::test]
    async fn signup_hook_and_disabled_signup_preserve_delivery_and_state_contracts() {
        let ctx = test_helpers::create_test_context().await;
        let (mut config, outbox) = configured();
        config.send_verification_on_sign_up = true;
        config.disable_sign_up = true;
        let plugin = EmailOtpPlugin::new(config);
        let request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
        let response =
            AuthResponse::json(200, &json!({"user":{"email":"signup@example.com"}})).unwrap();
        _ = plugin
            .after_request(&request, &ctx, response)
            .await
            .unwrap();
        assert_eq!(
            outbox.0.lock().unwrap().last().unwrap().otp_type,
            EmailOtpType::EmailVerification
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/email-otp/send-verification-otp",
                json!({"email":"missing@example.com","type":"sign-in"})
            )
            .await
            .status,
            200
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier("sign-in-otp-missing@example.com")
                .await
                .unwrap()
                .is_none()
        );
        let otp = plugin
            .create_verification_otp(&ctx, "missing@example.com", EmailOtpType::SignIn)
            .await
            .unwrap();
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/email-otp",
                json!({"email":"missing@example.com","otp":otp})
            )
            .await
            .status,
            400
        );
        assert!(
            ctx.database
                .get_user_by_email("missing@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Distinct delivery lifecycle contract: an abandoned completion observation
    /// still owns the real request/context and can read the issued proof after the
    /// request returns. No fixture supplies the proof or completes delivery.
    #[tokio::test]
    async fn background_delivery_retains_request_store_and_proof_after_observer_rejection() {
        type Schema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
        struct RejectObservation;
        impl alibi_core::BackgroundTaskHandler for RejectObservation {
            fn handle(&self, completion: alibi_core::BackgroundTaskCompletion) -> AuthResult<()> {
                drop(completion);
                Err(AuthError::internal("observer rejected"))
            }
        }
        struct Deferred {
            resume: tokio::sync::Notify,
            result: tokio::sync::Mutex<Option<(EmailOtpDelivery, String, bool)>>,
            done: tokio::sync::Notify,
        }
        #[async_trait]
        impl SendEmailOtp for Deferred {
            async fn send(
                &self,
                delivery: &EmailOtpDelivery,
                callback: &alibi_core::CallbackContext,
            ) -> AuthResult<()> {
                self.resume.notified().await;
                let ctx = callback.context::<Schema>().unwrap();
                let proof = ctx
                    .database
                    .get_verification_by_identifier(&format!("sign-in-otp-{}", delivery.email))
                    .await?;
                let marker = callback
                    .request
                    .as_ref()
                    .unwrap()
                    .headers
                    .get("x-callback-marker")
                    .unwrap()
                    .clone();
                *self.result.lock().await = Some((delivery.clone(), marker, proof.is_some()));
                self.done.notify_one();
                Err(AuthError::Upstream {
                    status: 409,
                    code: "DELIVERY_REJECTED",
                    message: "delivery rejected",
                })
            }
        }
        let mut ctx = test_helpers::create_test_context().await;
        ctx.config = Arc::new(
            (*ctx.config)
                .clone()
                .background_tasks(Arc::new(RejectObservation)),
        );
        let sender = Arc::new(Deferred {
            resume: tokio::sync::Notify::new(),
            result: tokio::sync::Mutex::new(None),
            done: tokio::sync::Notify::new(),
        });
        let plugin = EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(sender.clone()),
            ..Default::default()
        });
        let email = "background-context@fixture.test";
        let mut request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/email-otp/send-verification-otp",
            None,
            Some(json!({"email":email,"type":"sign-in"})),
        );
        request
            .headers
            .insert("x-callback-marker".into(), "real-request".into());
        let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        assert!(sender.result.lock().await.is_none());
        drop(request);
        sender.resume.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), sender.done.notified())
            .await
            .unwrap();
        let (delivery, marker, proof_exists) = sender.result.lock().await.clone().unwrap();
        assert_eq!(marker, "real-request");
        assert!(proof_exists);
        let consumed = post(
            &plugin,
            &ctx,
            "/sign-in/email-otp",
            json!({"email":email,"otp":delivery.otp}),
        )
        .await;
        assert_eq!(consumed.status, 200);
        let replay = post(
            &plugin,
            &ctx,
            "/sign-in/email-otp",
            json!({"email":email,"otp":delivery.otp}),
        )
        .await;
        assert_eq!(replay.status, 400);
        assert_eq!(
            ctx.database
                .get_user_sessions(
                    serde_json::from_slice::<Value>(&consumed.body)
                        .unwrap()
                        .get("user")
                        .and_then(|user| user.get("id"))
                        .and_then(Value::as_str)
                        .unwrap()
                )
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
// LCOV_EXCL_STOP
