//! Phone ownership verification, password login and scoped password reset.
//!
//! [`PhoneNumberPlugin::consume_otp`] is a server-only verification operation.
//! It does not create users or sessions and never registers a public route.

mod handlers;

mod types;

use async_trait::async_trait;
use better_auth_core::{AuthContext, AuthRequest, AuthResult, AuthSchema};
use std::sync::Arc;
pub use types::{PhoneNumberVerification, PhoneOtpDelivery};
pub(in crate::plugins) use types::{parse_signup_phone, reject_verified_input};

#[async_trait]
pub trait SendPhoneOtp: Send + Sync {
    async fn send(
        &self,
        delivery: &PhoneOtpDelivery,
        context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()>;
}

#[async_trait]
pub trait PhoneNumberValidator: Send + Sync {
    async fn is_valid(&self, phone_number: &str) -> AuthResult<bool>;
}

/// A provider that verifies its own phone challenge. Its verification result
/// replaces local verification, including expiry, replay and attempt policy.
#[async_trait]
pub trait PhoneOtpVerifier: Send + Sync {
    async fn verify(
        &self,
        delivery: &PhoneOtpDelivery,
        context: &better_auth_core::CallbackContext,
    ) -> AuthResult<bool>;
}

pub trait PhoneSignupIdentity: Send + Sync {
    fn temporary_email(&self, phone_number: &str) -> String;
    fn temporary_name(&self, _phone_number: &str) -> Option<String> {
        None
    }
}

#[async_trait]
pub trait PhoneVerificationHook: Send + Sync {
    async fn verified(
        &self,
        result: &PhoneNumberVerification,
        context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()>;
}

#[derive(Clone)]
pub struct PhoneNumberConfig {
    pub send_otp: Option<Arc<dyn SendPhoneOtp>>,
    pub send_password_reset_otp: Option<Arc<dyn SendPhoneOtp>>,
    pub verify_otp: Option<Arc<dyn PhoneOtpVerifier>>,
    pub phone_number_validator: Option<Arc<dyn PhoneNumberValidator>>,
    pub sign_up_on_verification: Option<Arc<dyn PhoneSignupIdentity>>,
    pub callback_on_verification: Option<Arc<dyn PhoneVerificationHook>>,
    pub require_verification: bool,
    /// Raw numeric length. Safe positive fractions round up; NaN generates an
    /// empty code. Nonpositive and resource-unsafe lengths fail generation.
    pub otp_length: f64,
    /// Lifetime in seconds. Fractions retain JavaScript millisecond rounding;
    /// invalid dates fail before persistence.
    pub expires_in: f64,
    /// Raw attempt budget compared with the persisted integer counter. Zero and
    /// negatives reject an unused proof; NaN and positive infinity never exhaust.
    pub allowed_attempts: f64,
}

impl std::fmt::Debug for PhoneNumberConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneNumberConfig").finish_non_exhaustive()
    }
}

impl Default for PhoneNumberConfig {
    fn default() -> Self {
        Self {
            send_otp: None,
            send_password_reset_otp: None,
            verify_otp: None,
            phone_number_validator: None,
            sign_up_on_verification: None,
            callback_on_verification: None,
            require_verification: false,
            otp_length: 6.0,
            expires_in: 300.0,
            allowed_attempts: 3.0,
        }
    }
}

#[derive(Clone)]
pub struct PhoneNumberPlugin {
    config: PhoneNumberConfig,
}

impl std::fmt::Debug for PhoneNumberPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneNumberPlugin").finish_non_exhaustive()
    }
}

impl PhoneNumberPlugin {
    #[must_use]
    pub const fn new(config: PhoneNumberConfig) -> Self {
        Self { config }
    }

    /// Consume a phone proof without mutating a user or issuing a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the OTP is missing, expired, invalid, or cannot be consumed from storage.
    pub async fn consume_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        phone_number: &str,
        code: &str,
    ) -> AuthResult<()> {
        self.verify_and_consume(ctx, None, phone_number, code).await
    }
}

better_auth_core::impl_auth_plugin! {
    PhoneNumberPlugin,"phone-number";
    routes {
        post "/sign-in/phone-number" => sign_in,"signInPhoneNumber";
        post "/phone-number/send-otp" => send_otp,"sendPhoneNumberOTP";
        post "/phone-number/verify" => verify,"verifyPhoneNumber";
        post "/phone-number/request-password-reset" => request_password_reset,"requestPasswordResetPhoneNumber";
        post "/phone-number/reset-password" => reset_password,"resetPasswordPhoneNumber";
    }
    extra {
    fn static_openapi_metadata(&self) -> better_auth_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as better_auth_core::AuthPlugin<S>>::name(self), &<Self as better_auth_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &better_auth_core::AuthInitContext<S>) -> better_auth_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as better_auth_core::AuthPlugin<S>>::name(self), &<Self as better_auth_core::AuthPlugin<S>>::routes(self), ctx)
    }

        fn rate_limits(&self) -> Vec<better_auth_core::PluginRateLimit> {
            vec![better_auth_core::PluginRateLimit { matches: |path| path.starts_with("/phone-number"), limit: better_auth_core::EndpointRateLimit { window_seconds: 60.0, max_requests: 10.0 } }]
        }
        async fn on_init(&self,ctx:&mut better_auth_core::AuthInitContext<S>)->AuthResult<()> {
            ctx.set_metadata("phone-number.enabled",serde_json::json!(true));
            ctx.register_user_update_transform(|_, mut update| {
                if matches!(update.phone_number.as_ref(), Some(None)) {
                    update.phone_number_verified = Some(false);
                }
                Ok(update)
            });
            Ok(())
        }
        async fn before_request(&self,req:&AuthRequest,_ctx:&AuthContext<S>)->AuthResult<Option<better_auth_core::BeforeRequestAction>> {
            if req.path()=="/update-user" && req.body_as_json::<better_auth_core::utils::json::JsValue>().ok().and_then(|value|value.get("phoneNumber").cloned()).is_some_and(|value|!value.is_null()) {
                return Err(types::phone_error(400,"PHONE_NUMBER_CANNOT_BE_UPDATED","Phone number cannot be updated"));
            }
            Ok(None)
        }
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::{
        AuthError, AuthPlugin, AuthResponse, AuthSession, AuthUser, AuthVerification,
        CreateAccount, CreateUser, CreateVerification, HttpMethod,
    };
    use chrono::Duration;
    use serde_json::{Value, json};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Outbox(Mutex<Vec<PhoneOtpDelivery>>);

    #[async_trait]
    impl SendPhoneOtp for Outbox {
        async fn send(
            &self,
            delivery: &PhoneOtpDelivery,
            _context: &better_auth_core::CallbackContext,
        ) -> AuthResult<()> {
            self.0.lock().unwrap().push(delivery.clone());
            Ok(())
        }
    }

    struct RejectingSender(Arc<Outbox>);

    #[async_trait]
    impl SendPhoneOtp for RejectingSender {
        async fn send(
            &self,
            delivery: &PhoneOtpDelivery,
            _context: &better_auth_core::CallbackContext,
        ) -> AuthResult<()> {
            self.0.0.lock().unwrap().push(delivery.clone());
            Err(AuthError::bad_request("fixture delivery failed"))
        }
    }

    struct SignupIdentity;

    impl PhoneSignupIdentity for SignupIdentity {
        fn temporary_email(&self, phone_number: &str) -> String {
            format!("{phone_number}@phone.fixture.test")
        }
    }

    struct Provider(Mutex<Option<PhoneOtpDelivery>>);

    #[async_trait]
    impl PhoneOtpVerifier for Provider {
        async fn verify(
            &self,
            delivery: &PhoneOtpDelivery,
            _context: &better_auth_core::CallbackContext,
        ) -> AuthResult<bool> {
            let mut challenge = self.0.lock().unwrap();
            let verified = if challenge.as_ref().is_some_and(|expected| {
                expected.phone_number == delivery.phone_number && expected.code == delivery.code
            }) {
                drop(challenge.take());
                Ok(true)
            } else {
                Ok(false)
            };
            drop(challenge);
            verified
        }
    }

    #[derive(Default)]
    struct VerificationCallback {
        captured: Mutex<Vec<PhoneNumberVerification>>,
        reject: bool,
    }

    #[async_trait]
    impl PhoneVerificationHook for VerificationCallback {
        async fn verified(
            &self,
            result: &PhoneNumberVerification,
            _context: &better_auth_core::CallbackContext,
        ) -> AuthResult<()> {
            self.captured.lock().unwrap().push(result.clone());
            if self.reject {
                Err(AuthError::Upstream {
                    status: 400,
                    code: "PHONE_CALLBACK_REJECTED",
                    message: "Phone callback rejected the authentication",
                })
            } else {
                Ok(())
            }
        }
    }

    fn configured() -> (PhoneNumberPlugin, Arc<Outbox>, Arc<Outbox>) {
        let outbox = Arc::new(Outbox::default());
        let reset = Arc::new(Outbox::default());
        (
            PhoneNumberPlugin::new(PhoneNumberConfig {
                send_otp: Some(Arc::<Outbox>::clone(&outbox)),
                send_password_reset_otp: Some(Arc::<Outbox>::clone(&reset)),
                sign_up_on_verification: Some(Arc::new(SignupIdentity)),
                ..Default::default()
            }),
            outbox,
            reset,
        )
    }

    async fn context()
    -> AuthContext<better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema>
    {
        let mut ctx = test_helpers::create_test_context().await;
        ctx.set_metadata("phone-number.enabled", json!(true));
        ctx
    }

    async fn post(
        plugin: &PhoneNumberPlugin,
        ctx: &AuthContext<impl AuthSchema>,
        path: &str,
        body: Value,
    ) -> AuthResponse {
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            path,
            None,
            Some(body),
        );
        match plugin.on_request(&req, ctx).await {
            Ok(Some(value)) => value,
            Ok(None) => AuthResponse::text(404, "missing route"),
            Err(error) => error.to_auth_response(),
        }
    }

    async fn phone_user(ctx: &AuthContext<impl AuthSchema>, phone: &str, verified: bool) -> String {
        let mut user = CreateUser::new()
            .with_email(format!("{phone}@registered.fixture.test"))
            .with_email_verified(true);
        user.phone_number = Some(phone.into());
        user.phone_number_verified = Some(verified);
        let user = ctx.database.create_user(user).await.unwrap();
        let hash = better_auth_core::utils::password::hash_password(None, "original-password123")
            .await
            .unwrap();
        drop(
            ctx.database
                .create_account(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user.id().to_string(),
                    account_id: user.id().to_string(),
                    provider_id: "credential".into(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(hash),
                })
                .await
                .unwrap(),
        );
        user.id().to_string()
    }

    // Upstream awaits sendOTP directly for /send-otp, but uses its nonfatal
    // background policy for unverified password signin and password reset delivery.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn notification_failure_preserves_phone_authentication_gates_and_issued_proofs() {
        let mut ctx = context().await;
        ctx.config = Arc::new((*ctx.config).clone().awaited_notification_errors(
            better_auth_core::AwaitedNotificationErrorPolicy::LogAndContinue,
        ));
        let phone = "+15551110099";
        let user_id = phone_user(&ctx, phone, false).await;
        let outbox = Arc::new(Outbox::default());
        let sender = Arc::new(RejectingSender(Arc::<Outbox>::clone(&outbox)));
        let plugin = PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(Arc::<RejectingSender>::clone(&sender)),
            send_password_reset_otp: Some(sender),
            require_verification: true,
            ..Default::default()
        });

        let denied = post(
            &plugin,
            &ctx,
            "/sign-in/phone-number",
            json!({"phoneNumber":phone,"password":"original-password123"}),
        )
        .await;
        assert_eq!(denied.status, 401);
        let body: Value = serde_json::from_slice(&denied.body).unwrap();
        assert_eq!(body.get("code"), Some(&json!("PHONE_NUMBER_NOT_VERIFIED")));
        let initial = outbox.0.lock().unwrap().last().unwrap().clone();
        assert_eq!(initial.phone_number, phone);
        assert_eq!(
            ctx.database
                .get_latest_verification_by_identifier(phone)
                .await
                .unwrap()
                .unwrap()
                .value(),
            initial.code
        );
        assert_eq!(
            ctx.database
                .get_user_sessions(&user_id)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/phone-number/verify",
                json!({"phoneNumber":phone,"code":initial.code,"disableSession":true})
            )
            .await
            .status,
            200
        );

        let direct = post(
            &plugin,
            &ctx,
            "/phone-number/send-otp",
            json!({"phoneNumber":phone}),
        )
        .await;
        assert_eq!(direct.status, 400);
        let direct_body: Value = serde_json::from_slice(&direct.body).unwrap();
        assert_eq!(
            direct_body.get("message"),
            Some(&json!("fixture delivery failed"))
        );
        let direct_code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        assert_eq!(
            ctx.database
                .get_latest_verification_by_identifier(phone)
                .await
                .unwrap()
                .unwrap()
                .value(),
            format!("{direct_code}:0")
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/phone-number/verify",
                json!({"phoneNumber":phone,"code":direct_code,"disableSession":true})
            )
            .await
            .status,
            200
        );

        let reset = post(
            &plugin,
            &ctx,
            "/phone-number/request-password-reset",
            json!({"phoneNumber":phone}),
        )
        .await;
        assert_eq!(reset.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&reset.body).unwrap(),
            json!({"status":true})
        );
        let reset_code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let key = format!("{phone}-request-password-reset");
        assert_eq!(
            ctx.database
                .get_latest_verification_by_identifier(&key)
                .await
                .unwrap()
                .unwrap()
                .value(),
            format!("{reset_code}:0")
        );
        let changed = post(
            &plugin,
            &ctx,
            "/phone-number/reset-password",
            json!({"phoneNumber":phone,"otp":reset_code,"newPassword":"changed-password123"}),
        )
        .await;
        assert_eq!(changed.status, 200);
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&key)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/phone-number",
                json!({"phoneNumber":phone,"password":"original-password123"})
            )
            .await
            .status,
            401
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/sign-in/phone-number",
                json!({"phoneNumber":phone,"password":"changed-password123"})
            )
            .await
            .status,
            200
        );
        assert_eq!(
            ctx.database
                .get_user_sessions(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(outbox.0.lock().unwrap().len(), 3);
    }

    // Upstream: signup on verification proves phone ownership, leaves email
    // unverified, and issues exactly one real session, without a password account.
    #[tokio::test]
    async fn phone_signup_and_replay_preserve_verification_identity_and_session() {
        let ctx = context().await;
        let (plugin, outbox, _) = configured();
        let phone = "+15551110001";
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":phone})
            )
            .await
            .status,
            200
        );
        let code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let response = post(
            &plugin,
            &ctx,
            "/phone-number/verify",
            json!({"phoneNumber":phone,"code":code}),
        )
        .await;
        assert_eq!(response.status, 200);
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        let token = payload.get("token").and_then(Value::as_str).unwrap();
        let user = ctx
            .database
            .get_user_by_phone_number(phone)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.phone_number_verified(), Some(true));
        assert!(!user.email_verified());
        assert_eq!(user.name(), Some(phone));
        assert_eq!(
            ctx.database
                .get_session(token)
                .await
                .unwrap()
                .unwrap()
                .user_id(),
            user.id()
        );
        assert_eq!(
            ctx.database
                .get_user_accounts(&user.id())
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            post(
                &plugin,
                &ctx,
                "/phone-number/verify",
                json!({"phoneNumber":phone,"code":code})
            )
            .await
            .status,
            400
        );
        assert_eq!(
            ctx.database
                .get_user_sessions(&user.id())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    // Upstream: attempts and expiry delete proofs, and a code for one phone cannot
    // authorize another. The server-only consumer cannot create any user/session.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn phone_consumer_enforces_scope_expiry_budget_and_single_use() {
        let ctx = context().await;
        let (plugin, outbox, _) = configured();
        let phone = "+15551110002";
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":phone}),
            )
            .await,
        );
        let code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        assert_eq!(
            plugin
                .consume_otp(&ctx, "+15559999999", &code)
                .await
                .unwrap_err()
                .status_code(),
            400
        );
        let deadline = ctx
            .database
            .get_latest_verification_by_identifier(phone)
            .await
            .unwrap()
            .unwrap()
            .expires_at();
        for _ in 0..3 {
            assert_eq!(
                plugin
                    .consume_otp(&ctx, phone, "incorrect")
                    .await
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(
                ctx.database
                    .get_latest_verification_by_identifier(phone)
                    .await
                    .unwrap()
                    .unwrap()
                    .expires_at(),
                deadline
            );
        }
        assert_eq!(
            plugin
                .consume_otp(&ctx, phone, &code)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(phone)
                .await
                .unwrap()
                .is_none()
        );
        drop(
            ctx.database
                .create_verification(CreateVerification {
                    identifier: phone.into(),
                    value: "654321:0".into(),
                    expires_at: chrono::Utc::now() - Duration::seconds(1),
                })
                .await
                .unwrap(),
        );
        assert_eq!(
            plugin
                .consume_otp(&ctx, phone, "654321")
                .await
                .unwrap_err()
                .error_payload()
                .1
                .as_deref(),
            Some("OTP_EXPIRED")
        );
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":phone}),
            )
            .await,
        );
        let code_2 = outbox.0.lock().unwrap().last().unwrap().code.clone();
        plugin.consume_otp(&ctx, phone, &code_2).await.unwrap();
        assert!(
            ctx.database
                .get_user_by_phone_number(phone)
                .await
                .unwrap()
                .is_none()
        );
        assert!(plugin.consume_otp(&ctx, phone, &code_2).await.is_err());
    }

    // Upstream: password sign-in can require phone verification before password
    // Password admission/session expiry and reset lifecycle are exercised through
    // installed HTTP handlers on both stores in integration/storage/plugin_flows/passwordless.rs.

    // A valid server-signed trust cookie for another user cannot bypass the phone
    // sign-in challenge or consume that user's trusted-device record.
    #[tokio::test]
    async fn phone_credentials_reject_another_users_signed_trust_before_authenticating() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use better_auth_core::utils::cookie_utils::{
            related_cookie_name, sign_cookie_value, verify_cookie_value,
        };
        use better_auth_core::{AuthInitContext, UpdateUser};
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let mut ctx = context().await;
        let mut init = AuthInitContext::new(Arc::clone(&ctx.config), Arc::clone(&ctx.database));
        crate::plugins::two_factor::TwoFactorPlugin::new()
            .on_init(&mut init)
            .await
            .unwrap();
        ctx.metadata.extend(init.metadata);
        let (plugin, _, _) = configured();
        let phone = "+15551110012";
        let user_id = phone_user(&ctx, phone, true).await;
        let foreign_id = phone_user(&ctx, "+15551110013", true).await;
        drop(
            ctx.database
                .update_user(
                    &user_id,
                    UpdateUser {
                        two_factor_enabled: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        );
        let trust_id = "trust-device-other-user";
        drop(
            ctx.database
                .create_verification(CreateVerification {
                    identifier: trust_id.into(),
                    value: foreign_id.clone(),
                    expires_at: chrono::Utc::now() + Duration::days(30),
                })
                .await
                .unwrap(),
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(ctx.config.secret.as_bytes()).unwrap();
        mac.update(format!("{foreign_id}!{trust_id}").as_bytes());
        let token = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let cookie = sign_cookie_value(&format!("{token}!{trust_id}"), &ctx.config.secret);
        let mut req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/phone-number",
            None,
            Some(json!({"phoneNumber":phone,"password":"original-password123","rememberMe":false})),
        );
        drop(req.headers.insert(
            "cookie".into(),
            format!(
                "{}={cookie}",
                related_cookie_name(&ctx.config, "trust_device")
            ),
        ));
        let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.get("twoFactorRedirect"), Some(&json!(true)));
        assert!(body.get("token").is_none());
        assert_eq!(
            ctx.database
                .get_user_sessions(&user_id)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            ctx.database
                .get_latest_verification_by_identifier(trust_id)
                .await
                .unwrap()
                .unwrap()
                .value(),
            foreign_id
        );
        let prefix = format!("{}=", related_cookie_name(&ctx.config, "two_factor"));
        let challenge_cookie = response
            .headers
            .get_all("set-cookie")
            .find_map(|cookie_2| cookie_2.strip_prefix(&prefix))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let identifier = verify_cookie_value(challenge_cookie, &ctx.config.secret).unwrap();
        let challenge = ctx
            .database
            .get_latest_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(challenge.value(), user_id);
        assert!((challenge.expires_at() - chrono::Utc::now()).num_seconds() > 598);
    }

    // Upstream: changing a phone consumes proof before authorization/collision;
    // the existing session token is returned without issuing a second session.
    #[tokio::test]
    async fn phone_update_rejects_occupied_number_and_keeps_requester_session() {
        let ctx = context().await;
        let (plugin, outbox, _) = configured();
        let user_id = phone_user(&ctx, "+15551110004", true).await;
        let user = ctx
            .database
            .get_user_by_id(&user_id)
            .await
            .unwrap()
            .unwrap();
        let session = ctx
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let occupied = "+15551110005";
        drop(phone_user(&ctx, occupied, true).await);
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":occupied}),
            )
            .await,
        );
        let code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/phone-number/verify",
            Some(session.token()),
            Some(json!({"phoneNumber":occupied,"code":code,"updatePhoneNumber":true})),
        );
        assert_eq!(
            plugin
                .on_request(&req, &ctx)
                .await
                .unwrap_err()
                .error_payload()
                .1
                .as_deref(),
            Some("PHONE_NUMBER_EXIST")
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&user_id)
                .await
                .unwrap()
                .unwrap()
                .phone_number(),
            Some("+15551110004")
        );
        let target = "+15551110006";
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":target}),
            )
            .await,
        );
        let code_2 = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let req_2 = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/phone-number/verify",
            Some(session.token()),
            Some(json!({"phoneNumber":target,"code":code_2,"updatePhoneNumber":true})),
        );
        let response = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            payload.get("token").and_then(Value::as_str),
            Some(session.token())
        );
        assert!(!response.headers.contains_key("set-cookie"));
        assert_eq!(
            ctx.database
                .get_user_sessions(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&user_id)
                .await
                .unwrap()
                .unwrap()
                .phone_number(),
            Some(target)
        );
    }

    // Upstream phone reset burns proof on password-policy rejection and never
    // Password admission/session expiry and reset lifecycle are exercised through
    // installed HTTP handlers on both stores in integration/storage/plugin_flows/passwordless.rs.

    // Upstream: a custom provider owns code expiry/replay. Successful provider
    // validation deletes any local state but consumes no user/session operation.
    #[tokio::test]
    async fn provider_verification_binds_phone_consumes_once_and_clears_local_rows() {
        let ctx = context().await;
        let (mut plugin, _, _) = configured();
        let phone = "+15551110008";
        plugin.config.verify_otp = Some(Arc::new(Provider(Mutex::new(Some(PhoneOtpDelivery {
            phone_number: phone.into(),
            code: "provider-approved".into(),
        })))));
        drop(
            ctx.database
                .create_verification(CreateVerification {
                    identifier: phone.into(),
                    value: "unrelated:100".into(),
                    expires_at: chrono::Utc::now() - Duration::days(1),
                })
                .await
                .unwrap(),
        );
        assert!(
            plugin
                .consume_otp(&ctx, "+15559999999", "provider-approved")
                .await
                .is_err()
        );
        plugin
            .consume_otp(&ctx, phone, "provider-approved")
            .await
            .unwrap();
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(phone)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            plugin
                .consume_otp(&ctx, phone, "provider-approved")
                .await
                .is_err()
        );
        assert!(
            ctx.database
                .get_user_by_phone_number(phone)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream rejects non-null phone mutation in the before hook even for an
    // unauthenticated caller. Clearing it passes to the normal update-user handler.
    #[tokio::test]
    async fn direct_phone_mutation_and_invalid_body_cannot_bypass_ownership() {
        let ctx = context().await;
        let (plugin, _, _) = configured();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/update-user",
            None,
            Some(json!({"phoneNumber":"+15551110009"})),
        );
        assert_eq!(
            plugin
                .before_request(&req, &ctx)
                .await
                .unwrap_err()
                .error_payload()
                .1
                .as_deref(),
            Some("PHONE_NUMBER_CANNOT_BE_UPDATED")
        );
        let req_2 = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/update-user",
            None,
            Some(json!({"phoneNumber":null})),
        );
        assert!(plugin.before_request(&req_2, &ctx).await.unwrap().is_none());
        let response = post(
            &plugin,
            &ctx,
            "/phone-number/verify",
            json!({"phoneNumber":null,"code":4,"disableSession":null}),
        )
        .await;
        assert_eq!(response.status, 400);
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(payload.get("code"), Some(&json!("VALIDATION_ERROR")));
        assert_eq!(
            payload.get("message"),
            Some(&json!(
                "[body.phoneNumber] Invalid input: expected string, received null; [body.code] Invalid input: expected string, received number; [body.disableSession] Invalid input: expected boolean, received null"
            ))
        );
    }

    // Upstream: the atomic consume guarantees exactly one winning verification.
    #[tokio::test]
    async fn concurrent_phone_consumers_cannot_reuse_a_local_proof() {
        let ctx = context().await;
        let (plugin, outbox, _) = configured();
        let phone = "+15551110010";
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":phone}),
            )
            .await,
        );
        let code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let (first, second) = tokio::join!(
            plugin.consume_otp(&ctx, phone, &code),
            plugin.consume_otp(&ctx, phone, &code)
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(
            ctx.database
                .get_user_by_phone_number(phone)
                .await
                .unwrap()
                .is_none()
        );
    }

    // The callback observes the persisted verified owner before session issuance.
    // Its failure consumes the proof and preserves the user, without a new session.
    #[tokio::test]
    async fn verification_callback_observes_owner_and_rejection_prevents_session_issuance() {
        let ctx = context().await;
        let (mut plugin, outbox, _) = configured();
        let callback = Arc::new(VerificationCallback::default());
        plugin.config.callback_on_verification =
            Some(Arc::<VerificationCallback>::clone(&callback));
        let phone = "+15551110011";
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":phone}),
            )
            .await,
        );
        let code = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let success = post(
            &plugin,
            &ctx,
            "/phone-number/verify",
            json!({"phoneNumber":phone,"code":code}),
        )
        .await;
        assert_eq!(success.status, 200);
        let user = ctx
            .database
            .get_user_by_phone_number(phone)
            .await
            .unwrap()
            .unwrap();
        {
            let captured = callback.captured.lock().unwrap();
            assert_eq!(captured.len(), 1);
            let proof = captured.first().unwrap();
            assert_eq!(proof.phone_number, phone);
            assert_eq!(proof.user.id, user.id());
            assert_eq!(proof.user.phone_number.as_deref(), Some(phone));
            assert_eq!(proof.user.phone_number_verified, Some(true));
            drop(captured);
        }
        let rejecting = Arc::new(VerificationCallback {
            reject: true,
            ..Default::default()
        });
        plugin.config.callback_on_verification =
            Some(Arc::<VerificationCallback>::clone(&rejecting));
        let rejected_phone = "+15551110012";
        drop(
            post(
                &plugin,
                &ctx,
                "/phone-number/send-otp",
                json!({"phoneNumber":rejected_phone}),
            )
            .await,
        );
        let code_2 = outbox.0.lock().unwrap().last().unwrap().code.clone();
        let rejected = post(
            &plugin,
            &ctx,
            "/phone-number/verify",
            json!({"phoneNumber":rejected_phone,"code":code_2}),
        )
        .await;
        assert_eq!(rejected.status, 400);
        assert_eq!(rejecting.captured.lock().unwrap().len(), 1);
        let user_2 = ctx
            .database
            .get_user_by_phone_number(rejected_phone)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_2.phone_number_verified(), Some(true));
        assert_eq!(
            ctx.database
                .get_user_sessions(&user_2.id())
                .await
                .unwrap()
                .len(),
            0
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(rejected_phone)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Number()-compatible persisted counters must not bypass the attempt budget.
    #[tokio::test]
    async fn server_consumer_rejects_exhausted_decimal_exponent_and_radix_counters() {
        let ctx = context().await;
        let (plugin, _, _) = configured();
        for attempts in ["3.0", "3e0", " 3 ", "0x3", "0o3", "0b11"] {
            let phone = format!("counter:{attempts}");
            drop(
                ctx.database
                    .create_verification(CreateVerification {
                        identifier: phone.clone(),
                        value: format!("654321:{attempts}"),
                        expires_at: chrono::Utc::now() + Duration::minutes(5),
                    })
                    .await
                    .unwrap(),
            );
            let result = plugin
                .consume_otp(&ctx, &phone, "654321")
                .await
                .unwrap_err();
            assert_eq!(
                result.error_payload().1.as_deref(),
                Some("TOO_MANY_ATTEMPTS")
            );
            assert!(
                ctx.database
                    .get_latest_verification_by_identifier(&phone)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
// LCOV_EXCL_STOP
