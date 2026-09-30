//! Phone ownership verification, password login and scoped password reset.
//!
//! [`PhoneNumberPlugin::consume_otp`] is a server-only verification operation.
//! It does not create users or sessions and never registers a public route.

use async_trait::async_trait;
use better_auth_core::{AuthContext, AuthRequest, AuthResult, AuthSchema};
use chrono::Duration;
use std::sync::Arc;

mod handlers;
#[cfg(test)]
mod tests;
mod types;

pub use types::{PhoneNumberVerification, PhoneOtpDelivery};
pub(crate) use types::{parse_signup_phone, reject_verified_input};

#[async_trait]
pub trait SendPhoneOtp: Send + Sync {
    async fn send(&self, delivery: &PhoneOtpDelivery) -> AuthResult<()>;
}

#[async_trait]
pub trait PhoneNumberValidator: Send + Sync {
    async fn is_valid(&self, phone_number: &str) -> AuthResult<bool>;
}

/// A provider that verifies its own phone challenge. Its verification result
/// replaces local verification, including expiry, replay and attempt policy.
#[async_trait]
pub trait PhoneOtpVerifier: Send + Sync {
    async fn verify(&self, delivery: &PhoneOtpDelivery) -> AuthResult<bool>;
}

pub trait PhoneSignupIdentity: Send + Sync {
    fn temporary_email(&self, phone_number: &str) -> String;
    fn temporary_name(&self, _phone_number: &str) -> Option<String> {
        None
    }
}

#[async_trait]
pub trait PhoneVerificationHook: Send + Sync {
    async fn verified(&self, result: &PhoneNumberVerification) -> AuthResult<()>;
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
    pub otp_length: usize,
    pub expires_in: Duration,
    pub allowed_attempts: usize,
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
            otp_length: 6,
            expires_in: Duration::seconds(300),
            allowed_attempts: 3,
        }
    }
}

#[derive(Clone)]
pub struct PhoneNumberPlugin {
    config: PhoneNumberConfig,
}

impl PhoneNumberPlugin {
    pub fn new(config: PhoneNumberConfig) -> Self {
        Self { config }
    }

    /// Consume a phone proof without mutating a user or issuing a session.
    pub async fn consume_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        phone_number: &str,
        code: &str,
    ) -> AuthResult<()> {
        self.verify_and_consume(ctx, phone_number, code).await
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
