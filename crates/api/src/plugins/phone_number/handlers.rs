use super::{
    PhoneNumberPlugin, PhoneNumberVerification, PhoneOtpDelivery,
    types::{
        ResetRequest, SendRequest, SignInRequest, VerifyRequest, phone_error, reject_verified_input,
    },
};
use crate::plugins::authentication_helpers::{
    find_verification, parse_body, prepare_additional_user_fields, session_response,
    session_response_with_remember,
};
use crate::plugins::{
    email_password::EmailPasswordConfig,
    password_management::{OnPasswordResetCallback, PasswordManagementConfig},
};
use better_auth_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthUser, CreateAccount, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};
use chrono::Utc;
use rand::{Rng, rngs::OsRng};
use serde_json::json;
use std::sync::Arc;

struct PasswordSettings {
    minimum: usize,
    maximum: usize,
    hasher: Option<Arc<dyn better_auth_core::PasswordHasher>>,
    on_reset: Option<Arc<OnPasswordResetCallback>>,
    revoke: bool,
}

impl PhoneNumberPlugin {
    fn generate_code(&self) -> String {
        let mut rng = OsRng;
        (0..self.config.otp_length)
            .map(|_| char::from(b'0' + rng.gen_range(0..10)))
            .collect()
    }
    async fn validate_phone(&self, phone_number: &str) -> AuthResult<()> {
        if let Some(validator) = &self.config.phone_number_validator
            && !validator.is_valid(phone_number).await?
        {
            return Err(phone_error(
                400,
                "INVALID_PHONE_NUMBER",
                "Invalid phone number",
            ));
        }
        Ok(())
    }
    async fn issue(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        identifier: &str,
        count_attempts: bool,
    ) -> AuthResult<String> {
        let code = self.generate_code();
        drop(
            ctx.verifications()
                .create(CreateVerification {
                    identifier: identifier.into(),
                    value: if count_attempts {
                        format!("{code}:0")
                    } else {
                        code.clone()
                    },
                    expires_at: Utc::now() + self.config.expires_in,
                })
                .await?,
        );
        Ok(code)
    }
    async fn callback(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        phone_number: &str,
        user: &impl AuthUser,
    ) -> AuthResult<()> {
        if let Some(callback) = &self.config.callback_on_verification {
            callback
                .verified(&PhoneNumberVerification {
                    phone_number: phone_number.into(),
                    user: ctx.user_view(user),
                })
                .await?;
        }
        Ok(())
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn verify_and_consume(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        phone_number: &str,
        code: &str,
    ) -> AuthResult<()> {
        if let Some(verifier) = &self.config.verify_otp {
            if !verifier
                .verify(&PhoneOtpDelivery {
                    phone_number: phone_number.into(),
                    code: code.into(),
                })
                .await?
            {
                return Err(invalid_otp());
            }
            ctx.verifications().delete(phone_number).await?;
            return Ok(());
        }
        self.consume_local(ctx, phone_number, code).await
    }
    async fn consume_local(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        identifier: &str,
        provided_code: &str,
    ) -> AuthResult<()> {
        let existing = find_verification(ctx, identifier)
            .await?
            .ok_or_else(|| phone_error(400, "OTP_NOT_FOUND", "OTP not found"))?;
        if existing.is_expired() {
            ctx.verifications().delete(identifier).await?;
            return Err(phone_error(400, "OTP_EXPIRED", "OTP expired"));
        }
        let (_, attempts) = split_code(existing.value()?);
        if attempts >= self.config.allowed_attempts {
            ctx.verifications().delete(identifier).await?;
            return Err(phone_error(403, "TOO_MANY_ATTEMPTS", "Too many attempts"));
        }
        let consumed = ctx
            .verifications()
            .consume(identifier)
            .await?
            .ok_or_else(invalid_otp)?;
        let (code, attempts_2) = split_code(consumed.value()?);
        if attempts_2 >= self.config.allowed_attempts {
            return Err(phone_error(403, "TOO_MANY_ATTEMPTS", "Too many attempts"));
        }
        if code != provided_code {
            drop(
                ctx.verifications()
                    .create(CreateVerification {
                        identifier: identifier.into(),
                        value: format!("{code}:{}", attempts_2 + 1),
                        expires_at: consumed.expires_at()?,
                    })
                    .await?,
            );
            return Err(invalid_otp());
        }
        Ok(())
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn send_otp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SendRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let sender = self.config.send_otp.as_ref().ok_or_else(|| {
            phone_error(501, "SEND_OTP_NOT_IMPLEMENTED", "sendOTP not implemented")
        })?;
        self.validate_phone(&body.phone_number).await?;
        let code = self.issue(ctx, &body.phone_number, true).await?;
        sender
            .send(&PhoneOtpDelivery {
                phone_number: body.phone_number,
                code,
            })
            .await?;
        AuthResponse::json(200, &json!({"message":"code sent"})).map_err(AuthError::from)
    }
    #[expect(
        clippy::too_many_lines,
        reason = "Keep phone proof validation, verification policy, and session issuance in request order"
    )]
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SignInRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        self.validate_phone(&body.phone_number).await?;
        let settings = password_settings(ctx);
        better_auth_core::utils::password::validate_password(
            &body.password,
            0,
            settings.maximum,
            ctx,
        )?;
        let user = ctx
            .database
            .get_user_by_phone_number(&body.phone_number)
            .await?
            .ok_or_else(invalid_credentials)?;
        if self.config.require_verification && user.phone_number_verified() != Some(true) {
            let code = self.issue(ctx, &body.phone_number, false).await?;
            if let Some(sender) = &self.config.send_otp {
                crate::plugins::authentication_helpers::run_notification(sender.send(
                    &PhoneOtpDelivery {
                        phone_number: body.phone_number,
                        code,
                    },
                ))
                .await;
            }
            return Err(phone_error(
                401,
                "PHONE_NUMBER_NOT_VERIFIED",
                "Phone number not verified",
            ));
        }
        let account = crate::plugins::helpers::get_credential_account(ctx, user.id())
            .await?
            .ok_or_else(invalid_credentials)?;
        let stored = account
            .password()
            .ok_or_else(|| phone_error(401, "UNEXPECTED_ERROR", "Unexpected error"))?;
        better_auth_core::utils::password::verify_password(
            settings.hasher.as_ref(),
            &body.password,
            stored,
        )
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => invalid_credentials(),
            error @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::Unauthenticated
            | AuthError::AuthenticationFailed(_)
            | AuthError::SessionNotFound
            | AuthError::Forbidden(_)
            | AuthError::UserCreationCancelled
            | AuthError::SessionCreationCancelled
            | AuthError::BannedUser(_)
            | AuthError::Unauthorized
            | AuthError::UserNotFound
            | AuthError::NotFound(_)
            | AuthError::Conflict(_)
            | AuthError::MethodNotAllowed(_)
            | AuthError::PayloadTooLarge(_)
            | AuthError::UnprocessableEntity(_)
            | AuthError::RateLimited
            | AuthError::NotImplemented(_)
            | AuthError::Config(_)
            | AuthError::Database(_)
            | AuthError::Serialization(_)
            | AuthError::Plugin { .. }
            | AuthError::CallbackFailure(_)
            | AuthError::Internal(_)
            | AuthError::PasswordHash(_)
            | AuthError::Jwt(_)) => error,
        })?;
        let (issued, mut response) = session_response_with_remember(
            ctx,
            req,
            &user.id(),
            Some(body.remember_me.unwrap_or(true)),
        )
        .await?;
        if crate::plugins::two_factor::is_enabled(ctx) && user.two_factor_enabled() {
            let trusted =
                crate::plugins::two_factor::inspect_trusted_device(req, &user, ctx).await?;
            if trusted.trusted {
                for header in trusted.set_cookie_headers {
                    response.headers.append("Set-Cookie", header);
                }
            } else {
                // The upstream after hook retires the just-issued credential
                // session before publishing its second-factor challenge.
                let token = issued
                    .get("token")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| AuthError::internal("Issued session must have a token"))?;
                ctx.database.delete_session(token).await?;
                let challenge = crate::plugins::two_factor::begin_sign_in_challenge(
                    &user,
                    body.remember_me,
                    ctx,
                )
                .await?;
                response = AuthResponse::json(200, &challenge.response)?;
                for header in trusted
                    .set_cookie_headers
                    .into_iter()
                    .chain(challenge.set_cookie_headers)
                {
                    response.headers.append("Set-Cookie", header);
                }
            }
        }
        Ok(response)
    }
    #[expect(
        clippy::too_many_lines,
        reason = "Keep proof validation, identity updates, and session callbacks in their protocol order"
    )]
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        self.verify_and_consume(ctx, &body.phone_number, &body.code)
            .await?;
        if body.update_phone_number == Some(true) {
            let (user, session) =
                ctx.require_cached_session(req)
                    .await
                    .map_err(|error| match error {
                        AuthError::Unauthenticated | AuthError::SessionNotFound => {
                            phone_error(401, "USER_NOT_FOUND", "User not found")
                        }
                        error @ (AuthError::Api { .. }
                        | AuthError::Upstream { .. }
                        | AuthError::BadRequest(_)
                        | AuthError::InvalidRequest(_)
                        | AuthError::Validation(_)
                        | AuthError::InvalidCredentials
                        | AuthError::AuthenticationFailed(_)
                        | AuthError::Forbidden(_)
                        | AuthError::UserCreationCancelled
                        | AuthError::SessionCreationCancelled
                        | AuthError::BannedUser(_)
                        | AuthError::Unauthorized
                        | AuthError::UserNotFound
                        | AuthError::NotFound(_)
                        | AuthError::Conflict(_)
                        | AuthError::MethodNotAllowed(_)
                        | AuthError::PayloadTooLarge(_)
                        | AuthError::UnprocessableEntity(_)
                        | AuthError::RateLimited
                        | AuthError::NotImplemented(_)
                        | AuthError::Config(_)
                        | AuthError::Database(_)
                        | AuthError::Serialization(_)
                        | AuthError::Plugin { .. }
                        | AuthError::CallbackFailure(_)
                        | AuthError::Internal(_)
                        | AuthError::PasswordHash(_)
                        | AuthError::Jwt(_)) => error,
                    })?;
            if ctx
                .database
                .get_user_by_phone_number(&body.phone_number)
                .await?
                .is_some()
            {
                return Err(phone_error(
                    400,
                    "PHONE_NUMBER_EXIST",
                    "Phone number already exists",
                ));
            }
            let updated = ctx
                .database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        phone_number: Some(Some(body.phone_number.clone())),
                        phone_number_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?;
            self.callback(ctx, &body.phone_number, &updated).await?;
            return AuthResponse::json(
                200,
                &json!({"status":true,"token":session.token,"user":ctx.user_view(&updated)}),
            )
            .map_err(AuthError::from);
        }
        let user = if let Some(user) = ctx
            .database
            .get_user_by_phone_number(&body.phone_number)
            .await?
        {
            ctx.database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        phone_number_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?
        } else {
            let identity = self
                .config
                .sign_up_on_verification
                .as_ref()
                .ok_or_else(|| {
                    phone_error(500, "FAILED_TO_UPDATE_USER", "Failed to update user")
                })?;
            reject_verified_input(body.phone_number_verified.as_ref())?;
            let mut user = CreateUser::new()
                .with_email(identity.temporary_email(&body.phone_number))
                .with_name(
                    identity
                        .temporary_name(&body.phone_number)
                        .unwrap_or_else(|| body.phone_number.clone()),
                );
            user.phone_number = Some(body.phone_number.clone());
            user.phone_number_verified = Some(true);
            user.username = body.username;
            user.display_username = body.display_username;
            user.image = body.image;
            crate::plugins::helpers::apply_default_role(ctx, &mut user);
            prepare_additional_user_fields(ctx, &mut user).await?;
            ctx.database
                .create_user_with_source(
                    user,
                    better_auth_core::user_validation::UserValidationSource::creation(
                        "phone-number",
                    ),
                )
                .await?
        };
        self.callback(ctx, &body.phone_number, &user).await?;
        if body.disable_session == Some(true) {
            return AuthResponse::json(
                200,
                &json!({"status":true,"token":null,"user":ctx.user_view(&user)}),
            )
            .map_err(AuthError::from);
        }
        let (payload, mut response) = session_response(ctx, req, &user.id()).await?;
        response.body = serde_json::to_vec(
            &json!({"status":true,"token":payload.get("token"),"user":payload.get("user")}),
        )?;
        Ok(response)
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SendRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let user = ctx
            .database
            .get_user_by_phone_number(&body.phone_number)
            .await?;
        // Unlike email OTP anti-enumeration, upstream retains the issued reset
        // verification even when the phone has no registered user.
        let code = self
            .issue(
                ctx,
                &format!("{}-request-password-reset", body.phone_number),
                true,
            )
            .await?;
        if user.is_some()
            && let Some(sender) = &self.config.send_password_reset_otp
        {
            crate::plugins::authentication_helpers::run_notification(sender.send(
                &PhoneOtpDelivery {
                    phone_number: body.phone_number,
                    code,
                },
            ))
            .await;
        }
        AuthResponse::json(200, &json!({"status":true})).map_err(AuthError::from)
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: ResetRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        // The phone reset consumes proof before looking up the account or
        // checking password policy. A policy rejection therefore burns the OTP.
        self.consume_local(
            ctx,
            &format!("{}-request-password-reset", body.phone_number),
            &body.otp,
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_phone_number(&body.phone_number)
            .await?
            .ok_or_else(|| phone_error(400, "UNEXPECTED_ERROR", "Unexpected error"))?;
        let settings = password_settings(ctx);
        better_auth_core::utils::password::validate_password(
            &body.new_password,
            settings.minimum,
            settings.maximum,
            ctx,
        )?;
        let hash = ctx
            .hash_password(settings.hasher.as_ref(), &body.new_password)
            .await?;
        if let Some(account) =
            crate::plugins::helpers::get_credential_account(ctx, user.id()).await?
        {
            drop(
                ctx.database
                    .update_account(
                        &account.id(),
                        UpdateAccount {
                            password: Some(hash),
                            ..Default::default()
                        },
                    )
                    .await?,
            );
        } else {
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
                    .await?,
            );
        }
        if let Some(callback) = settings.on_reset {
            callback(serde_json::to_value(ctx.user_view(&user))?).await?;
        }
        if settings.revoke {
            ctx.database.delete_user_sessions(&user.id()).await?;
        }
        AuthResponse::json(200, &json!({"status":true})).map_err(AuthError::from)
    }
}

const fn invalid_otp() -> AuthError {
    phone_error(400, "INVALID_OTP", "Invalid OTP")
}

const fn invalid_credentials() -> AuthError {
    phone_error(
        401,
        "INVALID_PHONE_NUMBER_OR_PASSWORD",
        "Invalid phone number or password",
    )
}

fn password_settings(ctx: &AuthContext<impl AuthSchema>) -> PasswordSettings {
    let passwords = ctx.extensions.get::<EmailPasswordConfig>();
    let resets = ctx.extensions.get::<PasswordManagementConfig>();
    PasswordSettings {
        minimum: passwords
            .as_ref()
            .map_or(ctx.config.password.min_length, |config| {
                config.password_min_length
            }),
        maximum: passwords
            .as_ref()
            .map_or(128, |config| config.password_max_length),
        hasher: resets
            .as_ref()
            .and_then(|config| config.password_hasher.clone())
            .or_else(|| {
                let config = passwords.as_ref()?;
                config.password_hasher.clone()
            }),
        on_reset: resets
            .as_ref()
            .and_then(|config| config.on_password_reset.clone()),
        revoke: resets
            .as_ref()
            .is_some_and(|config| config.revoke_sessions_on_password_reset),
    }
}

fn split_code(value: &str) -> (&str, usize) {
    let mut pieces = value.split(':');
    let code = pieces.next().unwrap_or_default();
    let attempts = pieces.next().and_then(parse_attempts).unwrap_or(0);
    (code, attempts)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn parse_attempts(value: &str) -> Option<usize> {
    let value =
        value.trim_matches(|character: char| character.is_whitespace() || character == '\u{feff}');
    let radix = [("0x", "0X", 16), ("0o", "0O", 8), ("0b", "0B", 2)]
        .into_iter()
        .find_map(|(lower, upper, radix)| {
            value
                .strip_prefix(lower)
                .or_else(|| value.strip_prefix(upper))
                .map(|digits| (digits, radix))
        });
    let number = if let Some((digits, radix)) = radix {
        u64::from_str_radix(digits, radix).ok()? as f64
    } else {
        value.parse::<f64>().ok()?
    };
    // Upstream accepts exactly the positive, safe integers produced by
    // JavaScript Number(), including integral decimal/exponent/radix strings.
    (number > 0.0 && number.fract() == 0.0 && number <= 9_007_199_254_740_991.0)
        .then_some(number as usize)
}
