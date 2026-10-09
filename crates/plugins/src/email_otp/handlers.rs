use super::{
    EmailOtpDelivery, EmailOtpPlugin, EmailOtpType, OtpResendStrategy,
    helpers::{expired_otp, invalid_otp, too_many_attempts, user_not_found},
    types::{
        ChangeEmailRequest, CheckRequest, ConfirmChangeRequest, EmailRequest, PasswordRequest,
        SendRequest, SignInRequest, VerifyRequest, identifier, split_value,
    },
};
use crate::authentication_helpers::{
    find_verification, parse_body, parse_email, prepare_additional_user_fields,
    revoke_unproven_access, session_response,
};
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthUser,
    CreateAccount, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};
use serde_json::{Value, json};

pub(super) enum PreparationError {
    Auth(AuthError),
    InvalidDate,
}
impl From<AuthError> for PreparationError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}
impl From<PreparationError> for AuthError {
    fn from(error: PreparationError) -> Self {
        match error {
            PreparationError::Auth(error) => error,
            PreparationError::InvalidDate => Self::internal("Invalid Date"),
        }
    }
}

impl EmailOtpPlugin {
    pub(super) async fn prepare_code(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        request: Option<&AuthRequest>,
        email: &str,
        otp_type: EmailOtpType,
        identifier_override: Option<String>,
    ) -> Result<(String, CreateVerification), PreparationError> {
        let generated = match &self.config.generate_otp {
            Some(generator) => {
                generator
                    .generate(
                        email,
                        otp_type,
                        &alibi_core::CallbackContext::new(ctx, request),
                    )
                    .await?
            }
            None => None,
        };
        let otp = match generated.filter(|value| !value.is_empty()) {
            Some(value) => value,
            None => super::super::passwordless_numeric::generate_code(self.config.otp_length)?,
        };
        let stored = self.config.storage.store(&otp, &ctx.config).await?;
        let verification = CreateVerification {
            identifier: identifier_override.unwrap_or_else(|| identifier(otp_type, email)),
            value: format!("{stored}:0"),
            expires_at: super::super::passwordless_numeric::expires_at(
                self.config.expires_in,
                false,
            )
            .ok_or(PreparationError::InvalidDate)?,
        };
        Ok((otp, verification))
    }

    pub(super) async fn issue_code(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        request: Option<&AuthRequest>,
        email: &str,
        otp_type: EmailOtpType,
        identifier_override: Option<String>,
    ) -> AuthResult<String> {
        let (otp, value) = self
            .prepare_code(ctx, request, email, otp_type, identifier_override)
            .await?;
        drop(ctx.verifications().create(value).await?);
        Ok(otp)
    }

    async fn resolve_code(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        request: Option<&AuthRequest>,
        email: &str,
        otp_type: EmailOtpType,
    ) -> AuthResult<String> {
        let key = identifier(otp_type, email);
        if self.config.resend_strategy == OtpResendStrategy::Reuse
            && let Some(value) = find_verification(ctx, &key).await?
            && !value.is_expired()
        {
            let (stored, attempts) = split_value(value.value()?);
            if super::super::passwordless_numeric::attempts_number(attempts)
                < self.allowed_attempts()
                && let Some(otp) = self.config.storage.reusable(stored, &ctx.config).await?
                && !otp.is_empty()
            {
                drop(
                    ctx.verifications()
                        .update(
                            &key,
                            alibi_core::UpdateVerification {
                                expires_at: Some(
                                    super::super::passwordless_numeric::expires_at(
                                        self.config.expires_in,
                                        false,
                                    )
                                    .ok_or_else(|| AuthError::internal("Invalid Date"))?,
                                ),
                                ..Default::default()
                            },
                        )
                        .await?,
                );
                return Ok(otp);
            }
        }
        let (otp, mut data) = match self.prepare_code(ctx, request, email, otp_type, None).await {
            Ok(prepared) => prepared,
            Err(PreparationError::InvalidDate) => {
                ctx.verifications().delete(&key).await?;
                return Err(AuthError::internal("Invalid Date"));
            }
            Err(error) => return Err(error.into()),
        };
        // The published delivery resolver retries a failed creation after
        // invalidating this logical identifier, retaining the same generated
        // OTP and selecting a fresh expiry for the retry. Server-only direct
        // creation and change-email issuance retain their separate contracts.
        if ctx.verifications().create(data.clone()).await.is_err() {
            ctx.verifications().delete(&key).await?;
            data.expires_at =
                super::super::passwordless_numeric::expires_at(self.config.expires_in, false)
                    .ok_or_else(|| AuthError::internal("Invalid Date"))?;
            drop(ctx.verifications().create(data).await?);
        }
        Ok(otp)
    }

    pub(super) async fn deliver(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        request: Option<&AuthRequest>,
        email: &str,
        otp: String,
        otp_type: EmailOtpType,
    ) -> AuthResult<()> {
        let sender =
            self.config.send_verification_otp.as_ref().ok_or_else(|| {
                AuthError::bad_request("send email verification is not implemented")
            })?;
        let sender = sender.clone();
        let context = alibi_core::CallbackContext::new(ctx, request);
        let delivery = EmailOtpDelivery {
            email: email.to_owned(),
            otp,
            otp_type,
        };
        crate::authentication_helpers::run_owned_notification(
            ctx,
            async move { sender.send(&delivery, &context).await },
            ctx.config.awaited_notification_errors,
        )
        .await
    }

    fn allowed_attempts(&self) -> f64 {
        if self.config.allowed_attempts == 0.0 || self.config.allowed_attempts.is_nan() {
            3.0
        } else {
            self.config.allowed_attempts
        }
    }

    /// Consume is the authorization gate. A wrong code recreates the record
    /// with its original deadline and incremented budget, matching 1.7.6.
    async fn consume_code(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        key: &str,
        otp: &str,
    ) -> AuthResult<()> {
        if let Some(existing) = find_verification(ctx, key).await?
            && existing.is_expired()
        {
            ctx.verifications().delete(key).await?;
            return Err(expired_otp());
        }
        let value = ctx
            .verifications()
            .consume(key)
            .await?
            .ok_or_else(invalid_otp)?;
        let (stored, attempts) = split_value(value.value()?);
        if super::super::passwordless_numeric::attempts_number(attempts) >= self.allowed_attempts()
        {
            return Err(too_many_attempts());
        }
        if !self.config.storage.verify(stored, otp, &ctx.config).await? {
            drop(
                ctx.verifications()
                    .create(CreateVerification {
                        identifier: key.to_owned(),
                        value: format!("{stored}:{}", attempts + 1),
                        expires_at: value.expires_at()?,
                    })
                    .await?,
            );
            return Err(invalid_otp());
        }
        Ok(())
    }

    pub(super) async fn send_verification(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.send_verification_with_request(req, Some(req), ctx)
            .await
    }

    pub(super) async fn send_verification_with_request(
        &self,
        req: &AuthRequest,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SendRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if self.config.send_verification_otp.is_none() {
            return Err(AuthError::bad_request(
                "send email verification is not implemented",
            ));
        }
        let email = parse_email(&body.email)?;
        if body.otp_type == EmailOtpType::ChangeEmail {
            return Err(AuthError::bad_request("Invalid OTP type"));
        }
        let otp = match self.resolve_code(ctx, request, &email, body.otp_type).await {
            Ok(otp) => otp,
            Err(AuthError::Internal(_)) => return Ok(AuthResponse::new(500)),
            Err(error) => return Err(error),
        };
        let should_send = body.otp_type == EmailOtpType::SignIn && !self.config.disable_sign_up;
        if ctx
            .database
            .get_user_by_email_record(&email)
            .await?
            .is_none()
            && !should_send
        {
            ctx.verifications()
                .delete(&identifier(body.otp_type, &email))
                .await?;
            return AuthResponse::json(200, &json!({"success":true})).map_err(AuthError::from);
        }
        self.deliver(ctx, request, &email, otp, body.otp_type)
            .await?;
        AuthResponse::json(200, &json!({"success":true})).map_err(AuthError::from)
    }

    pub(super) async fn check_verification(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: CheckRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let email = parse_email(&body.email)?;
        let key = identifier(body.otp_type, &email);
        let value = find_verification(ctx, &key)
            .await?
            .ok_or_else(invalid_otp)?;
        if value.is_expired() {
            ctx.verifications().delete(&key).await?;
            return Err(expired_otp());
        }
        let (stored, attempts) = split_value(value.value()?);
        if super::super::passwordless_numeric::attempts_number(attempts) >= self.allowed_attempts()
        {
            ctx.verifications().delete(&key).await?;
            return Err(too_many_attempts());
        }
        if !self
            .config
            .storage
            .verify(stored, &body.otp, &ctx.config)
            .await?
        {
            drop(
                ctx.verifications()
                    .update(
                        &key,
                        alibi_core::UpdateVerification {
                            value: Some(format!("{stored}:{}", attempts + 1)),
                            ..Default::default()
                        },
                    )
                    .await?,
            );
            return Err(invalid_otp());
        }
        if ctx
            .database
            .get_user_by_email_record(&email)
            .await?
            .is_none()
        {
            return Err(user_not_found());
        }
        AuthResponse::json(200, &json!({"success":true})).map_err(AuthError::from)
    }

    pub(super) async fn verify_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let email = parse_email(&body.email)?;
        self.consume_code(
            ctx,
            &identifier(EmailOtpType::EmailVerification, &email),
            &body.otp,
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_email_record(&email)
            .await?
            .ok_or_else(user_not_found)?;
        let settings = self.verification_settings(ctx);
        if let Some(hook) = &settings.before {
            hook(&ctx.user_view(&user)).await?;
        }
        let updated = ctx
            .database
            .update_user_record(
                &user.id(),
                UpdateUser {
                    email: Some(email),
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(hook) = &settings.after {
            hook(&ctx.user_view(&updated)).await?;
        }
        if settings.auto_sign_in {
            let (payload, mut response) = session_response(ctx, req, updated).await?;
            response.body = serde_json::to_vec(
                &json!({"status":true,"token":payload.get("token"),"user":payload.get("user")}),
            )?;
            return Ok(response);
        }
        AuthResponse::json(
            200,
            &json!({"status":true,"token":null,"user":ctx.user_view(&updated)}),
        )
        .map_err(AuthError::from)
    }

    pub(super) async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        // Extra user inputs come from the configured schema. An absent username
        // plugin must not deserialize, validate or persist its additional fields.
        let username_enabled = ctx
            .get_metadata("username.enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ignored = if username_enabled {
            &[][..]
        } else {
            &["username", "displayUsername"][..]
        };
        let body: SignInRequest =
            match crate::authentication_helpers::parse_body_with_ignored_fields(req, ignored) {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
        let email = body.email.to_lowercase();
        self.consume_code(ctx, &identifier(EmailOtpType::SignIn, &email), &body.otp)
            .await?;
        let user = match ctx.database.get_user_by_email_record(&email).await? {
            Some(user) if !user.email_verified() => revoke_unproven_access(ctx, &user.id())
                .await?
                .ok_or_else(invalid_otp)?,
            Some(user) => user,
            None if self.config.disable_sign_up => return Err(invalid_otp()),
            None => {
                let mut data = CreateUser::new()
                    .with_email(email)
                    .with_name(body.name.unwrap_or_default())
                    .with_email_verified(true);
                data.image = body.image;
                data.username = body.username;
                data.display_username = body.display_username;
                super::super::helpers::apply_default_role(ctx, &mut data);
                prepare_additional_user_fields(ctx, &mut data).await?;
                ctx.database
                    .create_user_with_source_record(
                        data,
                        alibi_core::user_validation::UserValidationSource::creation("email-otp"),
                    )
                    .await?
            }
        };
        session_response(ctx, req, user)
            .await
            .map(|(_, response)| response)
    }

    pub(super) async fn request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: EmailRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let email = body.email.to_lowercase();
        let otp = match self
            .resolve_code(ctx, Some(req), &email, EmailOtpType::ForgetPassword)
            .await
        {
            Ok(otp) => otp,
            Err(AuthError::Internal(_)) => return Ok(AuthResponse::new(500)),
            Err(error) => return Err(error),
        };
        if ctx
            .database
            .get_user_by_email_record(&email)
            .await?
            .is_none()
        {
            ctx.verifications()
                .delete(&identifier(EmailOtpType::ForgetPassword, &email))
                .await?;
        } else {
            self.deliver(ctx, Some(req), &email, otp, EmailOtpType::ForgetPassword)
                .await?;
        }
        AuthResponse::json(200, &json!({"success":true})).map_err(AuthError::from)
    }

    pub(super) async fn reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        use alibi_core::AuthAccount;
        let body: PasswordRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let email = body.email.to_lowercase();
        let settings = self.password_settings(ctx);
        alibi_core::utils::password::validate_password(
            &body.password,
            settings.minimum,
            settings.maximum,
            ctx,
        )?;
        self.consume_code(
            ctx,
            &identifier(EmailOtpType::ForgetPassword, &email),
            &body.otp,
        )
        .await?;
        let user = ctx
            .database
            .get_user_by_email_record(&email)
            .await?
            .ok_or_else(user_not_found)?;
        let password = ctx
            .hash_password(settings.hasher.as_ref(), &body.password)
            .await?;
        if let Some(account) = super::super::helpers::get_credential_account(ctx, user.id()).await?
        {
            drop(
                ctx.database
                    .update_account_record(
                        &account.id(),
                        UpdateAccount {
                            password: Some(password),
                            ..Default::default()
                        },
                    )
                    .await?,
            );
        } else {
            drop(
                ctx.database
                    .create_account_record(CreateAccount {
                        additional_fields: Default::default(),
                        user_id: user.id().to_string(),
                        account_id: user.id().to_string(),
                        provider_id: "credential".to_owned(),
                        access_token: None,
                        refresh_token: None,
                        id_token: None,
                        access_token_expires_at: None,
                        refresh_token_expires_at: None,
                        scope: None,
                        password: Some(password),
                    })
                    .await?,
            );
        }
        if let Some(hook) = &settings.on_reset {
            hook(serde_json::to_value(ctx.user_view(&user))?).await?;
        }
        if !user.email_verified() {
            drop(
                ctx.database
                    .update_user_record(
                        &user.id(),
                        UpdateUser {
                            email_verified: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?,
            );
        }
        if settings.revoke_sessions {
            ctx.database.delete_user_sessions(&user.id()).await?;
        }
        AuthResponse::json(200, &json!({"success":true})).map_err(AuthError::from)
    }

    pub(super) async fn request_email_change(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: ChangeEmailRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let (user, _) = require_authoritative_session(ctx, req).await?;
        if !self.config.change_email_enabled {
            return Err(AuthError::bad_request("Change email with OTP is disabled"));
        }
        let email = user.email().unwrap_or_default().to_lowercase();
        let new_email = parse_email(&body.new_email)?;
        if new_email == email {
            return Err(AuthError::bad_request("Email is the same"));
        }
        if self.config.verify_current_email {
            let otp = body
                .otp
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AuthError::bad_request("OTP is required to verify current email"))?;
            self.consume_code(
                ctx,
                &identifier(EmailOtpType::EmailVerification, &email),
                &otp,
            )
            .await?;
        }
        let key = identifier(EmailOtpType::ChangeEmail, &format!("{email}-{new_email}"));
        let otp = match self
            .issue_code(
                ctx,
                Some(req),
                &new_email,
                EmailOtpType::ChangeEmail,
                Some(key.clone()),
            )
            .await
        {
            Ok(otp) => otp,
            Err(AuthError::Internal(_)) => return Ok(AuthResponse::new(500)),
            Err(error) => return Err(error),
        };
        if ctx
            .database
            .get_user_by_email_record(&new_email)
            .await?
            .is_some()
        {
            ctx.verifications().delete(&key).await?;
        } else {
            self.deliver(ctx, Some(req), &new_email, otp, EmailOtpType::ChangeEmail)
                .await?;
        }
        AuthResponse::json(200, &json!({"success":true})).map_err(AuthError::from)
    }

    pub(super) async fn change_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: ConfirmChangeRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let otp = body.otp;
        let (user, session) = require_authoritative_session(ctx, req).await?;
        if !self.config.change_email_enabled {
            return Err(AuthError::bad_request("Change email with OTP is disabled"));
        }
        let email = user.email().unwrap_or_default().to_lowercase();
        let new_email = parse_email(&body.new_email)?;
        if new_email == email {
            return Err(AuthError::bad_request("Email is the same"));
        }
        self.consume_code(
            ctx,
            &identifier(EmailOtpType::ChangeEmail, &format!("{email}-{new_email}")),
            &otp,
        )
        .await?;
        let current = ctx
            .database
            .get_user_by_email_record(&email)
            .await?
            .ok_or_else(user_not_found)?;
        if ctx
            .database
            .get_user_by_email_record(&new_email)
            .await?
            .is_some()
        {
            return Err(AuthError::bad_request("Email already in use"));
        }
        let settings = self.verification_settings(ctx);
        if let Some(hook) = &settings.before {
            hook(&ctx.user_view(&current))
                .await
                .map_err(|error| match error {
                    AuthError::Api { .. }
                    | AuthError::Upstream { .. }
                    | AuthError::CallbackFailure(_) => error,
                    error => AuthError::CallbackFailure(Box::new(error)),
                })?;
        }
        let updated = ctx
            .database
            .update_user_record(
                &current.id(),
                UpdateUser {
                    email: Some(new_email),
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(hook) = &settings.after {
            hook(&ctx.user_view(&updated))
                .await
                .map_err(|error| match error {
                    AuthError::Api { .. }
                    | AuthError::Upstream { .. }
                    | AuthError::CallbackFailure(_) => error,
                    error => AuthError::CallbackFailure(Box::new(error)),
                })?;
        }
        Ok(AuthResponse::json(200, &json!({"success":true}))
            .map_err(AuthError::from)?
            .with_header(
                "Set-Cookie",
                alibi_core::utils::cookie_utils::create_session_cookie(
                    &session.token,
                    &ctx.config,
                )?,
            ))
    }
}

async fn require_authoritative_session<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
) -> AuthResult<(S::User, alibi_core::wire::SessionView)> {
    ctx.require_session(req).await.map_err(|error| match error {
        AuthError::Unauthenticated | AuthError::SessionNotFound => AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            message: "Unauthorized",
        },
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
        | AuthError::RateLimited { .. }
        | AuthError::NotImplemented(_)
        | AuthError::Config(_)
        | AuthError::Database(_)
        | AuthError::Serialization(_)
        | AuthError::Plugin { .. }
        | AuthError::CallbackFailure(_)
        | AuthError::Internal(_)
        | AuthError::Encryption(_)
        | AuthError::PasswordHash(_)
        | AuthError::Jwt(_)) => error,
    })
}
