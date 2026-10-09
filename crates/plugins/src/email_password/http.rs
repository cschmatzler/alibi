use super::types::{
    IsUsernameAvailableRequest, IsUsernameAvailableResponse, SignInCoreResult, SignInRequest,
    SignInUsernameFailure, SignInUsernameRequest, SignInUsernameResponse, SignUpRequest,
};
use super::{
    EmailPasswordPlugin, MESSAGE_EMAIL_NOT_VERIFIED, MESSAGE_INVALID_USERNAME_OR_PASSWORD,
    MESSAGE_USERNAME_IS_ALREADY_TAKEN, UsernameValidationOrder, append_dont_remember_cookie,
    create_session_cookie_for_remember_me, sign_in_core, sign_in_username_core, sign_up_core,
    username_error_response,
};
use crate::authentication_helpers::parse_body;
use alibi_core::{AuthContext, AuthRequest, AuthResponse, AuthResult, RequestMeta};
use std::sync::Arc;
impl EmailPasswordPlugin {
    pub(in crate::email_password) async fn handle_sign_up(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let ignored = if self.config.enable_username {
            &[][..]
        } else {
            &["username", "displayUsername"][..]
        };
        let mut signup_req: SignUpRequest =
            match super::super::authentication_helpers::parse_body_with_ignored_fields(req, ignored)
            {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };

        alibi_core::middleware::CsrfMiddleware::new(
            alibi_core::middleware::CsrfConfig::new(),
            Arc::clone(&ctx.config),
        )
        .check_form_origin(req)?;
        signup_req.email = signup_req.email.to_lowercase();
        if self.config.enable_username {
            let policy = &self.config.username;
            if signup_req.username.is_none()
                && let Some(display) = &signup_req.display_username
                && policy.value_error(display).await?.is_none()
            {
                signup_req.username = Some(display.clone());
            }
            if let Some(username) = &signup_req.username {
                policy.validate_hook_value(username).await?;
                if ctx
                    .database
                    .get_user_by_username(&policy.normalize(username)?)
                    .await?
                    .is_some()
                {
                    return username_error_response(
                        400,
                        "USERNAME_IS_ALREADY_TAKEN",
                        MESSAGE_USERNAME_IS_ALREADY_TAKEN,
                    );
                }
            }
            if let Some(display) = &signup_req.display_username {
                policy.validate_display(display).await?;
            }
            if policy.include_display_username
                && signup_req
                    .display_username
                    .as_ref()
                    .is_none_or(String::is_empty)
            {
                signup_req.display_username.clone_from(&signup_req.username);
            }
            if !policy.include_display_username {
                signup_req.display_username = None;
            }
            let mut callback_body = req.body_as_json::<alibi_core::utils::json::JsValue>()?;
            if let alibi_core::utils::json::JsValue::Object(body) = &mut callback_body {
                if let Some(value) = &signup_req.username {
                    drop(body.insert(
                        "username".into(),
                        alibi_core::utils::json::JsValue::String(value.clone()),
                    ));
                }
                if let Some(value) = &signup_req.display_username {
                    drop(body.insert(
                        "displayUsername".into(),
                        alibi_core::utils::json::JsValue::String(value.clone()),
                    ));
                }
            }
            req.extensions()
                .insert(alibi_core::hooks::TransformedRequestBody(callback_body));
        }

        alibi_core::session::cookie_cache::runtime::set_issuance_preference(
            req,
            signup_req.remember_me == Some(false),
        );
        let meta = RequestMeta::from_request(req);
        let (response, cookies) = sign_up_core(req, &signup_req, &self.config, &meta, ctx).await?;
        let mut response = AuthResponse::json(200, &response)?;
        for cookie in cookies.into_iter().flatten() {
            response.headers.append("Set-Cookie", cookie);
        }
        Ok(response)
    }

    pub(in crate::email_password) async fn handle_sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInRequest = match parse_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let mut callback_body: alibi_core::utils::json::JsValue = req.body_as_json()?;
        if let alibi_core::utils::json::JsValue::Object(body) = &mut callback_body {
            let _remember = body
                .entry("rememberMe".into())
                .or_insert(alibi_core::utils::json::JsValue::Bool(true));
        }
        req.extensions()
            .insert(alibi_core::hooks::ValidatedRequestBody(callback_body));
        alibi_core::middleware::CsrfMiddleware::new(
            alibi_core::middleware::CsrfConfig::new(),
            Arc::clone(&ctx.config),
        )
        .check_form_origin(req)?;

        alibi_core::session::cookie_cache::runtime::set_issuance_preference(
            req,
            signin_req.remember_me == Some(false),
        );
        let meta = RequestMeta::from_request(req);
        match sign_in_core(
            req,
            &signin_req,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await?
        {
            SignInCoreResult::Success {
                response,
                token,
                set_cookie_headers,
            } => {
                let mut auth_response = AuthResponse::json(200, &response)?.with_appended_header(
                    "Set-Cookie",
                    create_session_cookie_for_remember_me(
                        &token,
                        signin_req.remember_me,
                        &ctx.config,
                    )?,
                );
                if let Some(url) = signin_req
                    .callback_url
                    .as_deref()
                    .filter(|url| !url.is_empty())
                {
                    auth_response = auth_response.with_header("Location", url);
                }
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(append_dont_remember_cookie(
                    auth_response,
                    signin_req.remember_me,
                    &ctx.config,
                )?)
            }
            SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            } => {
                let mut auth_response = AuthResponse::json(200, &response)?;
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(auth_response)
            }
        }
    }

    pub(in crate::email_password) async fn handle_sign_in_username(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInUsernameRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        if signin_req.username.is_empty() || signin_req.password.is_empty() {
            return username_error_response(
                401,
                "INVALID_USERNAME_OR_PASSWORD",
                MESSAGE_INVALID_USERNAME_OR_PASSWORD,
            );
        }

        let policy = &self.config.username;
        let validation_input =
            if policy.validation_order == Some(UsernameValidationOrder::PreNormalization) {
                policy.normalize(&signin_req.username)?
            } else {
                signin_req.username.clone()
            };
        if let Err(error) = policy.validate_value(&validation_input, 422).await {
            return Ok(error.to_auth_response());
        }
        let username = policy.normalize(&validation_input)?;

        let meta = RequestMeta::from_request(req);
        match sign_in_username_core(
            req,
            &signin_req,
            &username,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await
        {
            Ok(SignInCoreResult::Success {
                response,
                token,
                set_cookie_headers,
            }) => {
                let username_response = SignInUsernameResponse {
                    redirect: response.redirect,
                    token: response.token,
                    url: response.url,
                    user: response.user,
                };
                let mut auth_response = AuthResponse::json(200, &username_response)?
                    .with_appended_header(
                        "Set-Cookie",
                        create_session_cookie_for_remember_me(
                            &token,
                            signin_req.remember_me,
                            &ctx.config,
                        )?,
                    );
                if let Some(url) = signin_req
                    .callback_url
                    .as_deref()
                    .filter(|url| !url.is_empty())
                {
                    auth_response = auth_response.with_header("Location", url);
                }
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(append_dont_remember_cookie(
                    auth_response,
                    signin_req.remember_me,
                    &ctx.config,
                )?)
            }
            Ok(SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            }) => {
                let mut auth_response = AuthResponse::json(200, &response)?;
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(auth_response)
            }
            Err(SignInUsernameFailure::InvalidUsernameOrPassword) => username_error_response(
                401,
                "INVALID_USERNAME_OR_PASSWORD",
                MESSAGE_INVALID_USERNAME_OR_PASSWORD,
            ),
            Err(SignInUsernameFailure::EmailNotVerified) => {
                username_error_response(403, "EMAIL_NOT_VERIFIED", MESSAGE_EMAIL_NOT_VERIFIED)
            }
            Err(SignInUsernameFailure::Auth(error)) => Err(error),
        }
    }

    pub(in crate::email_password) async fn handle_is_username_available(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: IsUsernameAvailableRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        if body.username.is_empty() {
            return username_error_response(422, "INVALID_USERNAME", "Username is invalid");
        }

        if let Err(error) = self
            .config
            .username
            .validate_value(&body.username, 422)
            .await
        {
            return Ok(error.to_auth_response());
        }
        let normalized = self.config.username.normalize(&body.username)?;
        let user = ctx.database.get_user_by_username(&normalized).await?;
        let available = user.is_none();

        Ok(AuthResponse::json(
            200,
            &IsUsernameAvailableResponse { available },
        )?)
    }
}
