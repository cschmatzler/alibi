//! Public credential sign-in uses logical input and the shared session issuer.
use super::types::SignInCoreResult;
use super::{EmailPasswordPlugin, SignInEmailRequest, SignInEmailResponse, sign_in_core};
use crate::authentication_helpers::RequestBody;
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod, RequestMeta};

pub(super) fn definitions(username_enabled: bool) -> Vec<EndpointDefinition> {
    let mut definitions = vec![
        crate::endpoint::definition(
            "signInEmail",
            "signInEmail",
            Some("/sign-in/email"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "signUpEmail",
            "signUpWithEmailAndPassword",
            Some("/sign-up/email"),
            HttpMethod::Post,
        ),
    ];
    if username_enabled {
        definitions.push(crate::endpoint::definition(
            "signInUsername",
            "signInUsername",
            Some("/sign-in/username"),
            HttpMethod::Post,
        ));
        definitions.push(crate::endpoint::definition(
            "isUsernameAvailable",
            "isUsernameAvailable",
            Some("/is-username-available"),
            HttpMethod::Post,
        ));
    }
    definitions
}
pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    if call.operation_id() == "signInUsername" {
        return Ok(EndpointInput {
            body: Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[
                    crate::authentication_helpers::JsonField::string("username", true),
                    crate::authentication_helpers::JsonField::string("password", true),
                    crate::authentication_helpers::JsonField {
                        name: "rememberMe",
                        kind: crate::authentication_helpers::JsonFieldKind::Boolean,
                        required: false,
                    },
                    crate::authentication_helpers::JsonField::string("callbackURL", false),
                ],
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "isUsernameAvailable" {
        return Ok(EndpointInput {
            body: Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                &[crate::authentication_helpers::JsonField::string(
                    "username", true,
                )],
            )?),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "signUpWithEmailAndPassword" {
        _ = crate::endpoint::validate_fields(
            call.body(),
            "body",
            super::SignUpEmailRequest::FIELDS,
        )?;
        return Ok(EndpointInput {
            body: call.body().cloned(),
            query: call.query().cloned(),
        });
    }
    let mut body =
        crate::endpoint::validate_fields(call.body(), "body", SignInEmailRequest::FIELDS)?;
    if let JsValue::Object(body) = &mut body {
        _ = body
            .entry("rememberMe".into())
            .or_insert(JsValue::Bool(true));
    }
    Ok(EndpointInput {
        body: Some(body),
        query: call.query().cloned(),
    })
}
impl EmailPasswordPlugin {
    /// Sign in using the installed username policy and credential service.
    ///
    /// # Errors
    /// Returns an error if the input cannot be serialized.
    pub fn sign_in_username_endpoint(
        input: &super::SignInUsernameRequest,
    ) -> AuthResult<ServerEndpoint<SignInEmailResponse>> {
        ServerEndpoint::new("email-password", "signInUsername").with_body(input)
    }

    /// Check a guest-supplied username through the installed username policy.
    #[must_use]
    pub fn is_username_available_endpoint(
        username: impl Into<String>,
    ) -> ServerEndpoint<super::IsUsernameAvailableResponse> {
        ServerEndpoint::new("email-password", "isUsernameAvailable").with_body_value(
            JsValue::Object(
                [("username".into(), JsValue::String(username.into()))]
                    .into_iter()
                    .collect(),
            ),
        )
    }

    /// Sign in through the installed credential service and server hooks.
    pub fn sign_in_email_endpoint(
        body: &SignInEmailRequest,
    ) -> AuthResult<ServerEndpoint<SignInEmailResponse>> {
        ServerEndpoint::new("email-password", "signInEmail").with_body(body)
    }
    /// Create a credential owner through the installed sign-up service and hooks.
    pub fn sign_up_email_endpoint(
        body: &super::SignUpEmailRequest,
    ) -> AuthResult<ServerEndpoint<super::SignUpEmailResponse<alibi_core::field_policy::FieldOutput>>>
    {
        ServerEndpoint::new("email-password", "signUpEmail").with_body(body)
    }
    pub(super) async fn call_sign_in_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "signInUsername" {
            let body: super::SignInUsernameRequest = call.body_as()?;
            alibi_core::session::cookie_cache::runtime::set_issuance_preference(
                call,
                body.remember_me == Some(false),
            );
            let headers = call.headers().cloned().unwrap_or_default();
            let meta = RequestMeta {
                ip_address: Some(
                    ctx.config
                        .advanced
                        .ip_address
                        .resolve_ip(&headers)
                        .unwrap_or_default(),
                ),
                user_agent: Some(headers.get("user-agent").cloned().unwrap_or_default()),
            };
            let output = self.username_sign_in_core(call, ctx, body, &meta).await?;
            let mut response = if output.status >= 400 {
                EndpointResponse::error(crate::endpoint::error_response(output.clone()))
            } else {
                EndpointResponse::value(alibi_core::utils::json::from_slice(&output.body)?)
            };
            response.set_status(Some(output.status));
            response.merge_headers(output.headers);
            return Ok(response);
        }
        if call.operation_id() == "isUsernameAvailable" {
            let output = self
                .username_availability_core(ctx, call.body_as()?)
                .await?;
            let mut response = if output.status >= 400 {
                EndpointResponse::error(crate::endpoint::error_response(output.clone()))
            } else {
                EndpointResponse::value(alibi_core::utils::json::from_slice(&output.body)?)
            };
            response.set_status(Some(output.status));
            response.merge_headers(output.headers);
            return Ok(response);
        }
        if call.operation_id() == "signUpWithEmailAndPassword" {
            return self.call_signup_endpoint(call, ctx).await;
        }
        let body: SignInEmailRequest = call.body_as()?;
        if let Some(request) = call.request() {
            alibi_core::middleware::CsrfMiddleware::new(
                alibi_core::middleware::CsrfConfig::new(),
                ctx.config.clone(),
            )
            .check_login_origin(request)?;
            if let Some(url) = body.callback_url.as_deref().filter(|url| !url.is_empty())
                && !ctx.config.current_origin_check_disabled()
                && !ctx.config.is_redirect_target_trusted(url)
            {
                return Err(AuthError::forbidden("Invalid callbackURL"));
            }
        }
        alibi_core::session::cookie_cache::runtime::set_issuance_preference(
            call,
            body.remember_me == Some(false),
        );
        let headers = call.headers().cloned().unwrap_or_default();
        let meta = RequestMeta {
            ip_address: Some(
                ctx.config
                    .advanced
                    .ip_address
                    .resolve_ip(&headers)
                    .unwrap_or_default(),
            ),
            user_agent: Some(headers.get("user-agent").cloned().unwrap_or_default()),
        };
        match Box::pin(sign_in_core(
            call,
            &body,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        ))
        .await?
        {
            SignInCoreResult::Success {
                response,
                token,
                set_cookie_headers,
            } => {
                let mut output = EndpointResponse::json(&response)?;
                output.merge_headers(crate::authentication_helpers::session_cookie_headers(
                    &ctx.config,
                    &token,
                    body.remember_me == Some(false),
                )?);
                if let Some(url) = body.callback_url.as_deref().filter(|url| !url.is_empty()) {
                    output = output.with_header("location", url);
                }
                for cookie in set_cookie_headers {
                    output = output.with_header("set-cookie", cookie);
                }
                Ok(output)
            }
            SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            } => {
                let mut output = EndpointResponse::json(&response)?;
                for cookie in set_cookie_headers {
                    output = output.with_header("set-cookie", cookie);
                }
                Ok(output)
            }
        }
    }
    async fn call_signup_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let raw = call.body().cloned().unwrap_or(JsValue::Null);
        let mut parsed = raw.clone();
        if !self.config.enable_username
            && let JsValue::Object(body) = &mut parsed
        {
            _ = body.shift_remove("username");
            _ = body.shift_remove("displayUsername");
        }
        let mut body: super::SignUpEmailRequest = alibi_core::utils::json::from_value(parsed)?;
        if let Some(request) = call.request() {
            alibi_core::middleware::CsrfMiddleware::new(
                alibi_core::middleware::CsrfConfig::new(),
                ctx.config.clone(),
            )
            .check_login_origin(request)?;
            if let Some(url) = body.callback_url.as_deref().filter(|url| !url.is_empty())
                && !ctx.config.current_origin_check_disabled()
                && !ctx.config.is_redirect_target_trusted(url)
            {
                return Err(AuthError::forbidden("Invalid callbackURL"));
            }
        }
        if let Some(response) = self.prepare_signup_input(&mut body, raw, call, ctx).await? {
            return Err(crate::endpoint::error_response(response));
        }
        alibi_core::session::cookie_cache::runtime::set_issuance_preference(
            call,
            body.remember_me == Some(false),
        );
        let headers = call.headers().cloned().unwrap_or_default();
        let meta = RequestMeta {
            ip_address: Some(
                ctx.config
                    .advanced
                    .ip_address
                    .resolve_ip(&headers)
                    .unwrap_or_default(),
            ),
            user_agent: Some(headers.get("user-agent").cloned().unwrap_or_default()),
        };
        let (value, cookies) = Box::pin(super::sign_up_core(
            call.request(),
            &body,
            &self.config,
            &meta,
            ctx,
        ))
        .await?;
        let mut response = EndpointResponse::json(&value)?;
        for cookie in cookies.into_iter().flatten() {
            response = response.with_header("set-cookie", cookie);
        }
        Ok(response)
    }
}
