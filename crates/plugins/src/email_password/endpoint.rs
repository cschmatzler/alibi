//! Public credential sign-in uses logical input and the shared session issuer.
use super::types::SignInCoreResult;
use super::{EmailPasswordPlugin, SignInEmailRequest, SignInEmailResponse, sign_in_core};
use crate::authentication_helpers::RequestBody;
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod, RequestMeta};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![crate::endpoint::definition(
        "signInEmail",
        "signInEmail",
        Some("/sign-in/email"),
        HttpMethod::Post,
    )]
}
pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
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
    /// Sign in through the installed credential service and server hooks.
    pub fn sign_in_email_endpoint(
        body: &SignInEmailRequest,
    ) -> AuthResult<ServerEndpoint<SignInEmailResponse>> {
        ServerEndpoint::new("email-password", "signInEmail").with_body(body)
    }
    pub(super) async fn call_sign_in_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
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
}
