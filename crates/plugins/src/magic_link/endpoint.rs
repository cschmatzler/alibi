use super::{MagicLinkPlugin, MagicLinkSignInInput};
use crate::authentication_helpers::RequestBody;
use crate::endpoint::{definition, validate_fields, validation};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde::Deserialize;

/// A persisted and delivered mailbox challenge, without browser authority.
#[derive(Debug, Deserialize)]
pub struct MagicLinkSent {
    pub status: bool,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![definition(
        "signInMagicLink",
        "signInWithMagicLink",
        Some("/sign-in/magic-link"),
        HttpMethod::Post,
    )]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let body = validate_fields(call.body(), "body", MagicLinkSignInInput::FIELDS)?;
    if call.headers().is_none() && call.request().is_none() {
        return Err(validation("Headers is required"));
    }
    Ok(EndpointInput {
        body: Some(body),
        query: call.query().cloned(),
    })
}

impl MagicLinkPlugin {
    /// Request a mailbox challenge through installed server endpoint hooks.
    ///
    /// # Errors
    /// Returns an error if the supplied input cannot be serialized.
    pub fn sign_in_endpoint(
        input: &MagicLinkSignInInput,
    ) -> AuthResult<ServerEndpoint<MagicLinkSent>> {
        ServerEndpoint::new("magic-link", "signInMagicLink").with_body(input)
    }

    pub(super) async fn call_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        if let Some(request) = call.request() {
            alibi_core::middleware::CsrfMiddleware::new(
                alibi_core::middleware::CsrfConfig::new(),
                ctx.config.clone(),
            )
            .check_login_origin(request)?;
        }
        let output = self
            .sign_in_core(call.request(), ctx, call.body_as()?)
            .await?;
        let mut response = if output.status >= 400 {
            EndpointResponse::error(crate::endpoint::error_response(output.clone()))
                .without_error_body()
        } else {
            EndpointResponse::value(alibi_core::utils::json::from_slice(&output.body)?)
        };
        response.set_status(Some(output.status));
        response.merge_headers(output.headers);
        Ok(response)
    }
}
