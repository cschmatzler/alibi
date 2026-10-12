use super::{MagicLinkPlugin, MagicLinkSignInInput};
use crate::authentication_helpers::{JsonField, RequestBody};
use crate::endpoint::{definition, validate_fields, validation};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde::{Deserialize, Serialize};

/// A persisted and delivered mailbox challenge, without browser authority.
#[derive(Debug, Deserialize)]
pub struct MagicLinkSent {
    pub status: bool,
}

/// Single-use proof and optional verification redirects.
#[derive(Debug, Deserialize, Serialize)]
pub struct MagicLinkVerifyInput {
    pub token: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL", skip_serializing_if = "Option::is_none")]
    pub new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL", skip_serializing_if = "Option::is_none")]
    pub error_callback_url: Option<String>,
}

/// Browser authority issued after successful proof redemption without a redirect.
#[derive(Debug, Deserialize)]
pub struct MagicLinkVerified {
    pub token: String,
    pub user: Box<alibi_core::UserView>,
    pub session: Box<alibi_core::wire::SessionView>,
}

const VERIFY_FIELDS: &[JsonField] = &[
    JsonField::string("token", true),
    JsonField::string("callbackURL", false),
    JsonField::string("errorCallbackURL", false),
    JsonField::string("newUserCallbackURL", false),
];

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "signInMagicLink",
            "signInWithMagicLink",
            Some("/sign-in/magic-link"),
            HttpMethod::Post,
        ),
        definition(
            "magicLinkVerify",
            "verifyMagicLink",
            Some("/magic-link/verify"),
            HttpMethod::Get,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let input = if call.operation_id() == "verifyMagicLink" {
        EndpointInput {
            body: call.body().cloned(),
            query: Some(validate_fields(call.query(), "query", VERIFY_FIELDS)?),
        }
    } else {
        EndpointInput {
            body: Some(validate_fields(
                call.body(),
                "body",
                MagicLinkSignInInput::FIELDS,
            )?),
            query: call.query().cloned(),
        }
    };
    if call.headers().is_none() {
        return Err(validation("Headers is required"));
    }
    Ok(input)
}

impl MagicLinkPlugin {
    /// Redeem a delivered proof through installed server endpoint hooks.
    ///
    /// Redirects return the endpoint's intentional API error with Location and cookies.
    /// # Errors
    /// Returns an error if the supplied query cannot be serialized.
    pub fn verify_endpoint(
        query: &MagicLinkVerifyInput,
    ) -> AuthResult<ServerEndpoint<MagicLinkVerified>> {
        ServerEndpoint::new("magic-link", "magicLinkVerify").with_query(query)
    }

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
        let output = if call.operation_id() == "verifyMagicLink" {
            self.verify_core(call, ctx, call.query_as()?).await?
        } else {
            if let Some(request) = call.request() {
                alibi_core::middleware::CsrfMiddleware::new(
                    alibi_core::middleware::CsrfConfig::new(),
                    ctx.config.clone(),
                )
                .check_login_origin(request)?;
            }
            self.sign_in_core(call.request(), ctx, call.body_as()?)
                .await?
        };
        if output.status == 302 {
            let mut response = EndpointResponse::redirect(
                output.headers.get("location").cloned().unwrap_or_default(),
            );
            response.merge_headers(output.headers);
            return Ok(response);
        }
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
