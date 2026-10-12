//! SIWE nonce operations use the real issuer without constructing an HTTP request.
use super::{SiwePlugin, validation};
use crate::authentication_helpers::json_type;
use crate::endpoint::{definition, error_response};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};
use serde::{Deserialize, Serialize};

/// An issued, stored ERC-4361 challenge.
#[derive(Debug, Serialize, Deserialize)]
pub struct SiweNonceResponse {
    pub nonce: String,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "getSiweNonce",
            "getSiweNonce",
            Some("/siwe/nonce"),
            HttpMethod::Post,
        ),
        definition(
            "getNonce",
            "getNonce",
            Some("/siwe/get-nonce"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    if let Some(value) = call.body() {
        let object = value.as_object().ok_or_else(|| {
            crate::endpoint::validation(format!(
                "[body] Invalid input: expected object, received {}",
                json_type(Some(value)),
            ))
        })?;
        if let Some(message) =
            validation::unknown_field_keys(object.keys().map(String::as_str), &[])
        {
            return Err(crate::endpoint::validation(message));
        }
    }
    Ok(EndpointInput {
        body: call.body().cloned(),
        query: call.query().cloned(),
    })
}

impl SiwePlugin {
    /// Generate and persist a nonce through installed server dispatch hooks.
    #[must_use]
    pub fn get_siwe_nonce_endpoint() -> ServerEndpoint<SiweNonceResponse> {
        ServerEndpoint::new("siwe", "getSiweNonce")
    }
    /// Generate and persist a nonce through the public legacy alias.
    #[must_use]
    pub fn get_nonce_endpoint() -> ServerEndpoint<SiweNonceResponse> {
        ServerEndpoint::new("siwe", "getNonce")
    }
}

pub(super) async fn execute<S: AuthSchema>(
    plugin: &SiwePlugin,
    ctx: &AuthContext<S>,
) -> AuthResult<EndpointResponse> {
    let output = plugin.issue_nonce(ctx).await?;
    let body = alibi_core::utils::json::from_slice::<JsValue>(&output.body)?;
    let mut response = if output.status >= 400 {
        EndpointResponse::error(error_response(output.clone())).with_error_body(body)
    } else {
        EndpointResponse::value(body)
    };
    response.set_status(Some(output.status));
    response.merge_headers(output.headers);
    Ok(response)
}
