//! SIWE nonce operations use the real issuer without constructing an HTTP request.
use super::{SiwePlugin, SiweVerificationInput, validation};
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

/// Wallet identity selected by a successful SIWE proof.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiweVerifiedUser {
    pub id: String,
    pub wallet_address: String,
    pub chain_id: f64,
}
/// Result of signature verification and session issuance.
#[derive(Debug, Serialize, Deserialize)]
pub struct SiweVerificationResponse {
    pub success: bool,
    pub token: String,
    pub user: SiweVerifiedUser,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "verifySiweMessage",
            "verifySiweMessage",
            Some("/siwe/verify"),
            HttpMethod::Post,
        ),
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

pub(super) fn validate(plugin: &SiwePlugin, call: &EndpointCall) -> AuthResult<EndpointInput> {
    if call.operation_id() == "verifySiweMessage" {
        _ = validation::verify_value(call.body(), plugin.config.anonymous)
            .map_err(error_response)?;
        if call.request().is_none() {
            return Err(crate::endpoint::validation("Request is required"));
        }
        return Ok(EndpointInput {
            body: call.body().cloned(),
            query: call.query().cloned(),
        });
    }
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
    /// Verify a signed proof using the original request supplied in call options.
    /// # Errors
    /// Returns a serialization error if the input cannot be represented.
    pub fn verify_message_endpoint(
        input: &SiweVerificationInput,
    ) -> AuthResult<ServerEndpoint<SiweVerificationResponse>> {
        ServerEndpoint::new("siwe", "verifySiweMessage").with_body(input)
    }
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
    call: &EndpointCall,
    ctx: &AuthContext<S>,
) -> AuthResult<EndpointResponse> {
    let output = if call.operation_id() == "verifySiweMessage" {
        let request = call
            .request()
            .ok_or_else(|| crate::endpoint::validation("Request is required"))?;
        plugin
            .verify_response(request, ctx, call.body_as()?)
            .await?
    } else {
        plugin.issue_nonce(ctx).await?
    };
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
