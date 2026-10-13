//! Public device issuance without manufacturing an HTTP request.
pub use super::types::{DeviceCodeRequest, DeviceCodeResponse};
use super::{DeviceAuthorizationPlugin, DeviceRequestKind, no_store, validate_device_json_body};
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointResponse, ServerEndpoint};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![crate::endpoint::definition(
        "deviceCode",
        "deviceCode",
        Some("/device/code"),
        HttpMethod::Post,
    )]
}

impl DeviceAuthorizationPlugin {
    /// Issue a device proof through the application's public server dispatcher.
    /// # Errors
    /// Returns an input serialization error.
    pub fn device_code_endpoint(
        request: &DeviceCodeRequest,
    ) -> AuthResult<ServerEndpoint<DeviceCodeResponse>> {
        ServerEndpoint::new("device-authorization", "deviceCode").with_body(request)
    }

    pub(super) async fn issue_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let body: serde_json::Value = call
            .body()
            .map_or_else(|| Ok(serde_json::Value::Null), serde_json::to_value)?;
        let output = if let Some(grant) = &self.config.grant {
            self.application_issuance_body(body, call.request(), ctx, grant.as_ref())
                .await?
        } else {
            match validate_device_json_body(&body, DeviceRequestKind::Issuance) {
                Ok(()) => {
                    call.set_response_header("Cache-Control", "no-store");
                    call.set_response_header("Pragma", "no-cache");
                    no_store(
                        self.issue_device_code(serde_json::from_value(body)?, ctx)
                            .await?,
                    )
                }
                Err(output) => output,
            }
        };
        let value = alibi_core::utils::json::from_slice::<JsValue>(&output.body)?;
        let mut response = if output.status >= 400 {
            EndpointResponse::error(crate::endpoint::error_response(output.clone()))
                .with_error_body(value)
        } else {
            EndpointResponse::value(value)
        };
        response.set_status(Some(output.status));
        response.merge_headers(output.headers);
        Ok(response)
    }
}
