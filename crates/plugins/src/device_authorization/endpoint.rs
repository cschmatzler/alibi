//! Public device issuance without manufacturing an HTTP request.
pub use super::types::{DeviceCodeRequest, DeviceCodeResponse};
use super::{DeviceAuthorizationPlugin, DeviceRequestKind, no_store, validate_device_json_body};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        crate::endpoint::definition(
            "deviceCode",
            "deviceCode",
            Some("/device/code"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "deviceVerify",
            "deviceVerify",
            Some("/device"),
            HttpMethod::Get,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: call.body().cloned(),
        query: if call.operation_id() == "deviceVerify" {
            Some(crate::endpoint::validate_fields(
                call.query(),
                "query",
                &[crate::authentication_helpers::JsonField::string(
                    "user_code",
                    true,
                )],
            )?)
        } else {
            call.query().cloned()
        },
    })
}

impl DeviceAuthorizationPlugin {
    /// Look up a device code and claim a pending proof under the caller's session.
    #[must_use]
    pub fn device_verify_endpoint(
        user_code: impl Into<String>,
    ) -> ServerEndpoint<serde_json::Value> {
        ServerEndpoint::new("device-authorization", "deviceVerify").with_query_value(
            JsValue::Object(
                [("user_code".into(), JsValue::String(user_code.into()))]
                    .into_iter()
                    .collect(),
            ),
        )
    }

    pub(super) async fn verify_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        #[derive(serde::Deserialize)]
        struct Query {
            user_code: String,
        }
        let query: Query = call.query_as()?;
        let output = self.verify_core(call, ctx, query.user_code).await?;
        endpoint_response(output)
    }

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
        endpoint_response(output)
    }
}

fn endpoint_response(output: alibi_core::AuthResponse) -> AuthResult<EndpointResponse> {
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
