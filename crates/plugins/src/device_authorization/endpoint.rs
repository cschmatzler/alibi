//! Public device issuance without manufacturing an HTTP request.
pub use super::types::{
    DeviceActionResponse, DeviceCodeRequest, DeviceCodeResponse, DeviceTokenResponse,
};
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
        crate::endpoint::definition(
            "deviceApprove",
            "deviceApprove",
            Some("/device/approve"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "deviceDeny",
            "deviceDeny",
            Some("/device/deny"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "deviceToken",
            "deviceToken",
            Some("/device/token"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let body = if matches!(call.operation_id(), "deviceApprove" | "deviceDeny") {
        let body = crate::endpoint::validate_fields(
            call.body(),
            "body",
            &[crate::authentication_helpers::JsonField::string(
                "userCode", true,
            )],
        )?;
        if call.headers().is_none() {
            return Err(crate::endpoint::validation("Headers is required"));
        }
        Some(body)
    } else if call.operation_id() == "deviceToken" {
        Some(validate_token_body(call.body())?)
    } else {
        call.body().cloned()
    };
    Ok(EndpointInput {
        body,
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

fn validate_token_body(body: Option<&JsValue>) -> AuthResult<JsValue> {
    use crate::authentication_helpers::{JsonFieldKind, field_issue, json_type};
    let Some(object) = body.and_then(JsValue::as_object) else {
        return Err(crate::endpoint::validation(format!(
            "[body] Invalid input: expected object, received {}",
            json_type(body)
        )));
    };
    let mut issues = Vec::new();
    if object.get("grant_type").and_then(JsValue::as_str) != Some(super::DEVICE_GRANT_TYPE) {
        issues.push(format!(
            "[body.grant_type] Invalid input: expected \"{}\"",
            super::DEVICE_GRANT_TYPE
        ));
    }
    for field in ["device_code", "client_id"] {
        let value = object.get(field);
        if let Some(issue) = field_issue(JsonFieldKind::String, value, json_type(value)) {
            issues.push(format!("[body.{field}] {issue}"));
        }
    }
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    Ok(JsValue::Object(
        object
            .iter()
            .filter(|(name, _)| ["grant_type", "device_code", "client_id"].contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    ))
}

impl DeviceAuthorizationPlugin {
    /// Redeem an approved device proof for its owner's bearer session.
    #[must_use]
    pub fn device_token_endpoint(
        device_code: impl Into<String>,
        client_id: impl Into<String>,
    ) -> ServerEndpoint<DeviceTokenResponse> {
        ServerEndpoint::new("device-authorization", "deviceToken").with_body_value(JsValue::Object(
            [
                (
                    "grant_type".into(),
                    JsValue::String(super::DEVICE_GRANT_TYPE.into()),
                ),
                ("device_code".into(), JsValue::String(device_code.into())),
                ("client_id".into(), JsValue::String(client_id.into())),
            ]
            .into_iter()
            .collect(),
        ))
    }

    pub(super) async fn token_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        call.set_response_header("Cache-Control", "no-store");
        call.set_response_header("Pragma", "no-cache");
        endpoint_response(no_store(
            self.redeem_device_token(call.body_as()?, call, ctx).await?,
        ))
    }

    /// Approve a pending device grant previously claimed by the caller's session.
    #[must_use]
    pub fn device_approve_endpoint(
        user_code: impl Into<String>,
    ) -> ServerEndpoint<DeviceActionResponse> {
        ServerEndpoint::new("device-authorization", "deviceApprove").with_body_value(
            JsValue::Object(
                [("userCode".into(), JsValue::String(user_code.into()))]
                    .into_iter()
                    .collect(),
            ),
        )
    }

    /// Deny a pending device grant previously claimed by the caller's session.
    #[must_use]
    pub fn device_deny_endpoint(
        user_code: impl Into<String>,
    ) -> ServerEndpoint<DeviceActionResponse> {
        ServerEndpoint::new("device-authorization", "deviceDeny").with_body_value(JsValue::Object(
            [("userCode".into(), JsValue::String(user_code.into()))]
                .into_iter()
                .collect(),
        ))
    }

    pub(super) async fn decision_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let decision = if call.operation_id() == "deviceDeny" {
            super::DeviceDecision::Deny
        } else {
            super::DeviceDecision::Approve
        };
        endpoint_response(
            self.decision_core(call, ctx, decision, call.body_as()?)
                .await?,
        )
    }

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
