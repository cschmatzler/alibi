use super::{MultiSessionPlugin, SessionTokenRequest};
use crate::authentication_helpers::RequestBody;
use crate::endpoint::{definition, validate_fields, validation};
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointInput, ServerEndpoint};
use alibi_core::{AuthResult, HttpMethod};
use serde::Deserialize;

/// An active account selected by the caller's signed device-session proofs.
#[derive(Debug, Deserialize)]
pub struct DeviceSession {
    pub user: Box<alibi_core::UserView>,
    pub session: Box<alibi_core::wire::SessionView>,
}

/// A selected device session was revoked and its browser proof retired.
#[derive(Debug, Deserialize)]
pub struct DeviceSessionRevoked {
    pub status: bool,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "revokeDeviceSession",
            "revokeDeviceSession",
            Some("/multi-session/revoke"),
            HttpMethod::Post,
        ),
        definition(
            "listDeviceSessions",
            "listDeviceSessions",
            Some("/multi-session/list-device-sessions"),
            HttpMethod::Get,
        ),
        definition(
            "setActiveSession",
            "setActiveSession",
            Some("/multi-session/set-active"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let body = if matches!(
        call.operation_id(),
        "setActiveSession" | "revokeDeviceSession"
    ) {
        Some(validate_fields(
            call.body(),
            "body",
            SessionTokenRequest::FIELDS,
        )?)
    } else {
        call.body().cloned()
    };
    if call.headers().is_none() {
        return Err(validation("Headers is required"));
    }
    Ok(EndpointInput {
        body,
        query: call.query().cloned(),
    })
}

impl MultiSessionPlugin {
    /// Revoke a device proof under the caller's authenticated session.
    #[must_use]
    pub fn revoke_device_session_endpoint(
        session_token: impl Into<String>,
    ) -> ServerEndpoint<DeviceSessionRevoked> {
        ServerEndpoint::new("multi-session", "revokeDeviceSession").with_body_value(
            alibi_core::utils::json::JsValue::Object(
                [(
                    "sessionToken".into(),
                    alibi_core::utils::json::JsValue::String(session_token.into()),
                )]
                .into_iter()
                .collect(),
            ),
        )
    }

    /// Select an account using its genuine signed device proof.
    #[must_use]
    pub fn set_active_session_endpoint(
        session_token: impl Into<String>,
    ) -> ServerEndpoint<DeviceSession> {
        ServerEndpoint::new("multi-session", "setActiveSession").with_body_value(
            alibi_core::utils::json::JsValue::Object(
                [(
                    "sessionToken".into(),
                    alibi_core::utils::json::JsValue::String(session_token.into()),
                )]
                .into_iter()
                .collect(),
            ),
        )
    }

    /// List active distinct accounts from genuine signed browser proofs.
    #[must_use]
    pub const fn list_device_sessions_endpoint() -> ServerEndpoint<Vec<DeviceSession>> {
        ServerEndpoint::new("multi-session", "listDeviceSessions")
    }
}
