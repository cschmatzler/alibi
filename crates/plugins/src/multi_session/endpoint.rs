use super::MultiSessionPlugin;
use crate::endpoint::{definition, validation};
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointInput, ServerEndpoint};
use alibi_core::{AuthResult, HttpMethod};
use serde::Deserialize;

/// An active account selected by the caller's signed device-session proofs.
#[derive(Debug, Deserialize)]
pub struct DeviceSession {
    pub user: Box<alibi_core::UserView>,
    pub session: Box<alibi_core::wire::SessionView>,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![definition(
        "listDeviceSessions",
        "listDeviceSessions",
        Some("/multi-session/list-device-sessions"),
        HttpMethod::Get,
    )]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    if call.headers().is_none() {
        return Err(validation("Headers is required"));
    }
    Ok(EndpointInput {
        body: call.body().cloned(),
        query: call.query().cloned(),
    })
}

impl MultiSessionPlugin {
    /// List active distinct accounts from genuine signed browser proofs.
    #[must_use]
    pub const fn list_device_sessions_endpoint() -> ServerEndpoint<Vec<DeviceSession>> {
        ServerEndpoint::new("multi-session", "listDeviceSessions")
    }
}
