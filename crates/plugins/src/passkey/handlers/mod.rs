mod authentication_flow;
mod management;
mod registration_flow;

use super::types::{
    DeletePasskeyRequest, PasskeyResponse, SessionResponse, UpdatePasskeyRequest,
    VerifyAuthenticationRequest, VerifyRegistrationRequest,
};
use super::webauthn::{
    StoredAuthenticationState, StoredCoreRegistrationState, StoredRegistrationState,
    StoredRegistrationVerifier, authentication_options_json, build_verification_core,
    build_webauthn, challenge_cookie_name, create_challenge_cookie,
    credential_id_from_authentication, decode_challenge_cookie, decode_credential_id,
    extract_registration_metadata, finish_core_authentication, finish_core_registration,
    generate_ts_user_handle, get_cookie_value, parse_transports_csv, registration_options_json,
    snapshot_passkey, transports_to_csv,
};
use super::{PasskeyConfig, PasskeyRegistrationUser};
use crate::StatusResponse;
use crate::helpers::{SessionIssueError, issue_user_session_record};
use alibi_core::entity::AuthUser;
use alibi_core::types::UpdatePasskeyAuthentication;
use alibi_core::wire::PasskeyView;
use alibi_core::{AuthContext, AuthError, AuthResult, CreatePasskey, CreateVerification};
pub(super) use authentication_flow::generate_authenticate_options_core;
pub(super) use authentication_flow::verify_authentication_core;
use chrono::{Duration, Utc};
pub(super) use management::delete_passkey_core;
pub(super) use management::list_user_passkeys_core;
pub(super) use management::update_passkey_core;
pub(super) use registration_flow::generate_register_options_core;
pub(super) use registration_flow::verify_registration_core;
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{DiscoverableKey, PublicKeyCredential, RegisterPublicKeyCredential};
use webauthn_rs_core::{
    error::WebauthnError,
    proto::{
        AttestationConveyancePreference, COSEAlgorithm, RequestRegistrationExtensions,
        UserVerificationPolicy,
    },
};

pub(super) type PasskeyHandlerResult<T> = AuthResult<PasskeyHandlerOutcome<T>>;

pub(super) enum PasskeyHandlerOutcome<T> {
    Success(T),
    Response(alibi_core::AuthResponse),
}

fn response_message<T>(status: u16, message: &str) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        alibi_core::AuthResponse::json(status, &json!({ "message": message }))
            .map_err(AuthError::from)?,
    ))
}

fn response_code<T>(status: u16, code: &str, message: &str) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        alibi_core::AuthResponse::json(status, &json!({ "code": code, "message": message }))?,
    ))
}

fn challenge_not_found<T>() -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        alibi_core::AuthResponse::json(
            400,
            &json!({ "code": "CHALLENGE_NOT_FOUND", "message": "Challenge not found" }),
        )?,
    ))
}

fn response_null<T>(status: u16) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        alibi_core::AuthResponse::json(status, &Value::Null).map_err(AuthError::from)?,
    ))
}

fn generation_origin(
    config: &PasskeyConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> String {
    if config.origin.is_empty() {
        ctx.config.base_url.clone()
    } else {
        config.origin.clone()
    }
}

fn passkey_registration_failure<T>() -> PasskeyHandlerResult<T> {
    response_code(
        500,
        "FAILED_TO_VERIFY_REGISTRATION",
        "Failed to verify registration",
    )
}

fn passkey_authentication_failure<T>() -> PasskeyHandlerResult<T> {
    response_code(400, "AUTHENTICATION_FAILED", "Authentication failed")
}

fn passkey_not_found<T>() -> PasskeyHandlerResult<T> {
    response_code(401, "PASSKEY_NOT_FOUND", "Passkey not found")
}

// The pinned adapter returns the database's nullable name in passkey rows.
// Keep this serialization local to passkey endpoints.
fn registration_value(passkey: &alibi_core::Passkey) -> AuthResult<Value> {
    let mut value = serde_json::to_value(PasskeyView::from(passkey))?;
    if passkey.name.is_none()
        && let Some(object) = value.as_object_mut()
    {
        _ = object.insert("name".into(), Value::Null);
    }
    Ok(value)
}
