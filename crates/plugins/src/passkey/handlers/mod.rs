mod authentication_flow;
mod management;
mod registration_flow;

use super::PasskeyConfig;
use alibi_core::error::codes;
use alibi_core::{AuthContext, AuthError, AuthResult};
pub(super) use authentication_flow::generate_authenticate_options_core;
pub(super) use authentication_flow::verify_authentication_core;
pub(super) use management::delete_passkey_core;
pub(super) use management::list_user_passkeys_core;
pub(super) use management::update_passkey_core;
pub(super) use registration_flow::generate_register_options_core;
pub(super) use registration_flow::verify_registration_core;
use serde_json::{Value, json};

pub(super) type PasskeyHandlerResult<T> = AuthResult<PasskeyHandlerOutcome<T>>;

pub(super) enum PasskeyHandlerOutcome<T> {
    Success(T),
    Response(alibi_core::AuthResponse),
}

fn credential_descriptor(
    passkey: &impl alibi_core::AuthPasskey,
) -> AuthResult<alibi_core::utils::json::JsValue> {
    use alibi_core::utils::json::JsValue;
    let transports = super::webauthn::stored_transports(passkey.transports())?;
    let credential_id = passkey.credential_id().replace('=', "");
    if !credential_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AuthError::internal(
            "Stored passkey credential ID is not valid base64url",
        ));
    }
    Ok(JsValue::Object(
        [
            ("id".into(), JsValue::String(credential_id.into())),
            ("transports".into(), transports),
            ("type".into(), JsValue::String("public-key".into())),
        ]
        .into(),
    ))
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
            &json!({ "code": codes::CHALLENGE_NOT_FOUND, "message": "Challenge not found" }),
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
        400,
        codes::FAILED_TO_VERIFY_REGISTRATION,
        "Failed to verify registration",
    )
}

fn passkey_authentication_failure<T>() -> PasskeyHandlerResult<T> {
    response_code(400, codes::AUTHENTICATION_FAILED, "Authentication failed")
}

fn passkey_not_found<T>() -> PasskeyHandlerResult<T> {
    response_code(401, codes::PASSKEY_NOT_FOUND, "Passkey not found")
}
