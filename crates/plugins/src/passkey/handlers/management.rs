use super::PasskeyHandlerOutcome;
use super::PasskeyHandlerResult;
use super::registration_value;
use crate::StatusResponse;
use crate::passkey::types::DeletePasskeyRequest;
use crate::passkey::types::PasskeyResponse;
use crate::passkey::types::UpdatePasskeyRequest;
use alibi_core::AuthContext;
use alibi_core::AuthError;
use alibi_core::AuthPasskey;
use alibi_core::AuthResult;
use alibi_core::entity::AuthUser;
use alibi_core::wire::PasskeyView;
use serde_json::Value;
use serde_json::json;
pub(in crate::passkey) async fn list_user_passkeys_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<Vec<Value>> {
    let passkeys = ctx.database.list_passkeys_by_user(&user.id()).await?;
    passkeys
        .iter()
        .map(|passkey| {
            let mut value = registration_value(passkey)?;
            // Source lists adapter rows, retaining an own SQL NULL property.
            if passkey.transports.is_none()
                && let Some(object) = value.as_object_mut()
            {
                _ = object.insert("transports".into(), Value::Null);
            }
            Ok(value)
        })
        .collect()
}

pub(in crate::passkey) async fn delete_passkey_core(
    body: &DeletePasskeyRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> PasskeyHandlerResult<StatusResponse> {
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if passkey.user_id() != user.id() {
        return Ok(PasskeyHandlerOutcome::Response(
            alibi_core::AuthResponse::new(401).with_header("content-type", "application/json"),
        ));
    }

    ctx.database.delete_passkey(&body.id).await?;
    Ok(PasskeyHandlerOutcome::Success(StatusResponse {
        status: true,
    }))
}

pub(in crate::passkey) async fn update_passkey_core(
    body: &UpdatePasskeyRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> PasskeyHandlerResult<PasskeyResponse> {
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if passkey.user_id() != user.id() {
        return Ok(PasskeyHandlerOutcome::Response(
            alibi_core::AuthResponse::json(
                401,
                &json!({ "code": "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", "message": "You are not allowed to register this passkey" }),
            )?,
        ));
    }

    let updated = ctx
        .database
        .update_passkey_name(&body.id, super::super::registration::trim_name(&body.name))
        .await?;

    Ok(PasskeyHandlerOutcome::Success(PasskeyResponse {
        passkey: PasskeyView::from(&updated),
    }))
}
