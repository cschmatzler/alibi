use alibi_core::field_policy::FieldInputError;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, CreateUser};
use serde_json::Value;

/// Parse passwordless signup fields before username create-hook validation.
/// Endpoint input transforms, database hooks, and adapter transforms are
/// separate stages; display fallback uses the parsed username.
pub(crate) fn prepare_additional_user_fields(
    ctx: &AuthContext<impl AuthSchema>,
    data: &mut CreateUser,
) -> AuthResult<()> {
    apply_creation_input_defaults(ctx, data);
    let username_enabled = ctx
        .get_metadata("username.enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !username_enabled {
        data.username = None;
        data.display_username = None;
        let mut input = data
            .additional_fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<indexmap::IndexMap<_, _>>();
        _ = input.shift_remove("username");
        _ = input.shift_remove("displayUsername");
        data.additional_fields = ctx
            .parse_user_fields(&input, true)
            .map_err(field_input_error)?;
        return Ok(());
    }
    let policy = ctx
        .extensions
        .get::<alibi_core::utils::username::UsernameConfig>()
        .map(|policy| (*policy).clone())
        .unwrap_or_default();
    // Retain raw extension values through schema parsing and username hooks.
    let mut input = data
        .additional_fields
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<indexmap::IndexMap<_, _>>();
    if !policy.include_display_username {
        _ = input.shift_remove("displayUsername");
    }
    if let Some(username) = &data.username {
        _ = input.insert(
            "username".into(),
            alibi_core::utils::json::JsValue::String(username.clone().into()),
        );
    }
    if policy.include_display_username
        && let Some(display) = &data.display_username
    {
        _ = input.insert(
            "displayUsername".into(),
            alibi_core::utils::json::JsValue::String(display.clone().into()),
        );
    }
    data.additional_fields = ctx
        .parse_user_fields(&input, true)
        .map_err(field_input_error)?;
    data.username = data
        .additional_fields
        .get("username")
        .and_then(alibi_core::utils::json::JsValue::as_str)
        .map(str::to_owned);
    data.display_username = data
        .additional_fields
        .get("displayUsername")
        .and_then(alibi_core::utils::json::JsValue::as_str)
        .map(str::to_owned);
    Ok(())
}

/// Built-in schema defaults introduced by parsed create input, before identity
/// validation. Direct identity creation instead receives adapter defaults after
/// its database hooks. Application additional schemas are handled separately.
pub(crate) fn apply_creation_input_defaults(
    ctx: &AuthContext<impl AuthSchema>,
    data: &mut CreateUser,
) {
    if ctx.config.user_validation.is_none() {
        return;
    }
    let enabled = |key| {
        ctx.get_metadata(key)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    if enabled("admin.enabled") {
        _ = data.banned.get_or_insert(false);
    }
    if enabled("anonymous.enabled") {
        _ = data.is_anonymous.get_or_insert(false);
    }
    if enabled("two_factor.enabled") {
        _ = data.two_factor_enabled.get_or_insert(false);
    }
}

/// Surface a rejected additional-field input as the published 400 response.
pub(crate) fn field_input_error(error: FieldInputError) -> AuthError {
    match error {
        FieldInputError::Validation { code, message } => AuthError::Api {
            status: 400,
            code: Some(code.into()),
            message,
        },
        FieldInputError::Transform(error) => error,
    }
}
