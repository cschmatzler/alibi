use alibi_core::entity::AuthUser;
use alibi_core::utils::username::UsernameConfig;
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, ErrorCodeMessageResponse,
    UpdateUser, UpdateUserRequest,
};

/// Handle user profile update.
#[expect(
    clippy::too_many_lines,
    reason = "Keep field validation and user-update callbacks adjacent to the persistence operation"
)]
pub async fn handle_update_user<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    context: &AuthContext<S>,
) -> AuthResult<AuthResponse> {
    let (current_user, current_session) = context
        .require_cached_session(req)
        .await
        .map_err(crate::helpers::unauthorized_if_session_missing)?;
    let body: serde_json::Value = req
        .body_as_json()
        .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {e}")))?;
    let Some(body) = body.as_object() else {
        let actual = match &body {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "record",
        };
        return Ok(AuthResponse::json(
            400,
            &ErrorCodeMessageResponse {
                code: Some("VALIDATION_ERROR".to_owned()),
                message: format!("[body] Invalid input: expected record, received {actual}"),
            },
        )?);
    };

    if body.get("email").is_some_and(|value| match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
    }) {
        return Err(AuthError::bad_request("Email can not be updated"));
    }

    // Role changes require the administrator's authorization, independently
    // of any application-defined additional field policy.
    if body.contains_key("role") {
        return Err(AuthError::Api {
            status: 400,
            code: Some("FIELD_NOT_ALLOWED".into()),
            message: "role is not allowed to be set".into(),
        });
    }

    let raw_body: alibi_core::utils::json::JsValue = req.body_as_json()?;
    crate::last_login_method::reject_last_login_method_input(
        context,
        raw_body.get("lastLoginMethod"),
    )?;

    let mut writable_body = body.clone();
    let _ = writable_body.remove("email");
    let update_req: UpdateUserRequest =
        serde_json::from_value(serde_json::Value::Object(writable_body))
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {e}")))?;
    let policy = context.extensions.get::<UsernameConfig>();
    if let Some(policy) = &policy {
        if let Some(value) = &update_req.username {
            policy.validate_hook_value(value).await?;
            let normalized = policy.normalize(value)?;
            let current_username = current_user.username();
            if policy.immutable_username
                && current_username
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && *value != normalized)
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "USERNAME_IS_IMMUTABLE",
                    message: "Username cannot be updated",
                });
            }
            if let Some(existing_user) = context.database.get_user_by_username(&normalized).await?
                && existing_user.id() != current_user.id()
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "USERNAME_IS_ALREADY_TAKEN",
                    message: "Username is already taken. Please try another.",
                });
            }
        }
        if let Some(value) = &update_req.display_username {
            policy.validate_display(value).await?;
        }
    }
    let mut input_fields = raw_body
        .as_object()
        .ok_or_else(|| AuthError::bad_request("Invalid JSON object"))?
        .clone();
    if policy.is_none() {
        _ = input_fields.shift_remove("username");
    }
    if policy
        .as_ref()
        .is_none_or(|policy| !policy.include_display_username)
    {
        _ = input_fields.shift_remove("displayUsername");
    }
    let additional_fields = context
        .parse_user_fields(&input_fields, false)
        .map_err(|error| match error {
            alibi_core::field_policy::FieldInputError::Validation { code, message } => {
                AuthError::Api {
                    status: 400,
                    code: Some(code.into()),
                    message,
                }
            }
            alibi_core::field_policy::FieldInputError::Transform(error) => error,
        })?;
    let username = additional_fields
        .get("username")
        .and_then(alibi_core::utils::json::JsValue::as_str)
        .map(str::to_owned);
    let display_username = additional_fields
        .get("displayUsername")
        .and_then(alibi_core::utils::json::JsValue::as_str)
        .map(str::to_owned);

    let clear_phone = context
        .get_metadata("phone-number.enabled")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && body.get("phoneNumber") == Some(&serde_json::Value::Null);
    let has_changes = additional_fields.has_input_fields()
        || clear_phone
        || update_req.name.is_some()
        || update_req.image.is_some()
        || username.is_some()
        || display_username.is_some()
        || update_req.metadata.is_some();
    if !has_changes {
        return Err(AuthError::bad_request("No fields to update"));
    }

    let update_user = UpdateUser {
        provider_email_verified: None,
        provider_name: None,
        provider_image: None,
        additional_fields,
        is_anonymous: None,
        phone_number: clear_phone.then_some(None),
        phone_number_verified: None,
        last_login_method: None,
        email: None,
        name: update_req.name,
        image: update_req.image,
        email_verified: None,
        username,
        display_username,
        role: None,
        banned: None,
        ban_reason: None,
        ban_expires: None,
        two_factor_enabled: None,
        metadata: update_req.metadata,
    };

    let publication = match context
        .database
        .update_user_record(&current_user.id(), update_user.clone())
        .await
    {
        Ok(updated_user) => alibi_core::CacheVersionContext::created(
            updated_user.clone(),
            current_session.clone(),
            context.user_view(&updated_user),
            current_session.clone(),
        ),
        Err(AuthError::UserNotFound) => {
            // Source retains the authenticated output snapshot when the
            // adapter no longer has this user. This does not recreate a row.
            let mut user = context.user_view(&current_user);
            if let Some(name) = update_user.name {
                user.name = Some(name);
            }
            if let Some(image) = update_user.image {
                user.image = Some(image);
            }
            if let Some(username) = update_user.username {
                user.username = Some(username);
            }
            if let Some(display_username) = update_user.display_username {
                user.display_username = Some(display_username);
            }
            if let Some(metadata) = update_user.metadata {
                user.metadata = metadata;
            }
            for (name, value) in update_user.additional_fields {
                _ = user.extension_fields.insert(name, value.to_json_value()?);
            }
            if let Some(phone_number) = update_user.phone_number {
                user.phone_number = phone_number;
                _ = user
                    .extension_fields
                    .insert("phoneNumber".into(), serde_json::Value::Null);
            }
            alibi_core::CacheVersionContext::created(
                user.clone(),
                current_session.clone(),
                user,
                current_session.clone(),
            )
        }
        Err(error) => return Err(error),
    };
    alibi_core::session::cookie_cache::runtime::emit_issuance_snapshot(context, publication)
        .await?;

    let mut response = AuthResponse::json(200, &alibi_core::StatusResponse { status: true })?;

    if let Some(token) = context.session_manager().extract_session_token(req) {
        let cookie_header =
            alibi_core::utils::cookie_utils::create_session_cookie(&token, &context.config)?;
        response = response.with_header("Set-Cookie", cookie_header);
    }

    Ok(response)
}
