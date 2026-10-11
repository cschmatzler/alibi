use alibi_core::entity::AuthUser;
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::utils::username::UsernameConfig;
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, ErrorCodeMessageResponse,
    UpdateUser, UpdateUserRequest,
};

/// Build the builtin profile-update operation, including configured input fields.
///
/// # Errors
/// Returns an error if the logical body cannot be serialized.
pub fn update_user_endpoint(
    body: &impl serde::Serialize,
) -> AuthResult<alibi_core::endpoint::ServerEndpoint<alibi_core::StatusResponse>> {
    alibi_core::endpoint::ServerEndpoint::new("core", "updateUser").with_body(body)
}

/// Build the public health-check operation without requiring credentials or input.
#[must_use]
pub fn ok_endpoint() -> alibi_core::endpoint::ServerEndpoint<alibi_core::OkResponse> {
    alibi_core::endpoint::ServerEndpoint::new("core", "ok")
}

/// Builtin owner used by the host runtime independently of optional user plugins.
#[doc(hidden)]
pub struct BuiltinUserEndpoints;
#[async_trait::async_trait]
impl<S: alibi_core::AuthSchema> alibi_core::AuthPlugin<S> for BuiltinUserEndpoints {
    fn name(&self) -> &'static str {
        "core"
    }
    fn routes(&self) -> Vec<alibi_core::AuthRoute> {
        Vec::new()
    }
    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        vec![
            crate::endpoint::definition("ok", "ok", Some("/ok"), alibi_core::HttpMethod::Get),
            crate::endpoint::definition(
                "updateUser",
                "updateUser",
                Some("/update-user"),
                alibi_core::HttpMethod::Post,
            ),
        ]
    }
    fn validate_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        if call.operation_id() == "ok" {
            return Ok(alibi_core::endpoint::EndpointInput {
                body: call.body().cloned(),
                query: call.query().cloned(),
            });
        }
        let body = call
            .body()
            .filter(|body| body.as_object().is_some())
            .ok_or_else(|| {
                crate::endpoint::validation(format!(
                    "[body] Invalid input: expected record, received {}",
                    crate::authentication_helpers::json_type(call.body())
                ))
            })?;
        Ok(alibi_core::endpoint::EndpointInput {
            body: Some(body.clone()),
            query: call.query().cloned(),
        })
    }
    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        context: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        if call.operation_id() == "ok" {
            return alibi_core::endpoint::EndpointResponse::json(&alibi_core::OkResponse {
                ok: true,
            });
        }
        let body = call
            .body()
            .ok_or_else(|| AuthError::bad_request("Missing profile input"))?;
        let (user, session) = context
            .require_cached_session(call)
            .await
            .map_err(crate::helpers::unauthorized_if_session_missing)?;
        call.record_authenticated_session(context.user_view(&user), session.clone());
        let response = update_user_core(call, body, user, session, context).await?;
        if response.status >= 400 {
            return Err(crate::endpoint::error_response(response));
        }
        // Logical ctx.json returns a value; HTTP serialization adds its content type.
        // Application headers remain in the actual endpoint response accumulator.
        let mut result = alibi_core::endpoint::EndpointResponse::value(
            alibi_core::utils::json::from_slice(&response.body)?,
        );
        for (name, value) in response.headers {
            if !name.eq_ignore_ascii_case("content-type") {
                result = result.with_header(name, value);
            }
        }
        Ok(result)
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

/// Handle user profile update through the shared profile lifecycle.
///
/// # Errors
/// Returns actual input, authentication, adapter, or publication failures.
pub async fn handle_update_user<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    context: &AuthContext<S>,
) -> AuthResult<AuthResponse> {
    // Preserve the HTTP owner's admission before JSON decoding.
    let (user, session) = context
        .require_cached_session(req)
        .await
        .map_err(crate::helpers::unauthorized_if_session_missing)?;
    _ = req
        .body_as_json::<serde_json::Value>()
        .map_err(|error| AuthError::bad_request(format!("Invalid JSON: {error}")))?;
    let raw_body: JsValue = req.body_as_json()?;
    update_user_core(req, &raw_body, user, session, context).await
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep field validation and callbacks adjacent to their profile persistence owner"
)]
async fn update_user_core<S: alibi_core::AuthSchema>(
    req: &impl SessionRequest,
    raw_body: &JsValue,
    current_user: alibi_core::AuthenticatedUser<S>,
    current_session: alibi_core::SessionView,
    context: &AuthContext<S>,
) -> AuthResult<AuthResponse> {
    let body: serde_json::Value = raw_body.to_json_value()?;
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

    crate::last_login_method::reject_last_login_method_input(
        context,
        raw_body.get("lastLoginMethod"),
    )?;

    let mut writable_body = body.clone();
    _ = writable_body.remove("email");
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
        .map_err(crate::authentication_helpers::field_input_error)?;
    let username = additional_fields
        .get("username")
        .and_then(JsValue::as_str)
        .map(str::to_owned);
    let display_username = additional_fields
        .get("displayUsername")
        .and_then(JsValue::as_str)
        .map(str::to_owned);

    let clear_phone = context
        .get_metadata("phone-number.enabled")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && body.get("phoneNumber") == Some(&serde_json::Value::Null);
    let clear_image = body.get("image") == Some(&serde_json::Value::Null);
    let has_changes = additional_fields.has_input_fields()
        || clear_image
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
        additional_fields,
        provider_image: clear_image.then_some(serde_json::Value::Null),
        phone_number: clear_phone.then_some(None),
        name: update_req.name,
        image: update_req.image,
        username,
        display_username,
        metadata: update_req.metadata,
        ..Default::default()
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
            if clear_image {
                user.image = None;
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
