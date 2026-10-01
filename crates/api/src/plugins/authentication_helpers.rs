//! Shared HTTP validation and authentication lifecycle behavior.

use better_auth_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthSession, AuthUser, CreateUser, CreateVerification, UpdateUser,
};

use chrono::{Duration, Utc};

use serde::de::DeserializeOwned;

use serde_json::Value;

#[derive(Clone, Copy)]
pub(in crate::plugins) enum JsonFieldKind {
    String,
    NonEmptyString,
    Email,
    Boolean,
    Record,
    OneOf(&'static [&'static str]),
}

pub(in crate::plugins) struct JsonField {
    pub name: &'static str,
    pub kind: JsonFieldKind,
    pub required: bool,
}

impl JsonField {
    #[must_use]
    pub(in crate::plugins) const fn string(name: &'static str, required: bool) -> Self {
        Self {
            name,
            kind: JsonFieldKind::String,
            required,
        }
    }
}

pub(in crate::plugins) trait RequestBody: DeserializeOwned + 'static {
    const FIELDS: &'static [JsonField];
}

/// The default upstream background-task policy awaits notifications, logs a
/// rejected callback, and retains the endpoint's already issued state. Direct
/// delivery endpoints deliberately do not use this policy.
pub(in crate::plugins) async fn run_notification(
    notification: impl Future<Output = AuthResult<()>>,
) {
    if let Err(error) = notification.await {
        tracing::error!(%error, "Failed to run background task");
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn parse_email(email: &str) -> AuthResult<String> {
    let normalized = email.to_lowercase();
    if !is_valid_email(&normalized) {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_EMAIL",
            message: "Invalid email",
        });
    }
    Ok(normalized)
}

/// Preserve the newest lookup snapshot before the configured global cleanup.
/// The atomic consume operation has its own expiry and concurrency contract.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn find_verification<S: AuthSchema>(
    ctx: &AuthContext<S>,
    identifier: &str,
) -> AuthResult<Option<S::Verification>> {
    let value = ctx
        .database
        .get_latest_verification_by_identifier(identifier)
        .await?;
    if !ctx.config.verification.disable_cleanup {
        let _ignored_delete_expired_verifications =
            ctx.database.delete_expired_verifications().await?;
    }
    Ok(value)
}

// This is the exact practical-email grammar used by the pinned Zod runtime.
// The HTML5/validator grammar accepts addresses such as `x@y.c` and local
// punctuation which Better Auth rejects, so those validators are unsuitable.
pub(in crate::plugins) fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.split('.').any(str::is_empty) {
        return false;
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_'+-.".contains(&b))
        || !local
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b"_+-".contains(b))
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() > 1
        && labels
            .last()
            .is_some_and(|last| last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic()))
        && labels.iter().all(|label| {
            label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Parse the upstream schema at the HTTP boundary. The error includes all
/// failed fields in declaration order, including explicitly null optionals.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn parse_body<T: RequestBody>(req: &AuthRequest) -> Result<T, AuthResponse> {
    parse_body_with_fields(req, T::FIELDS)
}

/// Parse schemas whose required fields depend on trusted plugin configuration.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn parse_body_with_fields<T: DeserializeOwned + 'static>(
    req: &AuthRequest,
    fields: &[JsonField],
) -> Result<T, AuthResponse> {
    parse_body_with_fields_and_ignored(req, fields, &[])
}

/// Remove configured unknown fields before schema validation without serializing
/// the remaining JavaScript numbers (which may include infinity or signed zero).
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn parse_body_with_ignored_fields<T: RequestBody>(
    req: &AuthRequest,
    ignored: &[&str],
) -> Result<T, AuthResponse> {
    parse_body_with_fields_and_ignored(req, T::FIELDS, ignored)
}

fn parse_body_with_fields_and_ignored<T: DeserializeOwned + 'static>(
    req: &AuthRequest,
    fields: &[JsonField],
    ignored: &[&str],
) -> Result<T, AuthResponse> {
    let mut value: better_auth_core::utils::json::JsValue =
        req.body_as_json().map_err(|_error| {
            AuthResponse::json(
                400,
                &serde_json::json!({"code":"BAD_REQUEST","message":"Invalid JSON in request body"}),
            )
            .unwrap_or_else(|_| AuthResponse::text(400, "Invalid JSON in request body"))
        })?;
    if let better_auth_core::utils::json::JsValue::Object(object) = &mut value {
        for field in ignored {
            drop(object.shift_remove(*field));
        }
    }
    let Some(object) = value.as_object() else {
        return Err(validation_response(&format!(
            "[body] Invalid input: expected object, received {}",
            json_type(Some(&value))
        )));
    };
    let mut issues = Vec::new();
    for field in fields {
        let field_value = object.get(field.name);
        if field_value.is_none() && !field.required {
            continue;
        }
        let issue = match field.kind {
            JsonFieldKind::String | JsonFieldKind::NonEmptyString | JsonFieldKind::Email
                if !field_value.is_some_and(better_auth_core::utils::json::JsValue::is_string) =>
            {
                Some(format!(
                    "Invalid input: expected string, received {}",
                    json_type(field_value)
                ))
            }
            JsonFieldKind::NonEmptyString
                if field_value
                    .and_then(better_auth_core::utils::json::JsValue::as_str)
                    .is_some_and(str::is_empty) =>
            {
                Some("Too small: expected string to have >=1 characters".to_owned())
            }
            JsonFieldKind::Boolean
                if !field_value.is_some_and(better_auth_core::utils::json::JsValue::is_boolean) =>
            {
                Some(format!(
                    "Invalid input: expected boolean, received {}",
                    json_type(field_value)
                ))
            }
            JsonFieldKind::Email
                if !field_value
                    .and_then(better_auth_core::utils::json::JsValue::as_str)
                    .is_some_and(is_valid_email) =>
            {
                Some("Invalid email address".to_owned())
            }
            JsonFieldKind::OneOf(choices)
                if !field_value
                    .and_then(better_auth_core::utils::json::JsValue::as_str)
                    .is_some_and(|value_2| choices.contains(&value_2)) =>
            {
                Some(format!(
                    "Invalid option: expected one of {}",
                    choices
                        .iter()
                        .map(|choice| format!("\"{choice}\""))
                        .collect::<Vec<_>>()
                        .join("|")
                ))
            }
            JsonFieldKind::Record
                if !field_value.is_some_and(better_auth_core::utils::json::JsValue::is_object) =>
            {
                Some(format!(
                    "Invalid input: expected record, received {}",
                    json_type(field_value)
                ))
            }
            JsonFieldKind::String
            | JsonFieldKind::NonEmptyString
            | JsonFieldKind::Email
            | JsonFieldKind::Boolean
            | JsonFieldKind::Record
            | JsonFieldKind::OneOf(_) => None,
        };
        if let Some(issue) = issue {
            issues.push(format!("[body.{}] {issue}", field.name));
        }
    }
    if !issues.is_empty() {
        return Err(validation_response(&issues.join("; ")));
    }
    better_auth_core::utils::json::from_value(value)
        .map_err(|_error| validation_response("[body] Invalid input"))
}

pub(in crate::plugins) const fn json_type(
    value: Option<&better_auth_core::utils::json::JsValue>,
) -> &'static str {
    use better_auth_core::utils::json::JsValue;
    match value {
        None => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Bool(_)) => "boolean",
        Some(JsValue::Number(number)) if number.is_infinite() && number.is_sign_negative() => {
            "-Infinity"
        }
        Some(JsValue::Number(number)) if number.is_infinite() => "Infinity",
        Some(JsValue::Number(_)) => "number",
        Some(JsValue::String(_)) => "string",
        Some(JsValue::Array(_)) => "array",
        Some(JsValue::Object(_)) => "object",
    }
}

pub(in crate::plugins) fn validation_response(message: &str) -> AuthResponse {
    AuthResponse::json(
        400,
        &serde_json::json!({"code":"VALIDATION_ERROR","message":message}),
    )
    .unwrap_or_else(|_| AuthResponse::text(400, "Validation failed"))
}

/// Default username create-hook behavior for auth methods whose additional
/// inputs have already passed through the username input transform.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn prepare_additional_user_fields(
    ctx: &AuthContext<impl AuthSchema>,
    data: &mut CreateUser,
) -> AuthResult<()> {
    use better_auth_core::utils::username::{
        UsernameValidationError, normalize_username, validate_username,
    };
    if !ctx
        .get_metadata("username.enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        data.username = None;
        data.display_username = None;
        return Ok(());
    }
    let Some(username) = data
        .username
        .as_deref()
        .filter(|username| !username.is_empty())
    else {
        return Ok(());
    };
    let username = normalize_username(username);
    if let Err(error) = validate_username(&username) {
        let (code, message) = match error {
            UsernameValidationError::TooShort => ("USERNAME_TOO_SHORT", "Username is too short"),
            UsernameValidationError::TooLong => ("USERNAME_TOO_LONG", "Username is too long"),
            UsernameValidationError::Invalid => ("INVALID_USERNAME", "Username is invalid"),
        };
        return Err(AuthError::Upstream {
            status: 400,
            code,
            message,
        });
    }
    if ctx
        .database
        .get_user_by_username(&username)
        .await?
        .is_some()
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "USERNAME_IS_ALREADY_TAKEN",
            message: "Username is already taken. Please try another.",
        });
    }
    if data.display_username.as_deref().is_none_or(str::is_empty) {
        data.display_username = Some(username.clone());
    }
    data.username = Some(username);
    Ok(())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn session_response<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    user_id: &str,
) -> AuthResult<(Value, AuthResponse)> {
    session_response_with_remember(ctx, req, user_id, None).await
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn session_response_with_remember<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    user_id: &str,
    remember_me: Option<bool>,
) -> AuthResult<(Value, AuthResponse)> {
    use better_auth_core::utils::cookie_utils::{
        create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
        sign_cookie_value, verify_cookie_value,
    };
    let inherited = crate::plugins::helpers::get_cookie(
        req,
        &related_cookie_name(&ctx.config, "dont_remember"),
    )
    .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
    .is_some_and(|value| !value.is_empty());
    let dont_remember = remember_me.map_or(inherited, |value| !value);
    let mut config = (*ctx.config).clone();
    if remember_me == Some(false) {
        config.session.expires_in = Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: std::sync::Arc::new(config),
        database: std::sync::Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let meta = better_auth_core::RequestMeta::from_request(req);
    let issued = crate::plugins::helpers::issue_user_session(
        &issuing_context,
        user_id,
        meta.ip_address,
        meta.user_agent,
    )
    .await
    .map_err(crate::plugins::helpers::SessionIssueError::into_auth_error)?;
    let token = issued.session.token();
    let user = serde_json::to_value(ctx.user_view(&issued.user))?;
    let session = serde_json::to_value(ctx.session_view(&issued.session))?;
    let payload = serde_json::json!({"token":token,"user":user,"session":session});
    let mut response = AuthResponse::json(200, &serde_json::json!({"token":token,"user":user}))?
        .with_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(token),
                if dont_remember {
                    None
                } else {
                    Some(ctx.config.session.expires_in.num_seconds())
                },
                &ctx.config,
            ),
        );
    if dont_remember {
        response.headers.append(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(&ctx.config, "dont_remember"),
                &sign_cookie_value("true", &ctx.config.secret),
                None,
                &ctx.config,
            ),
        );
    }
    Ok((payload, response))
}

/// Email-primary proof replaces access accrued before mailbox ownership was
/// proven. The database reservation serializes cleanup across auth instances.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_unproven_access<S: AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
) -> AuthResult<Option<S::User>> {
    let identifier = format!("revoke-unproven-account-access:{user_id}");
    if !ctx
        .database
        .reserve_verification(CreateVerification {
            identifier: identifier.clone(),
            value: user_id.to_owned(),
            expires_at: Utc::now() + Duration::seconds(5),
        })
        .await?
    {
        for _ in 0..8 {
            if ctx
                .database
                .get_verification_by_identifier(&identifier)
                .await?
                .is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        return ctx.database.get_user_by_id(user_id).await;
    }
    let result = async {
        let Some(user) = ctx.database.get_user_by_id(user_id).await? else {
            return Ok(None);
        };
        if user.email_verified() {
            return Ok(Some(user));
        }
        for account in ctx.database.get_user_accounts(user_id).await? {
            ctx.database.delete_account(&account.id()).await?;
        }
        ctx.database.delete_user_sessions(user_id).await?;
        ctx.database
            .update_user(
                user_id,
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
            .map(Some)
    }
    .await;
    drop(
        ctx.database
            .delete_verifications_by_identifier(&identifier)
            .await,
    );
    result
}

pub(in crate::plugins) fn redirect(url: &str) -> AuthResponse {
    AuthResponse::text(302, "")
        .with_header("Location", url)
        .with_header("content-type", "application/json")
}
