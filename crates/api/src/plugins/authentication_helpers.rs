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

/// Log a noncritical callback or a notification whose policy permits continuation.
pub(in crate::plugins) async fn run_notification(
    notification: impl Future<Output = AuthResult<()>>,
) {
    if let Err(error) = notification.await {
        tracing::error!(%error, "Failed to run background task");
    }
}

/// Apply the awaited error policy, or observe already running owned work when
/// the application supplies a background-task handler. Committed auth state is
/// retained; the caller's transaction controls uncommitted writes.
pub(in crate::plugins) async fn run_owned_notification(
    context: &AuthContext<impl AuthSchema>,
    notification: impl Future<Output = AuthResult<()>> + Send + 'static,
    error_policy: better_auth_core::AwaitedNotificationErrorPolicy,
) -> AuthResult<()> {
    if let Some(handler) = &context.config.background_tasks {
        let completion = better_auth_core::start_background_task(async move {
            run_notification(notification).await;
            Ok(())
        })
        .await?;
        if let Err(error) = handler.handle(completion) {
            tracing::error!(%error, "Failed to observe background task");
        }
    } else {
        match error_policy {
            better_auth_core::AwaitedNotificationErrorPolicy::Propagate => notification.await?,
            better_auth_core::AwaitedNotificationErrorPolicy::LogAndContinue => {
                run_notification(notification).await
            }
        }
    }
    Ok(())
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
) -> AuthResult<Option<better_auth_core::verification::VerificationSnapshot>> {
    ctx.verifications().find(identifier).await
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
    // Source object schemas inspect fields on decoded streams/buffers too.
    // Those transport objects have no schema fields; retain their raw bytes,
    // but validate missing properties instead of reparsing them as JSON.
    let opaque = req
        .extensions()
        .get::<better_auth_core::types::ParsedRequestBody>()
        .is_some_and(|body| {
            matches!(
                &*body,
                better_auth_core::types::ParsedRequestBody::Opaque(_)
            )
        });
    let mut value: better_auth_core::utils::json::JsValue = if opaque {
        better_auth_core::utils::json::JsValue::Object(Default::default())
    } else {
        req.body_as_json().map_err(|_error| {
            AuthResponse::json(
                400,
                &serde_json::json!({"code":"BAD_REQUEST","message":"Invalid JSON in request body"}),
            )
            .unwrap_or_else(|_| AuthResponse::text(400, "Invalid JSON in request body"))
        })?
    };
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
        let received_type = if req
            .extensions()
            .get::<better_auth_core::types::MultipartFiles>()
            .is_some_and(|files| files.0.contains_key(field.name))
        {
            "Blob"
        } else {
            json_type(field_value)
        };
        let issue = match field.kind {
            JsonFieldKind::String | JsonFieldKind::NonEmptyString | JsonFieldKind::Email
                if !field_value.is_some_and(better_auth_core::utils::json::JsValue::is_string) =>
            {
                Some(format!(
                    "Invalid input: expected string, received {}",
                    received_type
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
                    received_type
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
                    received_type
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

/// Configured username create-hook behavior for auth methods whose additional
/// inputs have already passed through the username input transform.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn prepare_additional_user_fields(
    ctx: &AuthContext<impl AuthSchema>,
    data: &mut CreateUser,
) -> AuthResult<()> {
    apply_creation_input_defaults(ctx, data);
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
    let policy = ctx
        .extensions
        .get::<better_auth_core::utils::username::UsernameConfig>()
        .map(|policy| (*policy).clone())
        .unwrap_or_default();
    policy.validate_hook_value(username).await?;
    let username = policy.normalize(username)?;
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
    if let Some(display) = data
        .display_username
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        policy.validate_display(display).await?;
    }
    Ok(())
}

/// Built-in schema defaults introduced by parsed create input, before identity
/// validation. Direct identity creation instead receives adapter defaults after
/// its database hooks. Application additional schemas are handled separately.
pub(in crate::plugins) fn apply_creation_input_defaults(
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

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn session_response<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    user: better_auth_core::AdapterRecord<S::User>,
) -> AuthResult<(Value, AuthResponse)> {
    session_response_with_remember(ctx, req, user, None).await
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn session_response_with_remember<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    user: better_auth_core::AdapterRecord<S::User>,
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
    let issued = crate::plugins::helpers::issue_selected_user_session_record(
        &issuing_context,
        user,
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
) -> AuthResult<Option<better_auth_core::AdapterRecord<S::User>>> {
    let identifier = format!("revoke-unproven-account-access:{user_id}");
    let reserved = ctx
        .verifications()
        .reserve(CreateVerification {
            identifier: identifier.clone(),
            value: user_id.to_owned(),
            expires_at: Utc::now() + Duration::seconds(5),
        })
        .await;
    // The pinned mailbox-promotion helper deliberately proceeds without a
    // reservation when verification storage is secondary-only. Other failures
    // still stop cleanup and publication.
    let reserved = match reserved {
        Ok(value) => value,
        Err(AuthError::Internal(message))
            if message
                == "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values." =>
        {
            true
        }
        Err(error) => return Err(error),
    };
    if !reserved {
        for _ in 0..8 {
            if ctx.verifications().find(&identifier).await?.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        return ctx.database.get_user_by_id_record(user_id).await;
    }
    let result = async {
        let Some(user) = ctx.database.get_user_by_id_record(user_id).await? else {
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
            .update_user_record(
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
    drop(ctx.verifications().delete(&identifier).await);
    result
}

pub(in crate::plugins) fn redirect(url: &str) -> AuthResponse {
    AuthResponse::text(302, "")
        .with_header("Location", url)
        .with_header("content-type", "application/json")
}
