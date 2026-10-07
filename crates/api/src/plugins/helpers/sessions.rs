use super::*;
/// Source ordinary HTTP middleware admits the authenticated cache snapshot.
/// Only the nested read is caught; subsequent storage and callback errors keep
/// their own endpoint contract.
pub(in crate::plugins) async fn ordinary_session<S: alibi_core::AuthSchema>(
    request: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<(alibi_core::AuthenticatedUser<S>, alibi_core::SessionView)> {
    ctx.require_cached_session(request).await.map_err(|error| {
        if matches!(error, AuthError::Unauthenticated) {
            AuthError::Upstream {
                status: 401,
                code: "UNAUTHORIZED",
                message: "Unauthorized",
            }
        } else {
            error
        }
    })
}

/// Convert an `expiresIn` value (**seconds** from now) into an RFC 3339
/// `expires_at` timestamp string.
///
/// Returns `None` when `expires_in_secs` is `None`.
///
/// # Errors
///
/// Returns an error if the duration or resulting timestamp is outside the supported range.
pub fn expires_in_to_at(expires_in_secs: Option<i64>) -> AuthResult<Option<String>> {
    match expires_in_secs {
        Some(secs) => {
            let duration = chrono::Duration::try_seconds(secs)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            let dt = Utc::now()
                .checked_add_signed(duration)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            Ok(Some(dt.to_rfc3339()))
        }
        None => Ok(None),
    }
}

/// Resolve the session selected by a completed response's signed session cookie.
///
/// Cookie clearing is not a new session. The record is read from storage so
/// hooks never trust user or session fields from a response body.
///
/// # Errors
///
/// Returns an error if the session cannot be serialized.
pub async fn response_session<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    response: &alibi_core::AuthResponse,
) -> AuthResult<Option<IssuedSession<S>>> {
    let token = response
        .headers
        .get_all("set-cookie")
        .filter_map(|header| {
            let cookie = cookie::Cookie::parse(header.clone()).ok()?;
            (cookie.name() == ctx.config.session.cookie_name && !cookie.value().is_empty())
                .then(|| {
                    alibi_core::utils::cookie_utils::verify_cookie_value(
                        cookie.value(),
                        ctx.config.current_secret(),
                    )
                })
                .flatten()
        })
        .last();
    let Some(token) = token else {
        return Ok(None);
    };
    let Some(session) = ctx.database.get_session(&token).await? else {
        return Ok(None);
    };
    let Some(user) = ctx.session_user(&session).await? else {
        return Ok(None);
    };
    Ok(Some(IssuedSession { user, session }))
}

pub(in crate::plugins) fn record_completed_session<S: alibi_core::AuthSchema>(
    user: &S::User,
    session: &S::Session,
) {
    if let Some(request) = alibi_core::hooks::current_request_hook_context() {
        request.extensions.insert(CompletedSession::<S> {
            user: user.clone(),
            session: session.clone(),
            user_view: None,
            user_record: None,
            session_record: None,
        });
    }
}

pub(in crate::plugins) fn record_completed_session_record<S: alibi_core::AuthSchema>(
    user: &alibi_core::AdapterRecord<S::User>,
    session: &alibi_core::AdapterRecord<S::Session>,
) {
    if let Some(request) = alibi_core::hooks::current_request_hook_context() {
        request.extensions.insert(CompletedSession::<S> {
            user: user.stored().clone(),
            session: session.stored().clone(),
            user_view: None,
            user_record: Some(user.clone()),
            session_record: Some(session.clone()),
        });
    }
}

/// Retain a Source-defined callback projection after genuine session issuance.
/// This cannot create a completion or replace its raw models/owner/token.
pub(in crate::plugins) fn record_completed_session_user_view<S: alibi_core::AuthSchema>(
    original_user: &impl AuthUser,
    session: &impl alibi_core::AuthSession,
    view: alibi_core::wire::UserView,
) {
    use alibi_core::AuthSession;
    if let Some(request) = alibi_core::hooks::current_request_hook_context()
        && let Some(completed) = request.extensions.get::<CompletedSession<S>>()
        && completed.user.id() == original_user.id()
        && view.id == original_user.id().as_ref()
        && completed.session.token() == session.token()
    {
        request.extensions.insert(CompletedSession::<S> {
            user: completed.user.clone(),
            session: completed.session.clone(),
            user_view: Some(view),
            user_record: completed.user_record.clone(),
            session_record: completed.session_record.clone(),
        });
    }
}

pub(in crate::plugins) fn response_has_session_cookie<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    response: &alibi_core::AuthResponse,
) -> bool {
    response.headers.get_all("set-cookie").any(|header| {
        cookie::Cookie::parse(header.clone()).is_ok_and(|cookie| {
            cookie.name() == ctx.config.session.cookie_name
                && cookie
                    .value()
                    .split('.')
                    .next()
                    .is_some_and(|value| !value.is_empty())
        })
    })
}

pub(in crate::plugins) fn completed_response_session<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
    response: &alibi_core::AuthResponse,
) -> Option<std::sync::Arc<CompletedSession<S>>> {
    // A clearing cookie is not a completed login. The snapshot comes from the
    // trusted issuer, never the response body or a freshly mutated database row.
    let selected = response_has_session_cookie(ctx, response);
    selected
        .then(|| req.extensions().get::<CompletedSession<S>>())
        .flatten()
}

/// Whether the admin plugin is active for this auth instance.
#[must_use]
pub fn admin_plugin_enabled(ctx: &AuthContext<impl alibi_core::AuthSchema>) -> bool {
    ctx.get_metadata("admin.enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Resolve the configured message shown when a banned user attempts to create
/// a session.
pub fn admin_banned_user_message(ctx: &AuthContext<impl alibi_core::AuthSchema>) -> Option<String> {
    ctx.get_metadata("admin.banned_user_message")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

/// Resolve an awaited application message from the actual stored user entity.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn resolve_admin_banned_user_message<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user: &impl AuthUser,
) -> AuthResult<String> {
    if let Some(policy) = ctx
        .extensions
        .get::<super::super::admin::BannedUserMessagePolicy>()
    {
        return policy.message(user).await;
    }
    Ok(admin_banned_user_message(ctx).unwrap_or_else(|| {
        "You have been banned from this application. Please contact support if you believe this is an error.".to_owned()
    }))
}

/// Issue a session for the given user, applying admin-plugin ban semantics
/// when the admin plugin is enabled.
///
/// # Errors
///
/// Returns an error if session hooks reject issuance, the user is banned, or storage fails.
pub async fn issue_user_session<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSession<S>, SessionIssueError> {
    issue_user_session_record(ctx, user_id, ip_address, user_agent)
        .await
        .map(IssuedSessionRecord::into_stored)
}

/// Issue and publish genuine retained adapter results.
///
/// # Errors
/// Propagates validation, storage and configured callback errors.
pub async fn issue_user_session_record<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSessionRecord<S>, SessionIssueError> {
    issue_user_session_inner(ctx, user_id, ip_address, user_agent, None, true, None).await
}

/// Issue a session with trusted fields applied during its initial insert.
///
/// Configured field policies and creation hooks receive the supplied fields;
/// issuance publishes the resulting row through the normal cache and completion
/// path. No follow-up session update is performed. Admin ban policy still applies.
///
/// # Errors
/// Returns an error if hooks reject issuance, the user is banned, or storage fails.
pub async fn issue_user_session_with_fields<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    fields: SessionOverrides,
) -> Result<IssuedSession<S>, SessionIssueError> {
    issue_user_session_with_fields_record(ctx, user_id, ip_address, user_agent, fields)
        .await
        .map(IssuedSessionRecord::into_stored)
}

/// Issue a session with trusted initial fields and retain its adapter output.
///
/// This is the retained-record counterpart to [`issue_user_session_with_fields`].
///
/// # Errors
/// Propagates validation, storage, ban policy, and configured callback errors.
pub async fn issue_user_session_with_fields_record<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    fields: SessionOverrides,
) -> Result<IssuedSessionRecord<S>, SessionIssueError> {
    // Additional fields use schema bindings, so reject names that could replace
    // issuance-owned columns rather than trusting the caller's map shape.
    for name in fields.additional_fields.keys() {
        if matches!(
            name.as_str(),
            "id" | "token"
                | "userId"
                | "user_id"
                | "expiresAt"
                | "expires_at"
                | "createdAt"
                | "created_at"
                | "updatedAt"
                | "updated_at"
        ) {
            return Err(
                AuthError::bad_request(format!("Session issuance owns the {name} field")).into(),
            );
        }
    }
    issue_user_session_inner(
        ctx,
        user_id,
        ip_address,
        user_agent,
        Some(fields),
        true,
        None,
    )
    .await
}

/// Create a genuine session for an endpoint that publishes it after later
/// persistence and application callbacks have completed.
pub(in crate::plugins) async fn create_user_session_record<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSessionRecord<S>, SessionIssueError> {
    issue_user_session_inner(ctx, user_id, ip_address, user_agent, None, false, None).await
}

/// Issue a replacement session while preserving trusted session extension fields.
///
/// # Errors
///
/// Returns an error if session hooks reject issuance, the user is banned, or storage fails.
pub async fn issue_user_session_with_overrides<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    current_session: &impl alibi_core::AuthSession,
) -> Result<IssuedSession<S>, SessionIssueError> {
    issue_user_session_with_overrides_record(ctx, user_id, ip_address, user_agent, current_session)
        .await
        .map(IssuedSessionRecord::into_stored)
}

/// Issue replacement records with actual retained output.
///
/// # Errors
/// Propagates persistence or configured callback errors.
pub async fn issue_user_session_with_overrides_record<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    current_session: &impl alibi_core::AuthSession,
) -> Result<IssuedSessionRecord<S>, SessionIssueError> {
    let overrides = SessionOverrides {
        additional_fields: current_session
            .additional_fields()
            .into_iter()
            .map(|(name, value)| (name, alibi_core::utils::json::JsValue::from(value)))
            .collect(),
        impersonated_by: current_session.impersonated_by().map(str::to_owned),
        active_organization_id: current_session.active_organization_id().map(str::to_owned),
        active_team_id: current_session.active_team_id().map(str::to_owned),
    };
    issue_user_session_inner(
        ctx,
        user_id,
        ip_address,
        user_agent,
        Some(overrides),
        true,
        None,
    )
    .await
}

/// Issue from the actual lookup already used to authenticate this user. This
/// retains its callback snapshot without repeating adapter output callbacks.
pub(in crate::plugins) async fn issue_selected_user_session_record<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user: alibi_core::AdapterRecord<S::User>,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSessionRecord<S>, SessionIssueError> {
    let id = user.id().into_owned();
    issue_user_session_inner(ctx, &id, ip_address, user_agent, None, true, Some(user)).await
}

pub(in crate::plugins::helpers) async fn issue_user_session_inner<S: alibi_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    overrides: Option<SessionOverrides>,
    publish: bool,
    selected: Option<alibi_core::AdapterRecord<S::User>>,
) -> Result<IssuedSessionRecord<S>, SessionIssueError> {
    let user = match selected {
        Some(user) => user,
        None => ctx
            .database
            .get_user_by_id_record(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?,
    };

    if admin_plugin_enabled(ctx) && user.banned() {
        if user
            .ban_expires()
            .is_some_and(|expires| expires < Utc::now())
        {
            drop(
                ctx.database
                    .update_user_record(
                        user_id,
                        UpdateUser {
                            banned: Some(false),
                            ban_reason: None,
                            ban_expires: None,
                            ..Default::default()
                        },
                    )
                    .await?,
            );
        } else {
            return Err(SessionIssueError::Banned {
                message: resolve_admin_banned_user_message(ctx, &user).await?,
            });
        }
    }

    let session = match overrides {
        None => {
            ctx.session_manager()
                .create_session_record(&user, ip_address, user_agent)
                .await?
        }
        Some(overrides) => {
            ctx.database
                .create_session_record(alibi_core::CreateSession {
                    additional_fields: overrides.additional_fields,
                    token: None,
                    user_id: user.id().to_string(),
                    expires_at: Utc::now() + ctx.config.session.expires_in,
                    ip_address,
                    user_agent,
                    impersonated_by: overrides.impersonated_by,
                    active_organization_id: overrides.active_organization_id,
                    active_team_id: overrides.active_team_id,
                })
                .await?
        }
    };

    if publish {
        alibi_core::session::cookie_cache::runtime::emit_issuance(ctx, &user, &session).await?;
        record_completed_session_record::<S>(&user, &session);
    }
    Ok(IssuedSessionRecord { user, session })
}

/// Parse a cookie value from the request's `Cookie` header.
#[must_use]
pub fn get_cookie(req: &AuthRequest, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
    header.split(';').find_map(|cookie| {
        let trimmed = cookie.trim();
        let (cookie_name, cookie_value) = trimmed.split_once('=')?;
        (cookie_name == name).then_some(cookie_value.to_owned())
    })
}

/// TS-style cookie clearing used by `deleteSessionCookie`.
pub fn delete_session_cookie_headers(config: &alibi_core::AuthConfig) -> AuthResult<Vec<String>> {
    alibi_core::utils::cookie_utils::delete_session_cookie_headers(config)
}
