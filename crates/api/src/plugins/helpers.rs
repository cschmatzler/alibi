//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).

use better_auth_core::entity::{AuthAccount, AuthUser};

use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, CreateUser, UpdateUser};

use chrono::Utc;

/// Result of issuing a real session for a user.
pub struct IssuedSession<S: better_auth_core::AuthSchema> {
    pub user: S::User,
    pub session: S::Session,
}

/// Original rows used by the handler that issued the completed session.
/// This is a callback observation; authorization still uses a current session read.
pub(in crate::plugins) struct CompletedSession<S: better_auth_core::AuthSchema> {
    pub(in crate::plugins) user: S::User,
    pub(in crate::plugins) session: S::Session,
    pub(in crate::plugins) user_view: Option<better_auth_core::wire::UserView>,
}

/// Session issuance failures that callers may need to surface differently from
/// a generic auth error (for example OAuth callback redirects).
#[derive(Debug)]
pub enum SessionIssueError {
    Auth(AuthError),
    Banned { message: String },
}

impl SessionIssueError {
    #[must_use]
    pub fn into_auth_error(self) -> AuthError {
        match self {
            Self::Auth(error) => error,
            Self::Banned { message } => AuthError::banned_user(message),
        }
    }

    #[must_use]
    pub const fn banned_message(&self) -> Option<&str> {
        match self {
            Self::Banned { message } => Some(message.as_str()),
            Self::Auth(_) => None,
        }
    }
}

impl From<AuthError> for SessionIssueError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

struct SessionOverrides {
    additional_fields: better_auth_core::field_policy::FieldValues,
    impersonated_by: Option<String>,
    active_organization_id: Option<String>,
    active_team_id: Option<String>,
}

impl<S: better_auth_core::AuthSchema> std::fmt::Debug for IssuedSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedSession").finish_non_exhaustive()
    }
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

/// Fetch an API key by ID and verify that it belongs to the given user.
///
/// Returns `AuthError::not_found` if the key does not exist or belongs to
/// another user.  This pattern was duplicated in `handle_get`, `handle_update`,
/// and `handle_delete`.
///
/// # Errors
///
/// Returns an error if the key is missing, belongs to another owner, or its lookup fails.
pub async fn get_owned_api_key(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &crate::plugins::api_key::ApiKeyConfig,
    key_id: &str,
    user_id: &str,
    action: &str,
) -> AuthResult<better_auth_core::ApiKey> {
    use crate::plugins::api_key::{ApiKeyReferences, config_id_matches};

    let api_key = ctx
        .database
        .get_api_key_by_id(key_id)
        .await?
        .ok_or_else(|| AuthError::not_found("API Key not found"))?;

    // A key only exists as far as the configuration that addressed it.
    if !config_id_matches(&api_key.config_id, &config.config_id) {
        return Err(AuthError::not_found("API Key not found"));
    }

    match config.references {
        ApiKeyReferences::User => {
            if api_key.reference_id != user_id {
                return Err(AuthError::not_found("API Key not found"));
            }
        }
        ApiKeyReferences::Organization => {
            require_org_api_key_permission(ctx, user_id, &api_key.reference_id, action).await?;
        }
    }

    Ok(api_key)
}

/// Authorize a user against an organization-owned API key, mirroring
/// upstream's `checkOrgApiKeyPermission`.
///
/// # Errors
///
/// Returns an error if organization permissions cannot be loaded or do not authorize the operation.
pub async fn require_org_api_key_permission(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_id: &str,
    organization_id: &str,
    action: &str,
) -> AuthResult<()> {
    use crate::plugins::api_key::{ApiKeyErrorCode, api_key_error};
    use crate::plugins::organization::{
        DynamicAccessControlConfig, METADATA_CREATOR_ROLE, METADATA_ENABLED, METADATA_ROLES,
        OrganizationConfig,
    };

    // Organization-owned keys are meaningless without the organization plugin,
    // which is what supplies the access control below.
    if !ctx
        .get_metadata(METADATA_ENABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(api_key_error(ApiKeyErrorCode::OrganizationPluginRequired));
    }

    let Some(member) = ctx.database.get_member(organization_id, user_id).await? else {
        return Err(api_key_error(ApiKeyErrorCode::UserNotMemberOfOrganization));
    };

    // Upstream passes `allowCreatorAllPermissions`, so the creator role clears
    // every action without consulting the statements. Roles are composite
    // (comma-separated), so holding it alongside others still counts.
    let creator_role = ctx
        .get_metadata(METADATA_CREATOR_ROLE)
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "owner".to_owned());
    if member.role.split(',').any(|role| role == creator_role) {
        return Ok(());
    }

    let config = OrganizationConfig {
        roles: ctx
            .get_metadata(METADATA_ROLES)
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .flatten(),
        access_control: ctx
            .get_metadata("organization.access_control")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .flatten(),
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: ctx
                .get_metadata("organization.dynamic_roles.enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            ..Default::default()
        },
        ..Default::default()
    };
    // The pinned API-key plugin turns failed dynamic role resolution into a
    // denied permission rather than allowing or exposing its internal error.
    let allowed = crate::plugins::organization::handlers::extension_common::has_action(
        &member.role,
        "apiKey",
        action,
        &config,
        ctx,
        organization_id,
    )
    .await
    .unwrap_or(false);

    if allowed {
        Ok(())
    } else {
        Err(api_key_error(
            ApiKeyErrorCode::InsufficientApiKeyPermissions,
        ))
    }
}

/// Fetch the user's credential account, if present.
///
/// # Errors
///
/// Propagates errors from credential-account storage.
pub async fn get_credential_account<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: impl AsRef<str>,
) -> AuthResult<Option<S::Account>> {
    Ok(ctx
        .database
        .get_user_accounts(user_id.as_ref())
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential"))
}

/// Resolve the user's stored password hash from the credential account.
///
/// # Errors
///
/// Propagates errors from credential-account storage.
pub async fn get_credential_password_hash(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<Option<String>> {
    Ok(get_credential_account(ctx, user.id())
        .await?
        .and_then(|account| account.password().map(str::to_owned)))
}

/// Whether the user currently has a password set.
///
/// # Errors
///
/// Propagates errors from credential-account storage.
pub async fn user_has_password(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
) -> AuthResult<bool> {
    Ok(get_credential_password_hash(ctx, user).await?.is_some())
}

/// Apply the configured default admin role to a new user when the caller
/// didn't set an explicit role.
pub fn apply_default_role(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    create_user: &mut CreateUser,
) {
    if create_user.role.is_some() {
        return;
    }

    if let Some(default_role) = ctx
        .get_metadata("admin.default_role")
        .and_then(|value| value.as_str())
    {
        create_user.role = Some(default_role.to_owned());
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
pub async fn response_session<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    response: &better_auth_core::AuthResponse,
) -> AuthResult<Option<IssuedSession<S>>> {
    use better_auth_core::entity::AuthSession;
    let token = response
        .headers
        .get_all("set-cookie")
        .filter_map(|header| {
            let cookie = cookie::Cookie::parse(header.clone()).ok()?;
            (cookie.name() == ctx.config.session.cookie_name && !cookie.value().is_empty())
                .then(|| {
                    better_auth_core::utils::cookie_utils::verify_cookie_value(
                        cookie.value(),
                        &ctx.config.secret,
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
    let Some(user) = ctx
        .database
        .get_user_by_id(session.user_id().as_ref())
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(IssuedSession { user, session }))
}

pub(in crate::plugins) fn record_completed_session<S: better_auth_core::AuthSchema>(
    user: &S::User,
    session: &S::Session,
) {
    if let Some(request) = better_auth_core::hooks::current_request_hook_context() {
        request.extensions.insert(CompletedSession::<S> {
            user: user.clone(),
            session: session.clone(),
            user_view: None,
        });
    }
}

/// Retain a Source-defined callback projection after genuine session issuance.
/// This cannot create a completion or replace its raw models/owner/token.
pub(in crate::plugins) fn record_completed_session_user_view<S: better_auth_core::AuthSchema>(
    original_user: &S::User,
    session: &S::Session,
    view: better_auth_core::wire::UserView,
) {
    use better_auth_core::AuthSession;
    if let Some(request) = better_auth_core::hooks::current_request_hook_context()
        && let Some(completed) = request.extensions.get::<CompletedSession<S>>()
        && completed.user.id() == original_user.id()
        && view.id == original_user.id().as_ref()
        && completed.session.token() == session.token()
    {
        request.extensions.insert(CompletedSession::<S> {
            user: completed.user.clone(),
            session: completed.session.clone(),
            user_view: Some(view),
        });
    }
}

pub(in crate::plugins) fn response_has_session_cookie<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    response: &better_auth_core::AuthResponse,
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

pub(in crate::plugins) fn completed_response_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
    response: &better_auth_core::AuthResponse,
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
pub fn admin_plugin_enabled(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> bool {
    ctx.get_metadata("admin.enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Resolve the configured message shown when a banned user attempts to create
/// a session.
pub fn admin_banned_user_message(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Option<String> {
    ctx.get_metadata("admin.banned_user_message")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

/// Resolve an awaited application message from the actual stored user entity.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn resolve_admin_banned_user_message<
    S: better_auth_core::AuthSchema,
>(
    ctx: &AuthContext<S>,
    user: &S::User,
) -> AuthResult<String> {
    if let Some(policy) = ctx
        .extensions
        .get::<super::admin::BannedUserMessagePolicy>()
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
pub async fn issue_user_session<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<IssuedSession<S>, SessionIssueError> {
    issue_user_session_inner(ctx, user_id, ip_address, user_agent, None).await
}

/// Issue a replacement session while preserving trusted session extension fields.
///
/// # Errors
///
/// Returns an error if session hooks reject issuance, the user is banned, or storage fails.
pub async fn issue_user_session_with_overrides<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    current_session: &impl better_auth_core::AuthSession,
) -> Result<IssuedSession<S>, SessionIssueError> {
    let overrides = SessionOverrides {
        additional_fields: current_session
            .additional_fields()
            .into_iter()
            .map(|(name, value)| (name, better_auth_core::utils::json::JsValue::from(value)))
            .collect(),
        impersonated_by: current_session.impersonated_by().map(str::to_owned),
        active_organization_id: current_session.active_organization_id().map(str::to_owned),
        active_team_id: current_session.active_team_id().map(str::to_owned),
    };
    issue_user_session_inner(ctx, user_id, ip_address, user_agent, Some(overrides)).await
}

async fn issue_user_session_inner<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    overrides: Option<SessionOverrides>,
) -> Result<IssuedSession<S>, SessionIssueError> {
    let user = ctx
        .database
        .get_user_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    if admin_plugin_enabled(ctx) && user.banned() {
        if user
            .ban_expires()
            .is_some_and(|expires| expires <= Utc::now())
        {
            drop(
                ctx.database
                    .update_user(
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
                .create_session(&user, ip_address, user_agent)
                .await?
        }
        Some(overrides) => {
            ctx.database
                .create_session(better_auth_core::CreateSession {
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

    better_auth_core::cache::runtime::emit_issuance(ctx, &user, &session).await?;
    record_completed_session::<S>(&user, &session);
    Ok(IssuedSession { user, session })
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
#[must_use]
pub fn delete_session_cookie_headers(config: &better_auth_core::AuthConfig) -> Vec<String> {
    better_auth_core::utils::cookie_utils::delete_session_cookie_headers(config)
}
