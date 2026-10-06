use super::access::has_permission;
use super::types::{
    AdminUpdateUserRequest, AdminUserView, BanUserRequest, CreateUserRequest, GetUserQuery,
    HasPermissionRequest, ListSessionsResponse, ListUsersQueryParams, ListUsersResponse,
    PermissionResponse, RevokeSessionRequest, RoleInput, SessionUserResponse, SetRoleRequest,
    SetUserPasswordRequest, SuccessResponse, UserIdRequest, UserResponse,
};
use super::{AdminConfig, target_is_admin};
use crate::plugins::StatusResponse;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, CreateAccount, CreateSession, UpdateUser,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

const MESSAGE_USER_NOT_FOUND: &str = "User not found";

const MESSAGE_NON_EXISTENT_ROLE: &str = "You are not allowed to set a non-existent role value";

const MESSAGE_INVALID_ROLE_TYPE: &str = "Invalid role type";

const MESSAGE_NO_DATA_TO_UPDATE: &str = "No data to update";

const MESSAGE_CHANGE_ROLE: &str = "You are not allowed to change users role";

const MESSAGE_CANNOT_IMPERSONATE_ADMINS: &str = "You cannot impersonate admins";

const MESSAGE_NOT_IMPERSONATING: &str = "You are not impersonating anyone";

const MESSAGE_FAILED_TO_FIND_USER: &str = "Failed to find user";

const MESSAGE_FAILED_TO_FIND_ADMIN_SESSION: &str = "Failed to find admin session";

/// Date-construction failures have the route-local empty 500 response.
/// Storage, application hook and authorization errors retain their own identity.
#[derive(Debug)]
pub(in crate::plugins) enum AdminDateOperationError {
    InvalidDate,
    Auth(AuthError),
}

impl From<AuthError> for AdminDateOperationError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminSessionCookieClaims {
    #[serde(rename = "sessionToken")]
    session_token: String,
    #[serde(rename = "dontRemember")]
    dont_remember: bool,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone)]
pub(in crate::plugins) struct AdminSessionCookiePayload {
    pub session_token: String,
    pub dont_remember: bool,
}

fn truthy_duration(duration: Option<f64>) -> Option<f64> {
    duration.filter(|value| *value != 0.0 && !value.is_nan())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn date_after_seconds(seconds: f64) -> Result<DateTime<Utc>, AdminDateOperationError> {
    let milliseconds = seconds.mul_add(1000.0, Utc::now().timestamp_millis() as f64);
    // Date TimeClip truncates the complete timestamp, not the duration. These
    // checked bounds are inside i64 and the exact integer range of f64.
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(AdminDateOperationError::InvalidDate);
    }
    DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or(AdminDateOperationError::InvalidDate)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn create_admin_session_cookie_value(
    secret: &str,
    payload: &AdminSessionCookiePayload,
    max_age: Duration,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = AdminSessionCookieClaims {
        session_token: payload.session_token.clone(),
        dont_remember: payload.dont_remember,
        exp: usize::try_from((now + max_age).timestamp()).map_err(|_error| {
            AuthError::internal("Session expiration is outside the supported range")
        })?,
        iat: usize::try_from(now.timestamp()).map_err(|_error| {
            AuthError::internal("Session timestamp is outside the supported range")
        })?,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn decode_admin_session_cookie_value(
    secret: &str,
    token: &str,
) -> AuthResult<AdminSessionCookiePayload> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let claims = decode::<AdminSessionCookieClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims;

    Ok(AdminSessionCookiePayload {
        session_token: claims.session_token,
        dont_remember: claims.dont_remember,
    })
}

fn joined_role(role: &RoleInput) -> String {
    role.joined()
}

fn validate_role_input(role: &RoleInput, config: &AdminConfig) -> AuthResult<()> {
    let Some(roles) = &config.roles else {
        return Ok(());
    };

    if role
        .roles()
        .into_iter()
        .all(|item| roles.contains_key(item))
    {
        Ok(())
    } else {
        Err(AuthError::bad_request(MESSAGE_NON_EXISTENT_ROLE))
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn set_role_core(
    body: &SetRoleRequest,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    let _target = ctx
        .database
        .get_user_by_id_record(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    validate_role_input(&body.role, config)?;

    let update = UpdateUser {
        role: Some(joined_role(&body.role)),
        ..Default::default()
    };

    let updated_user = ctx
        .database
        .update_user_record(&body.user_id, update)
        .await?;
    Ok(UserResponse {
        user: AdminUserView::from_output(ctx, &updated_user)?,
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn get_user_core(
    query: &GetUserQuery,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AdminUserView> {
    let user = ctx
        .database
        .get_user_by_id_record(&query.id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;
    AdminUserView::from_output(ctx, &user)
}

fn requested_create_role(body: &CreateUserRequest) -> AuthResult<Option<RoleInput>> {
    if let Some(role) = &body.role {
        return Ok(Some(role.clone()));
    }
    body.data
        .as_ref()
        .and_then(|data| data.get("role"))
        .map(|value| {
            serde_json::from_value::<RoleInput>(value.clone())
                .map_err(|_error| AuthError::bad_request(MESSAGE_INVALID_ROLE_TYPE))
        })
        .transpose()
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn create_user_core(
    body: &CreateUserRequest,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<UserView>> {
    let requested_role = requested_create_role(body)?;
    if let Some(role) = &requested_role {
        validate_role_input(role, config)?;
    }
    let email = body.email.to_lowercase();
    if !super::validation::valid_email(&email) {
        return Err(AuthError::Api {
            status: 400,
            code: Some("INVALID_EMAIL".into()),
            message: "Invalid email".into(),
        });
    }
    let password_policy = ctx.extensions.get::<crate::plugins::EmailPasswordConfig>();
    let (_, maximum) = crate::plugins::email_password::password_length_limits(ctx);
    if body
        .password
        .as_deref()
        .is_some_and(|password| password.encode_utf16().count() > maximum)
    {
        return Err(AuthError::Api {
            status: 400,
            code: Some("PASSWORD_TOO_LONG".into()),
            message: "Password too long".into(),
        });
    }
    if ctx
        .database
        .get_user_by_email_record(&email)
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request(
            "User already exists. Use another email.",
        ));
    }

    let role = requested_role
        .as_ref()
        .map_or_else(|| config.default_role.clone(), joined_role);

    let metadata = body.data.clone().map_or_else(
        || serde_json::json!({}),
        |mut data| {
            drop(data.remove("role"));
            serde_json::Value::Object(data)
        },
    );

    let mut create_user = better_auth_core::CreateUser::new()
        .with_email(&email)
        .with_name(&body.name)
        .with_role(role)
        .with_metadata(metadata);
    if ctx.config.user_validation.is_some() && body.data.is_none() {
        create_user.metadata = None;
    }

    let user = ctx
        .database
        .create_user_with_source_record(
            create_user,
            better_auth_core::user_validation::UserValidationSource::creation("admin"),
        )
        .await?;

    if let Some(password) = body
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        let password_hash = ctx
            .hash_password(
                password_policy
                    .as_ref()
                    .and_then(|policy| policy.password_hasher.as_ref()),
                password,
            )
            .await?;
        drop(
            ctx.database
                .create_account_record(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user.id().to_string(),
                    account_id: user.id().to_string(),
                    provider_id: "credential".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash),
                })
                .await?,
        );
    }

    Ok(UserResponse {
        user: ctx.user_view(&user),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn update_user_core(
    body: &AdminUpdateUserRequest,
    acting_user: &UserView,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AdminUserView> {
    if body.data.is_empty() {
        return Err(AuthError::bad_request(MESSAGE_NO_DATA_TO_UPDATE));
    }

    let mut update = UpdateUser::default();

    if let Some(value) = body.data.get("role") {
        let permissions =
            std::collections::HashMap::from([("user".to_owned(), vec!["set-role".to_owned()])]);
        if !has_permission(
            Some(acting_user.id.as_str()),
            acting_user.role.as_deref(),
            config,
            &permissions,
        ) {
            return Err(AuthError::forbidden(MESSAGE_CHANGE_ROLE));
        }

        let role = serde_json::from_value::<RoleInput>(value.clone())
            .map_err(|_error| AuthError::bad_request(MESSAGE_INVALID_ROLE_TYPE))?;
        validate_role_input(&role, config)?;
        update.role = Some(joined_role(&role));
    }

    if let Some(value) = body.data.get("email").and_then(|value| value.as_str()) {
        update.email = Some(value.to_owned());
    }
    if let Some(value) = body.data.get("name").and_then(|value| value.as_str()) {
        update.name = Some(value.to_owned());
    }
    if let Some(value) = body.data.get("image").and_then(|value| value.as_str()) {
        update.image = Some(value.to_owned());
    }
    if let Some(value) = body
        .data
        .get("emailVerified")
        .and_then(serde_json::Value::as_bool)
    {
        update.email_verified = Some(value);
    }
    if let Some(value) = body.data.get("username").and_then(|value| value.as_str()) {
        update.username = Some(value.to_owned());
    }
    if let Some(value) = body
        .data
        .get("displayUsername")
        .and_then(|value| value.as_str())
    {
        update.display_username = Some(value.to_owned());
    }
    if let Some(value) = body.data.get("banned").and_then(serde_json::Value::as_bool) {
        update.banned = Some(value);
    }
    if let Some(value) = body.data.get("banReason").and_then(|value| value.as_str()) {
        update.ban_reason = Some(value.to_owned());
    }
    if let Some(value) = body.data.get("banExpires").and_then(|value| value.as_str()) {
        let parsed = DateTime::parse_from_rfc3339(value)
            .map_err(|_error| AuthError::bad_request("Invalid banExpires"))?
            .with_timezone(&Utc);
        update.ban_expires = Some(Some(parsed));
    }
    if let Some(value) = body
        .data
        .get("twoFactorEnabled")
        .and_then(serde_json::Value::as_bool)
    {
        update.two_factor_enabled = Some(value);
    }
    if let Some(value) = body
        .data
        .get("metadata")
        .and_then(|value| value.as_object())
    {
        update.metadata = Some(serde_json::Value::Object(value.clone()));
    }

    let updated_user = ctx
        .database
        .update_user_record(&body.user_id, update)
        .await?;
    AdminUserView::from_output(ctx, &updated_user)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_users_core(
    query: &ListUsersQueryParams,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListUsersResponse<AdminUserView>> {
    let params = better_auth_core::ListUsersParams {
        limit: query.limit,
        offset: query.offset,
        search_field: query.search_field.clone(),
        search_value: query.search_value.clone(),
        search_operator: query.search_operator.clone(),
        sort_by: query.sort_by.clone(),
        sort_direction: query.sort_direction.clone(),
        filter_field: query.filter_field.clone(),
        filter_value: query.filter_value.clone(),
        filter_operator: query.filter_operator.clone(),
    };

    // Pinned list-users catches adapter query/count failures after authorization,
    // returning no pagination fields. Authentication and permission errors never
    // reach this boundary.
    let Ok((users, total)) = ctx.database.list_users_record(params).await else {
        return Ok(ListUsersResponse {
            users: Vec::new(),
            total: 0,
            limit: None,
            offset: None,
        });
    };
    Ok(ListUsersResponse {
        users: users
            .iter()
            .map(|user| AdminUserView::from_output(ctx, user))
            .collect::<AuthResult<_>>()?,
        total,
        limit: query.limit.filter(|limit| *limit > 0),
        offset: query.offset.filter(|offset| *offset > 0),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_user_sessions_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<ListSessionsResponse<SessionView>> {
    let sessions = ctx.database.get_user_sessions_record(&body.user_id).await?;
    let now = Utc::now();
    Ok(ListSessionsResponse {
        sessions: sessions
            .iter()
            .filter(|session| session.expires_at() > now && session.active())
            .map(|session| ctx.session_view(session))
            .collect(),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn ban_user_core(
    body: &BanUserRequest,
    admin_user_id: impl AsRef<str>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<UserResponse<AdminUserView>, AdminDateOperationError> {
    if body.user_id == admin_user_id.as_ref() {
        return Err(AuthError::bad_request("You cannot ban yourself").into());
    }

    let _target = ctx
        .database
        .get_user_by_id_record(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    let ban_expires = truthy_duration(body.ban_expires_in)
        .or_else(|| truthy_duration(config.default_ban_expires_in))
        .map(date_after_seconds)
        .transpose()?;

    let update = UpdateUser {
        banned: Some(true),
        ban_reason: Some(
            body.ban_reason
                .clone()
                .filter(|reason| !reason.is_empty())
                .or_else(|| {
                    config
                        .default_ban_reason
                        .clone()
                        .filter(|reason| !reason.is_empty())
                })
                .unwrap_or_else(|| "No reason".to_owned()),
        ),
        ban_expires: Some(ban_expires),
        ..Default::default()
    };

    let updated_user = ctx
        .database
        .update_user_record(&body.user_id, update)
        .await?;
    let _ignored_revoke_all_user_sessions = ctx
        .session_manager()
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(UserResponse {
        user: AdminUserView::from_output(ctx, &updated_user)?,
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn unban_user_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<UserResponse<AdminUserView>> {
    let _target = ctx
        .database
        .get_user_by_id_record(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    let update = UpdateUser {
        banned: Some(false),
        ban_reason: None,
        ban_expires: None,
        ..Default::default()
    };

    let updated_user = ctx
        .database
        .update_user_record(&body.user_id, update)
        .await?;
    Ok(UserResponse {
        user: AdminUserView::from_output(ctx, &updated_user)?,
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn impersonate_user_core(
    body: &UserIdRequest,
    admin_user_id: impl AsRef<str>,
    admin_role: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    config: &AdminConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(SessionUserResponse<SessionView, UserView>, String), AdminDateOperationError> {
    let target = ctx
        .database
        .get_user_by_id_record(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    if target_is_admin(Some(target.id().as_ref()), target.role(), config)
        && !config.allow_impersonating_admins
        && !has_permission(
            Some(admin_user_id.as_ref()),
            admin_role,
            config,
            &std::collections::HashMap::from([(
                "user".to_owned(),
                vec!["impersonate-admins".to_owned()],
            )]),
        )
    {
        return Err(AuthError::forbidden(MESSAGE_CANNOT_IMPERSONATE_ADMINS).into());
    }

    if target.banned() {
        if target
            .ban_expires()
            .is_some_and(|expires| expires < Utc::now())
        {
            drop(
                ctx.database
                    .update_user_record(
                        &body.user_id,
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
            let message = match &config.banned_user_message_callback {
                Some(handler) => handler.message(&target).await?,
                None => config.banned_user_message.clone(),
            };
            return Err(AuthError::banned_user(message).into());
        }
    }

    let expires_at = date_after_seconds(
        truthy_duration(config.impersonation_session_duration).unwrap_or(3600.0),
    )?;
    let create_session = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        active_team_id: None,
        user_id: target.id().to_string(),
        expires_at,
        ip_address: ip_address.map(str::to_owned),
        user_agent: user_agent.map(str::to_owned),
        impersonated_by: Some(admin_user_id.as_ref().to_owned()),
        active_organization_id: None,
    };

    let session = ctx
        .database
        .create_session_record(create_session)
        .await
        .map_err(|error| match error {
            AuthError::SessionCreationCancelled => AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_CREATE_USER",
                message: "Failed to create user",
            },
            other => other,
        })?;
    let token = session.token().to_owned();
    let response = SessionUserResponse {
        session: ctx.session_view(&session),
        user: ctx.user_view(&target),
    };

    Ok((response, token))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn stop_impersonating_core(
    session: &impl AuthSession,
    admin_cookie: &AdminSessionCookiePayload,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionUserResponse<SessionView, UserView>, String)> {
    let admin_id = session
        .impersonated_by()
        .ok_or_else(|| AuthError::bad_request(MESSAGE_NOT_IMPERSONATING))?
        .to_owned();

    let admin_user = ctx
        .database
        .get_user_by_id_record(&admin_id)
        .await?
        .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_USER))?;

    let admin_session = ctx
        .database
        .get_session_record(&admin_cookie.session_token)
        .await?
        .ok_or_else(|| AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION))?;

    if admin_session.user_id() != admin_user.id() {
        return Err(AuthError::internal(MESSAGE_FAILED_TO_FIND_ADMIN_SESSION));
    }

    ctx.session_manager()
        .delete_session(session.token())
        .await?;

    let token = admin_session.token().to_owned();
    let response = SessionUserResponse {
        session: ctx.session_view(&admin_session),
        user: ctx.user_view(&admin_user),
    };

    Ok((response, token))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_user_session_core(
    body: &RevokeSessionRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    ctx.session_manager()
        .delete_session(&body.session_token)
        .await?;
    Ok(SuccessResponse { success: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_user_sessions_core(
    body: &UserIdRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    let _ignored_revoke_all_user_sessions_2 = ctx
        .session_manager()
        .revoke_all_user_sessions(&body.user_id)
        .await?;

    Ok(SuccessResponse { success: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn remove_user_core(
    body: &UserIdRequest,
    admin_user_id: impl AsRef<str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    if body.user_id == admin_user_id.as_ref() {
        return Err(AuthError::bad_request("You cannot remove yourself"));
    }

    let _target = ctx
        .database
        .get_user_by_id_record(&body.user_id)
        .await?
        .ok_or_else(|| AuthError::not_found(MESSAGE_USER_NOT_FOUND))?;

    ctx.database.delete_user_sessions(&body.user_id).await?;

    let accounts = ctx.database.get_user_accounts_record(&body.user_id).await?;
    for account in &accounts {
        ctx.database.delete_account(&account.id()).await?;
    }

    ctx.database.delete_user(&body.user_id).await?;
    Ok(SuccessResponse { success: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn set_user_password_core(
    body: &SetUserPasswordRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let (minimum, maximum) = crate::plugins::email_password::password_length_limits(ctx);
    better_auth_core::utils::password::validate_password(
        &body.new_password,
        minimum,
        maximum,
        ctx,
    )?;

    let target = ctx
        .database
        .get_user_by_id_record(&body.user_id)
        .await?
        .ok_or(AuthError::Upstream {
            status: 404,
            code: "USER_NOT_FOUND",
            message: MESSAGE_USER_NOT_FOUND,
        })?;

    let password_policy = ctx.extensions.get::<crate::plugins::EmailPasswordConfig>();
    let password_hash = ctx
        .hash_password(
            password_policy
                .as_ref()
                .and_then(|policy| policy.password_hasher.as_ref()),
            &body.new_password,
        )
        .await?;

    if let Some(account) =
        crate::plugins::helpers::get_credential_account(ctx, &body.user_id).await?
    {
        drop(
            ctx.database
                .update_account_record(
                    &account.id(),
                    better_auth_core::UpdateAccount {
                        password: Some(password_hash),
                        ..Default::default()
                    },
                )
                .await?,
        );
    } else {
        drop(
            ctx.database
                .create_account_record(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: body.user_id.clone(),
                    account_id: target.id().to_string(),
                    provider_id: "credential".into(),
                    password: Some(password_hash),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?,
        );
    }

    Ok(StatusResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn has_permission_core(
    body: &HasPermissionRequest,
    user: &UserView,
    config: &AdminConfig,
) -> AuthResult<PermissionResponse> {
    let requested = body.requested_permissions().ok_or_else(|| {
        AuthError::bad_request("invalid permission check. no permission(s) were passed.")
    })?;

    Ok(PermissionResponse {
        error: None,
        success: has_permission(
            Some(user.id.as_str()),
            user.role.as_deref(),
            config,
            requested,
        ),
    })
}
