use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Role input accepted by TypeScript admin routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoleInput {
    /// One literal role name.
    One(String),
    /// Literal names stored in order as a comma-separated role.
    Many(Vec<String>),
}

impl RoleInput {
    pub(crate) fn joined(&self) -> String {
        match self {
            Self::One(role) => role.clone(),
            Self::Many(roles) => roles.join(","),
        }
    }

    pub(crate) fn roles(&self) -> Vec<&str> {
        match self {
            Self::One(role) => vec![role.as_str()],
            Self::Many(roles) => roles.iter().map(String::as_str).collect(),
        }
    }
}

/// Input for the admin role assignment server operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetRoleRequest {
    #[serde(rename = "userId")]
    /// The target user identifier.
    pub user_id: String,
    /// Literal role names to assign.
    pub role: RoleInput,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetUserQuery {
    pub id: String,
}

/// Input for trusted or authenticated admin user provisioning.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    /// The new user's email, normalized before storage.
    pub email: String,
    /// Optional credential password; empty strings create no credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The new user's display name.
    pub name: String,
    /// Optional literal role selector, taking precedence over data.role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleInput>,
    /// Optional application fields, subject to the installed permission policy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "alibi_core::utils::json::deserialize_optional_map"
    )]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}
impl CreateUserRequest {
    /// Provision a user without a credential or an explicit role selector.
    #[must_use]
    pub fn new(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: name.into(),
            password: None,
            role: None,
            data: None,
        }
    }
}

/// Target and application fields for an authenticated admin update.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminUpdateUserRequest {
    /// The user to update.
    #[serde(rename = "userId")]
    pub user_id: String,
    /// Fields admitted by the installed admin and user policies.
    #[serde(deserialize_with = "alibi_core::utils::json::deserialize_map")]
    pub data: serde_json::Map<String, serde_json::Value>,
}
impl AdminUpdateUserRequest {
    /// Update the specified user with the supplied application fields.
    #[must_use]
    pub fn new(
        user_id: impl Into<String>,
        data: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            data,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct UserIdRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BanUserRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    #[serde(
        rename = "banExpiresIn",
        default,
        deserialize_with = "finite_optional_duration"
    )]
    pub ban_expires_in: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeSessionRequest {
    #[serde(rename = "sessionToken")]
    pub session_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SetUserPasswordRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

/// Input for trusted or session-based admin permission evaluation.
#[derive(Debug, Serialize, Deserialize)]
pub struct HasPermissionRequest {
    /// User selector for a trusted call; an authenticated session takes precedence.
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Literal role selector for a trusted call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Singular schema alternative; the reference operation requires the plural field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<HashMap<String, Vec<String>>>,
    /// Requested actions grouped by resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

impl HasPermissionRequest {
    /// Check the supplied resource actions, optionally selecting a trusted user or role.
    #[must_use]
    pub fn new(permissions: HashMap<String, Vec<String>>) -> Self {
        Self {
            permissions: Some(permissions),
            user_id: None,
            role: None,
            permission: None,
        }
    }

    pub(crate) fn requested_permissions(&self) -> Option<&HashMap<String, Vec<String>>> {
        self.permissions.as_ref().or(self.permission.as_ref())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct PhysicalAdminUserView {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "alibi_core::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "alibi_core::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires")]
    pub ban_expires: Option<String>,
}

impl<T: alibi_core::entity::AuthUser> From<&T> for PhysicalAdminUserView {
    fn from(user: &T) -> Self {
        Self {
            id: user.id().into_owned(),
            name: user.name().map(str::to_owned),
            email: user.email().map(str::to_owned),
            email_verified: user.email_verified(),
            image: user.image().map(str::to_owned),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            username: user.username().map(str::to_owned),
            display_username: user.display_username().map(str::to_owned),
            two_factor_enabled: user.two_factor_enabled(),
            role: user.role().map(str::to_owned),
            banned: user.banned(),
            ban_reason: user.ban_reason().map(str::to_owned),
            ban_expires: user
                .ban_expires()
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
        }
    }
}

/// Public admin user projection, including returned application fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdminUserView(serde_json::Map<String, serde_json::Value>);

impl AdminUserView {
    /// Access the safe public user fields.
    #[must_use]
    pub const fn values(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.0
    }

    pub(crate) fn from_output<S: alibi_core::AuthSchema>(
        ctx: &alibi_core::AuthContext<S>,
        user: &alibi_core::AdapterRecord<S::User>,
    ) -> alibi_core::AuthResult<Self> {
        let serde_json::Value::Object(mut output) =
            serde_json::to_value(PhysicalAdminUserView::from(user))?
        else {
            return Err(alibi_core::AuthError::internal(
                "Admin user output must be an object",
            ));
        };
        let registered = ctx.extensions.get::<alibi_core::field_policy::UserFields>();
        let fields = registered
            .as_ref()
            .map_or(&ctx.config.user.additional_fields, |fields| &fields.0.0);
        for (name, field) in fields {
            _ = output.remove(name);
            if field.returned
                && let Some(value) = user.raw_snapshot().values().get(name)
            {
                _ = output.insert(name.clone(), value.clone());
            }
        }
        let view = ctx.user_view(user);
        if let Some(value) = view.is_anonymous {
            _ = output.insert("isAnonymous".into(), serde_json::Value::Bool(value));
        }
        output.extend(view.extension_fields);
        Ok(Self(output))
    }
}

/// Public admin operation result containing a safe user projection.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse<U> {
    /// The requested user after the operation.
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionUserResponse<S, U> {
    pub session: S,
    pub user: U,
}

/// Public admin listing with safe user projections and parsed pagination.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListUsersResponse<U> {
    /// The selected page of users.
    pub users: Vec<U>,
    /// Total matching users before pagination.
    pub total: usize,
    /// The effective nonzero limit supplied by the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    /// The effective nonzero offset supplied by the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListSessionsResponse<S> {
    pub sessions: Vec<S>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SuccessResponse {
    pub success: bool,
}

/// Result of a successfully evaluated permission request.
#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionResponse {
    /// The reference successful result carries a null error.
    pub error: Option<String>,
    /// Whether one configured role authorizes all requested resource actions.
    pub success: bool,
}

/// Query parameters for `list_users`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListUsersQueryParams {
    pub source_limit: Option<f64>,
    pub source_offset: Option<f64>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(rename = "searchField")]
    pub search_field: Option<String>,
    #[serde(rename = "searchValue")]
    pub search_value: Option<String>,
    #[serde(rename = "searchOperator")]
    pub search_operator: Option<String>,
    #[serde(rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    pub sort_direction: Option<String>,
    #[serde(rename = "filterField")]
    pub filter_field: Option<String>,
    #[serde(rename = "filterValue")]
    pub filter_value: Option<alibi_core::UserFilterValue>,
    #[serde(rename = "filterOperator")]
    pub filter_operator: Option<String>,
}

fn finite_optional_duration<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let duration = Option::<f64>::deserialize(deserializer)?;
    if duration.is_some_and(|value| !value.is_finite()) {
        return Err(serde::de::Error::custom("banExpiresIn must be finite"));
    }
    Ok(duration)
}

/// Logical query for admin listing; scalar and array filters retain their JSON types.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminListUsersQuery {
    /// A numeric or string limit, interpreted with JavaScript Number semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<serde_json::Value>,
    /// A numeric or string offset, interpreted with JavaScript Number semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<serde_json::Value>,
    /// Text to search for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_value: Option<String>,
    /// Search field: email or name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_field: Option<String>,
    /// Search operator: contains, `starts_with` or `ends_with`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_operator: Option<String>,
    /// Field to sort by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
    /// Ascending or descending order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_direction: Option<String>,
    /// Field to filter, defaulting to email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_field: Option<String>,
    /// A string, number, boolean, or homogeneous string/number array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_value: Option<serde_json::Value>,
    /// The comparison operator for the filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_operator: Option<String>,
}
