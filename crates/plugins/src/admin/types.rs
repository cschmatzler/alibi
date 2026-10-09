use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Role input accepted by TypeScript admin routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum RoleInput {
    One(String),
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

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct SetRoleRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: RoleInput,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetUserQuery {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateUserRequest {
    pub email: String,
    pub password: Option<String>,
    pub name: String,
    pub role: Option<RoleInput>,
    #[serde(
        default,
        deserialize_with = "alibi_core::utils::json::deserialize_optional_map"
    )]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminUpdateUserRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(deserialize_with = "alibi_core::utils::json::deserialize_map")]
    pub data: serde_json::Map<String, serde_json::Value>,
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

#[derive(Debug, Deserialize)]
#[expect(
    dead_code,
    reason = "server-side HTTP route currently checks session user only"
)]
pub(crate) struct HasPermissionRequest {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    pub role: Option<String>,
    pub permission: Option<HashMap<String, Vec<String>>>,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

impl HasPermissionRequest {
    pub(crate) fn requested_permissions(
        &self,
    ) -> Option<&HashMap<String, Vec<String>>> {
        self.permissions.as_ref().or(self.permission.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

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

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct AdminUserView(serde_json::Map<String, serde_json::Value>);

impl AdminUserView {
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
            drop(output.remove(name));
            if field.returned
                && let Some(value) = user.raw_snapshot().values().get(name)
            {
                drop(output.insert(name.clone(), value.clone()));
            }
        }
        let view = ctx.user_view(user);
        if let Some(value) = view.is_anonymous {
            drop(output.insert("isAnonymous".into(), serde_json::Value::Bool(value)));
        }
        output.extend(view.extension_fields);
        Ok(Self(output))
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct UserResponse<U> {
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionUserResponse<S, U> {
    pub session: S,
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListUsersResponse<U> {
    pub users: Vec<U>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListSessionsResponse<S> {
    pub sessions: Vec<S>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PermissionResponse {
    pub error: Option<String>,
    pub success: bool,
}

/// Query parameters for `list_users`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListUsersQueryParams {
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
