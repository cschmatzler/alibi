use crate::utils::normalize_user_email;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;
/// User creation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    /// Trusted provider value before boolean storage conversion. HTTP input
    /// cannot populate this; native accessors retain their boolean interface.
    #[serde(skip)]
    pub provider_email_verified: Option<serde_json::Value>,
    /// Trusted raw provider text scalars, never accepted from HTTP user input.
    #[serde(skip)]
    pub provider_name: Option<serde_json::Value>,
    #[serde(skip)]
    pub provider_image: Option<serde_json::Value>,
    #[serde(flatten, default)]
    pub additional_fields: crate::field_policy::FieldValues,
    pub id: Option<String>,
    /// Trusted creation timestamps; omitted values use the adapter's clock.
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    /// `None` leaves the two-factor plugin field unset.
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    /// `None` leaves the admin plugin field unset.
    pub banned: Option<bool>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub last_login_method: Option<String>,
}

/// User update data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUser {
    /// Trusted provider value, independent from the typed boolean authority.
    #[serde(skip)]
    pub provider_email_verified: Option<serde_json::Value>,
    /// Trusted raw provider text scalars, never accepted from HTTP user input.
    #[serde(skip)]
    pub provider_name: Option<serde_json::Value>,
    #[serde(skip)]
    pub provider_image: Option<serde_json::Value>,
    #[serde(flatten, default)]
    pub additional_fields: crate::field_policy::FieldValues,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    /// `None` leaves the expiry unchanged; `Some(None)` clears it without unbanning.
    #[serde(
        default,
        deserialize_with = "deserialize_ban_expiry_patch",
        skip_serializing_if = "Option::is_none"
    )]
    pub ban_expires: Option<Option<DateTime<Utc>>>,
    pub two_factor_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    pub is_anonymous: Option<bool>,
    /// `None` leaves the field unchanged; `Some(None)` clears it.
    pub phone_number: Option<Option<String>>,
    pub phone_number_verified: Option<bool>,
    /// `None` leaves the field unchanged; `Some(None)` clears it.
    pub last_login_method: Option<Option<String>>,
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub additional_fields: crate::field_policy::FieldValues,
    /// Optional token override for trusted database hooks and server-side creation.
    /// Stores generate a secure 32-character alphanumeric token when omitted.
    pub token: Option<String>,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
}

/// Account creation data
#[derive(Debug, Clone)]
pub struct CreateAccount {
    pub additional_fields: crate::field_policy::FieldValues,
    pub user_id: String,
    pub account_id: String,
    pub provider_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Account update data (for refreshing OAuth tokens)
#[derive(Debug, Clone, Default)]
pub struct UpdateAccount {
    /// Trusted OAuth writes distinguish an explicit token null from omission.
    /// Order: access token, refresh token, ID token. Defaults retain omission.
    pub provider_token_nulls: [bool; 3],
    pub additional_fields: crate::field_policy::FieldValues,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Verification token creation data
#[derive(Debug, Clone)]
pub struct CreateVerification {
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateVerification {
    pub value: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CreateUser {
    #[must_use]
    pub fn new() -> Self {
        Self {
            additional_fields: crate::field_policy::FieldValues::new(),
            id: None,
            created_at: None,
            updated_at: None,
            email: None,
            name: None,
            image: None,
            email_verified: None,
            provider_email_verified: None,
            provider_name: None,
            provider_image: None,
            username: None,
            display_username: None,
            two_factor_enabled: None,
            role: None,
            banned: None,
            metadata: None,
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            last_login_method: None,
        }
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(normalize_user_email(&email.into()));
        self
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    #[must_use]
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl Default for CreateUser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    pub role: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserResponse<U> {
    pub user: U,
}

/// String operands for admin user-list filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserFilterValue {
    /// One complete scalar string operand.
    Scalar(String),
    /// Ordered operands, including duplicates, for membership or adapter queries.
    Multiple(Vec<String>),
}

impl From<String> for UserFilterValue {
    fn from(value: String) -> Self {
        Self::Scalar(value)
    }
}

impl From<&str> for UserFilterValue {
    fn from(value: &str) -> Self {
        Self::Scalar(value.to_owned())
    }
}

impl From<Vec<String>> for UserFilterValue {
    fn from(value: Vec<String>) -> Self {
        Self::Multiple(value)
    }
}

/// Parameters for listing users through the configured adapter.
#[derive(Debug, Clone, Default)]
pub struct ListUsersParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub search_field: Option<String>,
    pub search_value: Option<String>,
    pub search_operator: Option<String>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<UserFilterValue>,
    pub filter_operator: Option<String>,
}

#[expect(
    clippy::option_option,
    reason = "The wire contract distinguishes an omitted field, explicit null, and a supplied value"
)]
pub(in crate::types) fn deserialize_ban_expiry_patch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<DateTime<Utc>>>, D::Error> {
    Option::<DateTime<Utc>>::deserialize(deserializer).map(Some)
}
