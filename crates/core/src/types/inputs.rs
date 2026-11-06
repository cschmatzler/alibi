use crate::field_policy::FieldValues;
use crate::utils::normalize_user_email;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;
/// User creation data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateUser {
    /// Trusted native adapter inputs; HTTP deserialization cannot populate this channel.
    #[serde(skip)]
    pub adapter_native_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// Trusted provider value before boolean storage conversion. HTTP input
    /// cannot populate this; native accessors retain their boolean interface.
    #[serde(skip)]
    pub provider_email_verified: Option<crate::utils::json::JsValue>,
    /// Trusted raw provider text scalars, never accepted from HTTP user input.
    #[serde(skip)]
    pub provider_name: Option<crate::utils::json::JsValue>,
    /// Trusted raw provider image scalar.
    #[serde(skip)]
    pub provider_image: Option<crate::utils::json::JsValue>,
    /// Trusted original provider email; retained through admission and hooks.
    #[serde(skip)]
    pub provider_email: Option<crate::utils::json::JsValue>,
    #[serde(flatten, default)]
    pub additional_fields: FieldValues,
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
    /// Trusted native adapter updates; HTTP deserialization cannot populate this channel.
    #[serde(skip)]
    pub adapter_native_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// Trusted provider value, independent from the typed boolean authority.
    #[serde(skip)]
    pub provider_email_verified: Option<crate::utils::json::JsValue>,
    /// Trusted raw provider text scalars, never accepted from HTTP user input.
    #[serde(skip)]
    pub provider_name: Option<crate::utils::json::JsValue>,
    /// Trusted raw image scalar, also used for validated profile image removal.
    #[serde(skip)]
    pub provider_image: Option<crate::utils::json::JsValue>,
    /// Trusted original provider email; retained through admission and hooks.
    #[serde(skip)]
    pub provider_email: Option<crate::utils::json::JsValue>,
    #[serde(flatten, default)]
    pub additional_fields: FieldValues,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    /// Explicitly clear the reason; takes precedence over `ban_reason`.
    #[serde(skip)]
    pub clear_ban_reason: bool,
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
    pub additional_fields: FieldValues,
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
    pub additional_fields: FieldValues,
    pub user_id: String,
    pub account_id: crate::utils::json::JsString,
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
    pub additional_fields: FieldValues,
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

macro_rules! native_shadow_reconciliation {
    ($input:ty; $($field:ident => $key:literal),* $(,)?) => {
        impl $input {
    /// Reconcile the two native callback interfaces after a typed transform.
    /// Explicit raw edits win. Removing a raw override restores typed fallback;
    /// it does not create an own JavaScript undefined property.
    pub(crate) fn reconcile_native_shadows(&mut self, before: &Self) {
        for (key, changed) in [$(($key, self.$field != before.$field)),*] {
            if changed && self.adapter_native_fields.get(key) == before.adapter_native_fields.get(key) {
                _ = self.adapter_native_fields.remove(key);
            }
        }
        if self.name != before.name && self.provider_name == before.provider_name {
            self.provider_name = None;
        }
        if self.email != before.email && self.provider_email == before.provider_email {
            self.provider_email = None;
        }
        if self.image != before.image && self.provider_image == before.provider_image {
            self.provider_image = None;
        }
        if self.email_verified != before.email_verified
            && self.provider_email_verified == before.provider_email_verified {
            self.provider_email_verified = None;
        }
    }
        }
    };
}

native_shadow_reconciliation!(CreateUser;
    id => "id", name => "name", email => "email", image => "image",
    email_verified => "emailVerified", username => "username",
    display_username => "displayUsername", two_factor_enabled => "twoFactorEnabled",
    role => "role", banned => "banned", metadata => "metadata",
    is_anonymous => "isAnonymous", phone_number => "phoneNumber",
    phone_number_verified => "phoneNumberVerified", last_login_method => "lastLoginMethod",
    created_at => "createdAt", updated_at => "updatedAt",
);
native_shadow_reconciliation!(UpdateUser;
    name => "name", email => "email", image => "image",
    email_verified => "emailVerified", username => "username",
    display_username => "displayUsername", two_factor_enabled => "twoFactorEnabled",
    role => "role", banned => "banned", metadata => "metadata",
    is_anonymous => "isAnonymous", phone_number => "phoneNumber",
    phone_number_verified => "phoneNumberVerified", last_login_method => "lastLoginMethod",
    ban_reason => "banReason", clear_ban_reason => "banReason", ban_expires => "banExpires",
);

impl CreateUser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

/// Operands for admin user-list filtering, before adapter field transformations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserFilterValue {
    /// One complete scalar string operand.
    Scalar(String),
    /// Ordered operands, including duplicates, for membership or adapter queries.
    Multiple(Vec<String>),
    /// Original JavaScript operand, including numbers, booleans and UTF-16 strings.
    Native(crate::utils::json::JsValue),
}

impl UserFilterValue {
    /// Recover the original operand without string coercion.
    #[must_use]
    pub fn native(&self) -> crate::utils::json::JsValue {
        use crate::utils::json::JsValue;
        match self {
            Self::Scalar(value) => JsValue::String(value.clone().into()),
            Self::Multiple(values) => JsValue::Array(
                values
                    .iter()
                    .map(|value| JsValue::String(value.clone().into()))
                    .collect(),
            ),
            Self::Native(value) => value.clone(),
        }
    }
}

impl From<crate::utils::json::JsValue> for UserFilterValue {
    fn from(value: crate::utils::json::JsValue) -> Self {
        use crate::utils::json::JsValue;
        match &value {
            JsValue::String(text) => {
                if let Some(text) = text.as_str() {
                    return Self::Scalar(text.to_owned());
                }
            }
            JsValue::Array(values) => {
                if let Some(values) = values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                {
                    return Self::Multiple(values);
                }
            }
            _ => {}
        }
        Self::Native(value)
    }
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
    /// Original JavaScript limit, retained for backend pagination semantics.
    pub source_limit: Option<f64>,
    /// Original JavaScript offset, retained for backend pagination semantics.
    pub source_offset: Option<f64>,
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
