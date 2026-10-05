//! Entity traits for the Better Auth framework.
//!
//! These traits define the interface that entity types must implement.
//! The framework accesses entity fields through these trait methods,
//! allowing users to define their own entity structs with custom field names
//! and extra fields.
//!
//! Implement these traits manually for any custom types used inside the auth
//! runtime.

use crate::types::InvitationStatus;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;

/// Conversion between an application timestamp field and the auth UTC clock.
///
/// `NaiveDateTime` fields represent UTC wall-clock values, never local time.
/// The optional implementation preserves typed absence in model mutations.
pub trait AuthTimestamp: Sized {
    /// The core timestamp shape (`DateTime<Utc>` or its optional form).
    type UtcValue;
    /// Convert a core UTC timestamp into the model representation.
    fn from_utc(value: Self::UtcValue) -> Self;
    /// Interpret the model timestamp on the core UTC clock.
    fn into_utc(self) -> Self::UtcValue;
}

impl AuthTimestamp for chrono::NaiveDateTime {
    type UtcValue = DateTime<Utc>;
    fn from_utc(value: Self::UtcValue) -> Self {
        value.naive_utc()
    }
    fn into_utc(self) -> Self::UtcValue {
        self.and_utc()
    }
}

impl<Tz: chrono::TimeZone> AuthTimestamp for DateTime<Tz>
where
    DateTime<Tz>: From<DateTime<Utc>>,
{
    type UtcValue = DateTime<Utc>;
    fn from_utc(value: Self::UtcValue) -> Self {
        value.into()
    }
    fn into_utc(self) -> Self::UtcValue {
        self.with_timezone(&Utc)
    }
}

impl<T: AuthTimestamp> AuthTimestamp for Option<T> {
    type UtcValue = Option<T::UtcValue>;
    fn from_utc(value: Self::UtcValue) -> Self {
        value.map(T::from_utc)
    }
    fn into_utc(self) -> Self::UtcValue {
        self.map(T::into_utc)
    }
}

/// Trait representing a user entity.
///
/// The framework reads user fields through these getters. Custom types
/// must provide all framework fields and may have additional fields.
pub trait AuthUser: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    /// Encode the complete typed model for a trusted secondary backend.
    /// Custom entities can opt in without adding a Deserialize bound to all schemas.
    fn secondary_snapshot(&self) -> crate::AuthResult<serde_json::Value> {
        Err(crate::AuthError::NotImplemented(
            "Secondary model encoding is unsupported".into(),
        ))
    }
    /// Restore a model from a trusted secondary backend, before public projection.
    fn from_secondary_snapshot(_snapshot: serde_json::Value) -> crate::AuthResult<Self> {
        Err(crate::AuthError::NotImplemented(
            "Secondary model decoding is unsupported".into(),
        ))
    }

    /// A genuine retained adapter result, including declared undefined values.
    fn adapter_snapshot(&self) -> Option<&crate::AdapterOutput> {
        None
    }
    /// A chosen authenticated view is already projected and must remain exact.
    fn retained_user_view(&self) -> Option<&crate::UserView> {
        None
    }
    /// Physical application/plugin values; public policy is applied separately.
    fn additional_fields(&self) -> crate::field_policy::FieldOutput {
        crate::field_policy::FieldOutput::new()
    }
    fn id(&self) -> Cow<'_, str>;
    fn email(&self) -> Option<&str>;
    fn name(&self) -> Option<&str>;
    fn email_verified(&self) -> bool;
    fn image(&self) -> Option<&str>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
    fn username(&self) -> Option<&str>;
    fn display_username(&self) -> Option<&str>;
    fn two_factor_enabled(&self) -> bool;
    /// Persisted plugin state. `None` preserves an absent or unset field.
    fn two_factor_enabled_value(&self) -> Option<bool> {
        Some(self.two_factor_enabled())
    }
    fn role(&self) -> Option<&str>;
    fn banned(&self) -> bool;
    /// Persisted plugin state. `None` preserves an absent or unset field.
    fn banned_value(&self) -> Option<bool> {
        Some(self.banned())
    }
    fn ban_reason(&self) -> Option<&str>;
    fn ban_expires(&self) -> Option<DateTime<Utc>>;
    fn metadata(&self) -> &serde_json::Value;
    /// Anonymous-plugin state; `None` means the field is absent or unset.
    fn is_anonymous(&self) -> Option<bool> {
        None
    }
    fn phone_number(&self) -> Option<&str> {
        None
    }
    fn phone_number_verified(&self) -> Option<bool> {
        None
    }
    fn last_login_method(&self) -> Option<&str> {
        None
    }
}

/// Trait representing a session entity.
pub trait AuthSession: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    /// Encode the complete typed model for a trusted secondary backend.
    /// Custom entities can opt in without adding a Deserialize bound to all schemas.
    fn secondary_snapshot(&self) -> crate::AuthResult<serde_json::Value> {
        Err(crate::AuthError::NotImplemented(
            "Secondary model encoding is unsupported".into(),
        ))
    }
    /// Restore a model from a trusted secondary backend, before public projection.
    fn from_secondary_snapshot(_snapshot: serde_json::Value) -> crate::AuthResult<Self> {
        Err(crate::AuthError::NotImplemented(
            "Secondary model decoding is unsupported".into(),
        ))
    }

    fn adapter_snapshot(&self) -> Option<&crate::AdapterOutput> {
        None
    }
    fn retained_session_view(&self) -> Option<&crate::SessionView> {
        None
    }
    fn additional_fields(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
    fn id(&self) -> Cow<'_, str>;
    fn expires_at(&self) -> DateTime<Utc>;
    fn token(&self) -> &str;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
    fn ip_address(&self) -> Option<&str>;
    fn user_agent(&self) -> Option<&str>;
    fn user_id(&self) -> Cow<'_, str>;
    fn impersonated_by(&self) -> Option<&str>;
    fn active_organization_id(&self) -> Option<&str>;
    fn active_team_id(&self) -> Option<&str> {
        None
    }
    fn active(&self) -> bool;
}

/// Trait representing an account entity (OAuth provider linking).
pub trait AuthAccount: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn adapter_snapshot(&self) -> Option<&crate::AdapterOutput> {
        None
    }
    fn additional_fields(&self) -> crate::field_policy::FieldOutput {
        crate::field_policy::FieldOutput::new()
    }
    fn id(&self) -> Cow<'_, str>;
    fn account_id(&self) -> &str;
    fn provider_id(&self) -> &str;
    fn user_id(&self) -> Cow<'_, str>;
    fn access_token(&self) -> Option<&str>;
    fn refresh_token(&self) -> Option<&str>;
    fn id_token(&self) -> Option<&str>;
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>>;
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>>;
    fn scope(&self) -> Option<&str>;
    fn password(&self) -> Option<&str>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing an organization entity.
pub trait AuthOrganization: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn additional_fields(&self) -> std::collections::BTreeMap<String, serde_json::Value> {
        Default::default()
    }
    fn id(&self) -> Cow<'_, str>;
    fn name(&self) -> &str;
    fn slug(&self) -> &str;
    fn logo(&self) -> Option<&str>;
    fn metadata(&self) -> Option<&serde_json::Value>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing an organization member entity.
pub trait AuthMember: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> Cow<'_, str>;
    fn organization_id(&self) -> Cow<'_, str>;
    fn user_id(&self) -> Cow<'_, str>;
    fn role(&self) -> &str;
    fn created_at(&self) -> DateTime<Utc>;
}

/// Trait representing an invitation entity.
pub trait AuthInvitation: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> Cow<'_, str>;
    fn organization_id(&self) -> Cow<'_, str>;
    fn email(&self) -> &str;
    fn role(&self) -> &str;
    fn optional_role(&self) -> Option<&str> {
        Some(self.role())
    }
    fn team_id(&self) -> Option<&str> {
        None
    }
    fn status(&self) -> &InvitationStatus;
    fn inviter_id(&self) -> Cow<'_, str>;
    fn expires_at(&self) -> DateTime<Utc>;
    fn created_at(&self) -> DateTime<Utc>;

    /// Check if the invitation is still pending.
    fn is_pending(&self) -> bool {
        *self.status() == InvitationStatus::Pending
    }

    /// Check if the invitation has expired.
    fn is_expired(&self) -> bool {
        self.expires_at() < Utc::now()
    }
}

/// Trait representing a verification token entity.
pub trait AuthVerification: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> Cow<'_, str>;
    fn identifier(&self) -> &str;
    fn value(&self) -> &str;
    fn expires_at(&self) -> DateTime<Utc>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing a two-factor authentication entity.
pub trait AuthTwoFactor: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> Cow<'_, str>;
    fn secret(&self) -> &str;
    fn backup_codes(&self) -> &str;
    fn user_id(&self) -> Cow<'_, str>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
    /// Legacy records without this field are not explicitly unverified.
    fn verified(&self) -> Option<bool> {
        None
    }
    fn failed_verification_count(&self) -> Option<f64> {
        None
    }
    fn locked_until(&self) -> Option<DateTime<Utc>> {
        None
    }
}

/// Trait representing an API key entity.
pub trait AuthApiKey: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> Cow<'_, str>;
    fn name(&self) -> Option<&str>;
    fn start(&self) -> Option<&str>;
    fn prefix(&self) -> Option<&str>;
    fn key_hash(&self) -> &str;
    /// Owner of the key — a user id, or an organization id when the key's
    /// configuration references organizations.
    fn reference_id(&self) -> Cow<'_, str>;
    /// Name of the API-key configuration this key belongs to (`"default"`
    /// unless the application registers named configurations).
    fn config_id(&self) -> Cow<'_, str>;
    fn refill_interval(&self) -> Option<f64>;
    fn refill_amount(&self) -> Option<f64>;
    fn last_refill_at(&self) -> Option<&str>;
    fn enabled(&self) -> bool;
    fn rate_limit_enabled(&self) -> bool;
    fn rate_limit_time_window(&self) -> Option<f64>;
    fn rate_limit_max(&self) -> Option<f64>;
    fn request_count(&self) -> Option<f64>;
    fn remaining(&self) -> Option<f64>;
    fn last_request(&self) -> Option<&str>;
    fn expires_at(&self) -> Option<&str>;
    fn created_at(&self) -> &str;
    fn updated_at(&self) -> &str;
    fn permissions(&self) -> Option<&str>;
    fn metadata(&self) -> Option<&str>;
}

/// Trait representing a passkey entity.
pub trait AuthPasskey: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> Cow<'_, str>;
    fn name(&self) -> Option<&str>;
    fn public_key(&self) -> &str;
    fn user_id(&self) -> Cow<'_, str>;
    fn credential_id(&self) -> &str;
    fn counter(&self) -> u64;
    fn device_type(&self) -> &str;
    fn backed_up(&self) -> bool;
    fn transports(&self) -> Option<&str>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
    fn aaguid(&self) -> Option<&str>;
    fn credential(&self) -> &str;
}

/// Minimal user info for member-related API responses.
///
/// This is a concrete framework type (not generic) used to project
/// user fields into member responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberUserView {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
}

impl MemberUserView {
    /// Construct from any type implementing [`AuthUser`].
    #[must_use]
    pub fn from_user(user: &impl AuthUser) -> Self {
        Self {
            id: user.id().to_string(),
            email: user.email().map(ToOwned::to_owned),
            name: user.name().map(ToOwned::to_owned),
            image: user.image().map(ToOwned::to_owned),
        }
    }
}
