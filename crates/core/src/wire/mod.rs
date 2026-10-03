//! Concrete auth types for API responses and framework callbacks.
//!
//! These types decouple JSON response shapes from app-owned `SeaORM` entities.
//! Each view implements its corresponding `Auth*` entity trait, allowing it
//! to be used in trait-generic framework code (hooks, helpers).

use crate::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthOrganization, AuthPasskey, AuthSession, AuthUser,
    AuthVerification,
};
use crate::types::InvitationStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;

/// Public user response shape.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(try_from = "UserViewInput")]
pub struct UserView {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(
        rename = "displayUsername",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_username: Option<String>,
    #[serde(
        rename = "twoFactorEnabled",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub two_factor_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banned: Option<bool>,
    #[serde(rename = "banReason", default, skip_serializing_if = "Option::is_none")]
    pub ban_reason: Option<String>,
    #[serde(
        rename = "banExpires",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    pub ban_expires: Option<DateTime<Utc>>,
    #[serde(
        rename = "isAnonymous",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_anonymous: Option<bool>,
    #[serde(
        rename = "phoneNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub phone_number: Option<String>,
    #[serde(
        rename = "phoneNumberVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub phone_number_verified: Option<bool>,
    #[serde(
        rename = "lastLoginMethod",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_login_method: Option<String>,
    /// Nullable fields contributed by an enabled plugin's output schema.
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    pub extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    pub metadata: serde_json::Value,
    /// Fields absent from an authenticated cache projection.
    #[serde(skip)]
    pub omitted_fields: std::collections::BTreeSet<String>,
}

impl Serialize for UserView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        macro_rules! entry {
            ($name:literal, $value:expr) => {
                if !self.omitted_fields.contains($name) {
                    map.serialize_entry($name, $value)?;
                }
            };
        }
        entry!("id", &self.id);
        entry!("name", &self.name);
        entry!("email", &self.email);
        if let Some(value) = self.extension_fields.get("emailVerified") {
            entry!("emailVerified", value);
        } else {
            entry!("emailVerified", &self.email_verified);
        }
        entry!("image", &self.image);
        entry!(
            "createdAt",
            &crate::utils::datetime::json_date_millis(self.created_at.timestamp_millis())
        );
        entry!(
            "updatedAt",
            &crate::utils::datetime::json_date_millis(self.updated_at.timestamp_millis())
        );
        if let Some(value) = &self.username {
            entry!("username", value);
        }
        if let Some(value) = &self.display_username {
            entry!("displayUsername", value);
        }
        if let Some(value) = &self.two_factor_enabled {
            entry!("twoFactorEnabled", value);
        }
        if let Some(value) = &self.role {
            entry!("role", value);
        }
        if let Some(value) = &self.banned {
            entry!("banned", value);
        }
        if let Some(value) = &self.ban_reason {
            entry!("banReason", value);
        }
        if let Some(value) = &self.ban_expires {
            entry!(
                "banExpires",
                &crate::utils::datetime::json_date_millis(value.timestamp_millis())
            );
        }
        if let Some(value) = &self.is_anonymous {
            entry!("isAnonymous", value);
        }
        if let Some(value) = &self.phone_number {
            entry!("phoneNumber", value);
        }
        if let Some(value) = &self.phone_number_verified {
            entry!("phoneNumberVerified", value);
        }
        if let Some(value) = &self.last_login_method {
            entry!("lastLoginMethod", value);
        }
        for (name, value) in &self.extension_fields {
            if name != "emailVerified" && !self.omitted_fields.contains(name) {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
    }
}

#[derive(Deserialize)]
struct UserViewInput {
    id: String,
    name: Option<String>,
    email: Option<String>,
    #[serde(rename = "emailVerified")]
    email_verified: serde_json::Value,
    image: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(
        rename = "displayUsername",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    display_username: Option<String>,
    #[serde(
        rename = "twoFactorEnabled",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    two_factor_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    banned: Option<bool>,
    #[serde(rename = "banReason", default, skip_serializing_if = "Option::is_none")]
    ban_reason: Option<String>,
    #[serde(
        rename = "banExpires",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    ban_expires: Option<DateTime<Utc>>,
    #[serde(
        rename = "isAnonymous",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    is_anonymous: Option<bool>,
    #[serde(
        rename = "phoneNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    phone_number: Option<String>,
    #[serde(
        rename = "phoneNumberVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    phone_number_verified: Option<bool>,
    #[serde(
        rename = "lastLoginMethod",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    last_login_method: Option<String>,
    /// Nullable fields contributed by an enabled plugin's output schema.
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    metadata: serde_json::Value,
}

impl TryFrom<UserViewInput> for UserView {
    type Error = &'static str;
    fn try_from(mut input: UserViewInput) -> Result<Self, Self::Error> {
        let email_verified = match &input.email_verified {
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::String(value) => !value.is_empty(),
            _ => {
                return Err("User verification output must be a boolean or retained SQLite string");
            }
        };
        if !input.email_verified.is_boolean() {
            drop(
                input
                    .extension_fields
                    .insert("emailVerified".into(), input.email_verified),
            );
        }
        Ok(Self {
            email_verified,
            extension_fields: input.extension_fields,
            id: input.id,
            name: input.name,
            email: input.email,
            image: input.image,
            created_at: input.created_at,
            updated_at: input.updated_at,
            username: input.username,
            display_username: input.display_username,
            two_factor_enabled: input.two_factor_enabled,
            role: input.role,
            banned: input.banned,
            ban_reason: input.ban_reason,
            ban_expires: input.ban_expires,
            is_anonymous: input.is_anonymous,
            phone_number: input.phone_number,
            phone_number_verified: input.phone_number_verified,
            last_login_method: input.last_login_method,
            metadata: input.metadata,
            omitted_fields: std::collections::BTreeSet::default(),
        })
    }
}

/// Public session response shape.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SessionView {
    pub id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(
        rename = "impersonatedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub impersonated_by: Option<String>,
    #[serde(
        rename = "activeOrganizationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub active_organization_id: Option<String>,
    #[serde(
        rename = "activeTeamId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub active_team_id: Option<String>,
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    pub extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    pub active: bool,
    #[serde(skip)]
    pub omitted_fields: std::collections::BTreeSet<String>,
}

impl Serialize for SessionView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        macro_rules! entry {
            ($name:literal, $value:expr) => {
                if !self.omitted_fields.contains($name) {
                    map.serialize_entry($name, $value)?;
                }
            };
        }
        entry!("id", &self.id);
        entry!(
            "expiresAt",
            &crate::utils::datetime::json_date_millis(self.expires_at.timestamp_millis())
        );
        entry!("token", &self.token);
        entry!(
            "createdAt",
            &crate::utils::datetime::json_date_millis(self.created_at.timestamp_millis())
        );
        entry!(
            "updatedAt",
            &crate::utils::datetime::json_date_millis(self.updated_at.timestamp_millis())
        );
        entry!("ipAddress", &self.ip_address);
        entry!("userAgent", &self.user_agent);
        entry!("userId", &self.user_id);
        if let Some(value) = &self.impersonated_by {
            entry!("impersonatedBy", value);
        }
        if let Some(value) = &self.active_organization_id {
            entry!("activeOrganizationId", value);
        }
        if let Some(value) = &self.active_team_id {
            entry!("activeTeamId", value);
        }
        for (name, value) in &self.extension_fields {
            if !self.omitted_fields.contains(name) {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
    }
}

/// Public account response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountView {
    pub id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(rename = "refreshTokenExpiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
}

/// Public verification response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationView {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
}

impl<T: AuthUser> From<&T> for UserView {
    fn from(user: &T) -> Self {
        let mut view = Self {
            id: user.id().into_owned(),
            name: user.name().map(str::to_owned),
            email: user.email().map(str::to_owned),
            email_verified: user.email_verified(),
            image: user.image().map(str::to_owned),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            username: user.username().map(str::to_owned),
            display_username: user.display_username().map(str::to_owned),
            two_factor_enabled: user.two_factor_enabled_value(),
            role: user.role().map(str::to_owned),
            banned: user.banned_value(),
            ban_reason: user.ban_reason().map(str::to_owned),
            ban_expires: user.ban_expires(),
            is_anonymous: user.is_anonymous(),
            phone_number: user.phone_number().map(str::to_owned),
            phone_number_verified: user.phone_number_verified(),
            last_login_method: user.last_login_method().map(str::to_owned),
            extension_fields: std::collections::BTreeMap::default(),
            metadata: user.metadata().clone(),
            omitted_fields: std::collections::BTreeSet::default(),
        };
        if let Some(value) = user
            .adapter_snapshot()
            .and_then(|output| output.values().get("emailVerified"))
            && !value.is_boolean()
        {
            drop(
                view.extension_fields
                    .insert("emailVerified".into(), value.clone()),
            );
        }
        view
    }
}

impl<T: AuthSession> From<&T> for SessionView {
    fn from(session: &T) -> Self {
        Self {
            id: session.id().into_owned(),
            expires_at: session.expires_at(),
            token: session.token().to_owned(),
            created_at: session.created_at(),
            updated_at: session.updated_at(),
            ip_address: session.ip_address().map(str::to_owned),
            user_agent: session.user_agent().map(str::to_owned),
            user_id: session.user_id().into_owned(),
            impersonated_by: session.impersonated_by().map(str::to_owned),
            active_organization_id: session.active_organization_id().map(str::to_owned),
            active_team_id: session.active_team_id().map(str::to_owned),
            extension_fields: session.additional_fields().into_iter().collect(),
            omitted_fields: std::collections::BTreeSet::default(),
            active: session.active(),
        }
    }
}

impl<T: AuthAccount> From<&T> for AccountView {
    fn from(account: &T) -> Self {
        Self {
            id: account.id().into_owned(),
            account_id: account.account_id().to_owned(),
            provider_id: account.provider_id().to_owned(),
            user_id: account.user_id().into_owned(),
            access_token: account.access_token().map(str::to_owned),
            refresh_token: account.refresh_token().map(str::to_owned),
            id_token: account.id_token().map(str::to_owned),
            access_token_expires_at: account.access_token_expires_at(),
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope().map(str::to_owned),
            password: account.password().map(str::to_owned),
            created_at: account.created_at(),
            updated_at: account.updated_at(),
        }
    }
}

impl<T: AuthVerification> From<&T> for VerificationView {
    fn from(verification: &T) -> Self {
        Self {
            id: verification.id().into_owned(),
            identifier: verification.identifier().to_owned(),
            value: verification.value().to_owned(),
            expires_at: verification.expires_at(),
            created_at: verification.created_at(),
            updated_at: verification.updated_at(),
        }
    }
}

impl AuthUser for UserView {
    fn retained_user_view(&self) -> Option<&UserView> {
        Some(self)
    }
    fn additional_fields(&self) -> crate::field_policy::FieldOutput {
        self.extension_fields.clone().into_iter().collect()
    }
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn email_verified(&self) -> bool {
        self.email_verified
    }
    fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    fn display_username(&self) -> Option<&str> {
        self.display_username.as_deref()
    }
    fn two_factor_enabled(&self) -> bool {
        self.two_factor_enabled.unwrap_or(false)
    }

    fn two_factor_enabled_value(&self) -> Option<bool> {
        self.two_factor_enabled
    }
    fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
    fn banned(&self) -> bool {
        self.banned.unwrap_or(false)
    }

    fn banned_value(&self) -> Option<bool> {
        self.banned
    }
    fn ban_reason(&self) -> Option<&str> {
        self.ban_reason.as_deref()
    }
    fn ban_expires(&self) -> Option<DateTime<Utc>> {
        self.ban_expires
    }
    fn is_anonymous(&self) -> Option<bool> {
        self.is_anonymous
    }
    fn phone_number(&self) -> Option<&str> {
        self.phone_number.as_deref()
    }
    fn phone_number_verified(&self) -> Option<bool> {
        self.phone_number_verified
    }
    fn last_login_method(&self) -> Option<&str> {
        self.last_login_method.as_deref()
    }
    fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }
}

impl AuthSession for SessionView {
    fn retained_session_view(&self) -> Option<&SessionView> {
        Some(self)
    }
    fn additional_fields(&self) -> serde_json::Map<String, serde_json::Value> {
        self.extension_fields.clone().into_iter().collect()
    }
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn token(&self) -> &str {
        &self.token
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }
    fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn impersonated_by(&self) -> Option<&str> {
        self.impersonated_by.as_deref()
    }
    fn active_organization_id(&self) -> Option<&str> {
        self.active_organization_id.as_deref()
    }
    fn active_team_id(&self) -> Option<&str> {
        self.active_team_id.as_deref()
    }
    fn active(&self) -> bool {
        self.active
    }
}

impl AuthAccount for AccountView {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }
    fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
    fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_token_expires_at
    }
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }
    fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthVerification for VerificationView {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn identifier(&self) -> &str {
        &self.identifier
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Public organization response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationView {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(
        serialize_with = "serialize_json_option_as_string",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
}

impl<T: AuthOrganization> From<&T> for OrganizationView {
    fn from(org: &T) -> Self {
        Self {
            id: org.id().into_owned(),
            name: org.name().to_owned(),
            slug: org.slug().to_owned(),
            logo: org.logo().map(str::to_owned),
            metadata: org.metadata().cloned(),
            created_at: org.created_at(),
            updated_at: org.updated_at(),
        }
    }
}

/// Public invitation response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationView {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub status: InvitationStatus,
    #[serde(rename = "inviterId")]
    pub inviter_id: String,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "teamId", default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    pub extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<T: AuthInvitation> From<&T> for InvitationView {
    fn from(inv: &T) -> Self {
        Self {
            id: inv.id().into_owned(),
            organization_id: inv.organization_id().into_owned(),
            email: inv.email().to_owned(),
            role: inv.role().to_owned(),
            status: inv.status().clone(),
            inviter_id: inv.inviter_id().into_owned(),
            expires_at: inv.expires_at(),
            created_at: inv.created_at(),
            team_id: inv.team_id().map(str::to_owned),
            extension_fields: std::collections::BTreeMap::default(),
        }
    }
}

/// Public passkey response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyView {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
}

impl<T: AuthPasskey> From<&T> for PasskeyView {
    fn from(pk: &T) -> Self {
        Self {
            id: pk.id().into_owned(),
            name: pk.name().map(str::to_owned),
            credential_id: pk.credential_id().to_owned(),
            user_id: pk.user_id().into_owned(),
            public_key: pk.public_key().to_owned(),
            counter: pk.counter(),
            device_type: pk.device_type().to_owned(),
            backed_up: pk.backed_up(),
            transports: pk.transports().map(str::to_owned),
            created_at: pk
                .created_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            aaguid: pk.aaguid().map(str::to_owned),
        }
    }
}

/// Public API key response shape.
///
/// Intentionally omits `key_hash` — the hashed key value is never returned
/// over the wire (matches upstream TS behavior).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyView {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "configId")]
    pub config_id: String,
    #[serde(rename = "refillInterval")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub refill_interval: Option<f64>,
    #[serde(rename = "refillAmount")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub refill_amount: Option<f64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub rate_limit_time_window: Option<f64>,
    #[serde(rename = "rateLimitMax")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub rate_limit_max: Option<f64>,
    #[serde(rename = "requestCount")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub request_count: Option<f64>,
    #[serde(serialize_with = "serialize_api_key_number")]
    pub remaining: Option<f64>,
    #[serde(rename = "lastRequest")]
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub permissions: Option<serde_json::Value>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
}

impl<T: AuthApiKey> From<&T> for ApiKeyView {
    fn from(ak: &T) -> Self {
        Self {
            id: ak.id().into_owned(),
            name: ak.name().map(str::to_owned),
            start: ak.start().map(str::to_owned),
            prefix: ak.prefix().map(str::to_owned),
            reference_id: ak.reference_id().into_owned(),
            config_id: ak.config_id().into_owned(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at().map(api_key_wire_date),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request().map(api_key_wire_date),
            expires_at: ak.expires_at().map(api_key_wire_date),
            created_at: api_key_wire_date(ak.created_at()),
            updated_at: api_key_wire_date(ak.updated_at()),
            permissions: ak
                .permissions()
                .and_then(|s| crate::utils::json::from_slice(s.as_bytes()).ok())
                .map(|mut value| {
                    normalize_api_key_permission_dates(&mut value);
                    value
                }),
            metadata: ak.metadata().and_then(|s| {
                let value = crate::utils::json::parse_value(s).ok()?;
                if let crate::utils::json::JsValue::String(encoded) = value {
                    let mut value = crate::utils::json::parse_value(&encoded)
                        .ok()?
                        .to_json_value()
                        .ok()?;
                    normalize_api_key_permission_dates(&mut value);
                    Some(value)
                } else {
                    value.to_json_value().ok()
                }
            }),
        }
    }
}

fn normalize_api_key_permission_dates(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(date) = crate::utils::datetime::normalize_json_date(text) {
                *text = date;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_api_key_permission_dates(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                normalize_api_key_permission_dates(value);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Plugin entity views
// ---------------------------------------------------------------------------

#[expect(
    clippy::ref_option,
    reason = "Serde field serializers receive a reference to the declared Option field type"
)]
fn serialize_json_option_as_string<S>(
    value: &Option<serde_json::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(inner) => serializer
            .serialize_some(&serde_json::to_string(inner).map_err(serde::ser::Error::custom)?),
        None => serializer.serialize_none(),
    }
}

// JSON.stringify emits safe integral JavaScript numbers without a decimal suffix.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
#[expect(
    clippy::ref_option,
    reason = "Serde field serializers receive a reference to the declared Option field type"
)]
fn serialize_api_key_number<S: Serializer>(
    value: &Option<f64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) if value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0 => {
            serializer.serialize_i64(*value as i64)
        }
        value => value.serialize(serializer),
    }
}

// The source adapter exposes dates to JSON through Date.toJSON(). Keep native
// accessor/storage precision intact while projecting valid RFC3339 wire dates.
fn api_key_wire_date(value: &str) -> String {
    DateTime::parse_from_rfc3339(value).map_or_else(
        |_| value.to_owned(),
        |date| {
            date.with_timezone(&Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        },
    )
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_view_serializes_camel_case() {
        let user = UserView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "user-1".to_owned(),
            name: Some("Ada".to_owned()),
            email: Some("ada@example.com".to_owned()),
            email_verified: true,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: Some("ada".to_owned()),
            display_username: Some("Ada".to_owned()),
            two_factor_enabled: Some(true),
            role: Some("admin".to_owned()),
            banned: Some(false),
            ban_reason: None,
            ban_expires: None,
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            last_login_method: None,
            extension_fields: std::collections::BTreeMap::default(),
            metadata: serde_json::json!({}),
        };

        let json = serde_json::to_value(UserView::from(&user)).expect("serialize user view");
        assert_eq!(
            (*(json)
                .get("emailVerified")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert_eq!(
            (*(json)
                .get("displayUsername")
                .unwrap_or(&serde_json::Value::Null)),
            "Ada"
        );
        assert_eq!(
            (*(json)
                .get("twoFactorEnabled")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
    }

    #[test]
    fn session_view_serializes_camel_case() {
        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "session-1".to_owned(),
            expires_at: Utc::now(),
            token: "token".to_owned(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: Some("agent".to_owned()),
            user_id: "user-1".to_owned(),
            impersonated_by: Some("admin-1".to_owned()),
            active_organization_id: Some("org-1".to_owned()),
            active_team_id: None,
            active: true,
            extension_fields: std::collections::BTreeMap::default(),
        };

        let json =
            serde_json::to_value(SessionView::from(&session)).expect("serialize session view");
        assert!((*(json).get("expiresAt").unwrap_or(&serde_json::Value::Null)).is_string());
        assert_eq!(
            (*(json).get("ipAddress").unwrap_or(&serde_json::Value::Null)),
            "127.0.0.1"
        );
        assert_eq!(
            (*(json)
                .get("activeOrganizationId")
                .unwrap_or(&serde_json::Value::Null)),
            "org-1"
        );
    }

    #[test]
    fn account_view_omits_password_on_serialize() {
        let account = AccountView {
            id: "acc-1".to_owned(),
            account_id: "account-id".to_owned(),
            provider_id: "credential".to_owned(),
            user_id: "user-1".to_owned(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("$2a$hash".to_owned()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_value(&account).expect("serialize account view");
        assert!(
            json.get("password").is_none(),
            "password field must not appear in serialized output"
        );
    }
}
// LCOV_EXCL_STOP
