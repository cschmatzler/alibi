use crate::AuthUser;
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
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(rename = "displayUsername", default)]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled", default)]
    pub two_factor_enabled: Option<bool>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub banned: Option<bool>,
    #[serde(rename = "banReason", default)]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires", default)]
    pub ban_expires: Option<DateTime<Utc>>,
    #[serde(rename = "isAnonymous", default)]
    pub is_anonymous: Option<bool>,
    #[serde(rename = "phoneNumber", default)]
    pub phone_number: Option<String>,
    #[serde(rename = "phoneNumberVerified", default)]
    pub phone_number_verified: Option<bool>,
    #[serde(rename = "lastLoginMethod", default)]
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
                    if let Some(value) = self.extension_fields.get($name) {
                        map.serialize_entry($name, value)?;
                    } else {
                        map.serialize_entry($name, $value)?;
                    }
                }
            };
        }
        entry!("id", &self.id);
        entry!("name", &self.name);
        entry!("email", &self.email);
        entry!("emailVerified", &self.email_verified);
        entry!("image", &self.image);
        entry!(
            "createdAt",
            &crate::utils::datetime::json_date_millis(self.created_at.timestamp_millis())
        );
        entry!(
            "updatedAt",
            &crate::utils::datetime::json_date_millis(self.updated_at.timestamp_millis())
        );
        if self.username.is_some() || self.extension_fields.contains_key("username") {
            entry!("username", &self.username);
        }
        if self.display_username.is_some() || self.extension_fields.contains_key("displayUsername")
        {
            entry!("displayUsername", &self.display_username);
        }
        if self.two_factor_enabled.is_some()
            || self.extension_fields.contains_key("twoFactorEnabled")
        {
            entry!("twoFactorEnabled", &self.two_factor_enabled);
        }
        if self.role.is_some() || self.extension_fields.contains_key("role") {
            entry!("role", &self.role);
        }
        if self.banned.is_some() || self.extension_fields.contains_key("banned") {
            entry!("banned", &self.banned);
        }
        if self.ban_reason.is_some() || self.extension_fields.contains_key("banReason") {
            entry!("banReason", &self.ban_reason);
        }
        if self.ban_expires.is_some() || self.extension_fields.contains_key("banExpires") {
            entry!(
                "banExpires",
                &self
                    .ban_expires
                    .map(|value| crate::utils::datetime::json_date_millis(
                        value.timestamp_millis()
                    ))
            );
        }
        if self.is_anonymous.is_some() || self.extension_fields.contains_key("isAnonymous") {
            entry!("isAnonymous", &self.is_anonymous);
        }
        if self.phone_number.is_some() || self.extension_fields.contains_key("phoneNumber") {
            entry!("phoneNumber", &self.phone_number);
        }
        if self.phone_number_verified.is_some()
            || self.extension_fields.contains_key("phoneNumberVerified")
        {
            entry!("phoneNumberVerified", &self.phone_number_verified);
        }
        if self.last_login_method.is_some() || self.extension_fields.contains_key("lastLoginMethod")
        {
            entry!("lastLoginMethod", &self.last_login_method);
        }
        for (name, value) in &self.extension_fields {
            if !matches!(
                name.as_str(),
                "emailVerified"
                    | "banned"
                    | "twoFactorEnabled"
                    | "isAnonymous"
                    | "phoneNumberVerified"
                    | "createdAt"
                    | "updatedAt"
                    | "banExpires"
                    | "name"
                    | "email"
                    | "image"
                    | "username"
                    | "displayUsername"
                    | "role"
                    | "banReason"
                    | "phoneNumber"
                    | "lastLoginMethod"
            ) && !self.omitted_fields.contains(name)
            {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
    }
}

#[derive(Deserialize)]
pub(in crate::wire) struct UserViewInput {
    pub(in crate::wire) id: String,
    pub(in crate::wire) name: Option<String>,
    pub(in crate::wire) email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub(in crate::wire) email_verified: serde_json::Value,
    pub(in crate::wire) image: Option<String>,
    #[serde(rename = "createdAt")]
    pub(in crate::wire) created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub(in crate::wire) updated_at: DateTime<Utc>,
    #[serde(default)]
    pub(in crate::wire) username: Option<String>,
    #[serde(rename = "displayUsername", default)]
    pub(in crate::wire) display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled", default)]
    pub(in crate::wire) two_factor_enabled: Option<bool>,
    #[serde(default)]
    pub(in crate::wire) role: Option<String>,
    #[serde(default)]
    pub(in crate::wire) banned: Option<bool>,
    #[serde(rename = "banReason", default)]
    pub(in crate::wire) ban_reason: Option<String>,
    #[serde(rename = "banExpires", default)]
    pub(in crate::wire) ban_expires: Option<DateTime<Utc>>,
    #[serde(rename = "isAnonymous", default)]
    pub(in crate::wire) is_anonymous: Option<bool>,
    #[serde(rename = "phoneNumber", default)]
    pub(in crate::wire) phone_number: Option<String>,
    #[serde(rename = "phoneNumberVerified", default)]
    pub(in crate::wire) phone_number_verified: Option<bool>,
    #[serde(rename = "lastLoginMethod", default)]
    pub(in crate::wire) last_login_method: Option<String>,
    /// Nullable fields contributed by an enabled plugin's output schema.
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    pub(in crate::wire) extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    pub(in crate::wire) metadata: serde_json::Value,
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
            _ = input
                .extension_fields
                .insert("emailVerified".into(), input.email_verified);
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

impl<T: AuthUser> From<&T> for UserView {
    fn from(user: &T) -> Self {
        if let Some(view) = user.retained_user_view() {
            return view.clone();
        }
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
        for field in [
            "emailVerified",
            "banned",
            "twoFactorEnabled",
            "isAnonymous",
            "phoneNumberVerified",
            "createdAt",
            "updatedAt",
            "banExpires",
            "name",
            "email",
            "image",
            "username",
            "displayUsername",
            "role",
            "banReason",
            "phoneNumber",
            "lastLoginMethod",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain(user.additional_fields().into_iter().map(|(name, _)| name))
        {
            if let Some(output) = user.adapter_snapshot() {
                if output.field_is_undefined(&field) {
                    _ = view.omitted_fields.insert(field.into());
                } else if let Some(value) = output.values().get(&field) {
                    _ = view.extension_fields.insert(field.into(), value.clone());
                }
            }
        }
        view
    }
}

impl AuthUser for UserView {
    fn secondary_snapshot(&self) -> crate::AuthResult<serde_json::Value> {
        serde_json::to_value(self).map_err(Into::into)
    }

    fn secondary_snapshot_with_native_output(
        &self,
        native: &crate::AdapterOutput,
    ) -> crate::AuthResult<serde_json::Value> {
        self.secondary_native_snapshot(native)
    }

    fn from_secondary_snapshot(snapshot: serde_json::Value) -> crate::AuthResult<Self> {
        Self::from_secondary_native_snapshot(snapshot)
    }

    fn from_secondary_snapshot_record(
        snapshot: serde_json::Value,
    ) -> crate::AuthResult<crate::AdapterRecord<Self>> {
        Self::secondary_native_record(snapshot, &Default::default())
    }

    fn from_secondary_snapshot_record_with_fields(
        snapshot: serde_json::Value,
        allowed: &crate::field_policy::FieldConfigs,
    ) -> crate::AuthResult<crate::AdapterRecord<Self>> {
        Self::secondary_native_record(snapshot, allowed)
    }

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
