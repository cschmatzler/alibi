use crate::AuthUser;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
/// Public user response shape.
#[derive(Debug, Clone, PartialEq)]
pub struct UserView {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub last_login_method: Option<String>,
    /// Nullable fields contributed by an enabled plugin's output schema.
    pub extension_fields: crate::utils::json::JsObject,
    pub metadata: crate::utils::json::JsValue,
    /// Fields absent from an authenticated cache projection.
    pub omitted_fields: std::collections::BTreeSet<String>,
}

impl<'de> Deserialize<'de> for UserView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_secondary_native_snapshot(crate::utils::json::JsValue::deserialize(
            deserializer,
        )?)
        .map_err(serde::de::Error::custom)
    }
}

impl Serialize for UserView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = crate::utils::json::JsObject::new();
        macro_rules! entry {
            ($name:literal, $value:expr) => {
                if !self.omitted_fields.contains($name) {
                    if let Some(value) = self.extension_fields.get($name) {
                        _ = map.insert($name.into(), value.clone());
                    } else {
                        _ = map.insert(
                            $name.into(),
                            crate::utils::json::to_js_value($value)
                                .map_err(serde::ser::Error::custom)?,
                        );
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
            if !name.as_str().is_some_and(|name| {
                matches!(
                    name,
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
                )
            }) && !name
                .as_str()
                .is_some_and(|name| self.omitted_fields.contains(name))
            {
                _ = map.insert(name.clone(), value.clone());
            }
        }
        crate::utils::json::JsValue::Object(map).serialize(serializer)
    }
}

impl<T: AuthUser> From<&T> for UserView {
    fn from(user: &T) -> Self {
        Self::from_user(user, true)
    }
}

impl UserView {
    pub(crate) fn without_private_metadata(user: &impl AuthUser) -> Self {
        Self::from_user(user, false)
    }

    fn from_user(user: &impl AuthUser, include_metadata: bool) -> Self {
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
            extension_fields: Default::default(),
            metadata: if include_metadata {
                user.metadata()
            } else {
                crate::utils::json::JsValue::Undefined
            },
            omitted_fields: std::collections::BTreeSet::default(),
        };
        if let Some(output) = user.adapter_snapshot() {
            for (name, value) in output.values() {
                if name != "id" {
                    _ = view.extension_fields.insert(name.clone(), value.clone());
                }
            }
        }
        view
    }
}

impl AuthUser for UserView {
    fn secondary_snapshot(&self) -> crate::AuthResult<crate::utils::json::JsValue> {
        crate::utils::json::to_js_value(self).map_err(Into::into)
    }

    fn secondary_snapshot_with_native_output(
        &self,
        native: &crate::AdapterOutput,
    ) -> crate::AuthResult<crate::utils::json::JsValue> {
        self.secondary_native_snapshot(native)
    }

    fn from_secondary_snapshot(snapshot: crate::utils::json::JsValue) -> crate::AuthResult<Self> {
        Self::from_secondary_native_snapshot(snapshot)
    }

    fn from_secondary_snapshot_record(
        snapshot: crate::utils::json::JsValue,
    ) -> crate::AuthResult<crate::AdapterRecord<Self>> {
        Self::secondary_native_record(snapshot, &Default::default())
    }

    fn from_secondary_snapshot_record_with_fields(
        snapshot: crate::utils::json::JsValue,
        allowed: &crate::field_policy::FieldConfigs,
    ) -> crate::AuthResult<crate::AdapterRecord<Self>> {
        Self::secondary_native_record(snapshot, allowed)
    }

    fn retained_user_view(&self) -> Option<&UserView> {
        Some(self)
    }
    fn additional_js_fields(&self) -> crate::AuthResult<crate::utils::json::JsObject> {
        Ok(self.extension_fields.clone())
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
    fn metadata(&self) -> crate::utils::json::JsValue {
        self.metadata.clone()
    }
}
