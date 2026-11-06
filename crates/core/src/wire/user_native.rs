use super::UserView;
use crate::{AuthResult, UpdateUser};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeMap;

const NATIVE_FIELDS: &[&str] = &[
    "name",
    "email",
    "image",
    "emailVerified",
    "createdAt",
    "updatedAt",
    "username",
    "displayUsername",
    "twoFactorEnabled",
    "role",
    "banned",
    "banReason",
    "banExpires",
    "isAnonymous",
    "phoneNumber",
    "phoneNumberVerified",
    "lastLoginMethod",
];

fn typed_date(value: &Value) -> Option<DateTime<Utc>> {
    let milliseconds = match value {
        Value::String(text) => crate::utils::datetime::parse_date_millis(text),
        Value::Number(number) => number
            .as_f64()
            .filter(|value| value.abs() <= 8_640_000_000_000_000.0)
            .map(|value| value.trunc() as i64),
        Value::Bool(value) => Some(i64::from(*value)),
        _ => None,
    };
    milliseconds.and_then(DateTime::<Utc>::from_timestamp_millis)
}

impl UserView {
    pub(super) fn secondary_native_snapshot(
        &self,
        native: &crate::AdapterOutput,
    ) -> AuthResult<Value> {
        let Value::Object(mut snapshot) = serde_json::to_value(self)? else {
            return Err(crate::AuthError::internal(
                "Invalid secondary user snapshot",
            ));
        };
        for name in NATIVE_FIELDS {
            if native.field_is_undefined(name) {
                _ = snapshot.remove(*name);
            } else if let Some(value) = native.values().get(*name) {
                _ = snapshot.insert((*name).to_owned(), value.clone());
            }
        }
        Ok(Value::Object(snapshot))
    }

    pub(super) fn from_secondary_native_snapshot(snapshot: Value) -> AuthResult<Self> {
        let Value::Object(source) = snapshot else {
            return Err(crate::AuthError::internal(
                "Invalid secondary user snapshot",
            ));
        };
        let Some(Value::String(id)) = source.get("id") else {
            return Err(crate::AuthError::internal(
                "Invalid secondary user identity",
            ));
        };
        let mut user = Self {
            id: id.clone(),
            name: None,
            email: None,
            image: None,
            email_verified: false,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
            username: None,
            display_username: None,
            two_factor_enabled: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            last_login_method: None,
            metadata: Value::Null,
            extension_fields: BTreeMap::new(),
            omitted_fields: Default::default(),
        };
        user.retain_native_user_fields(
            source
                .iter()
                .filter(|(name, _)| NATIVE_FIELDS.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        );
        for name in NATIVE_FIELDS {
            if !source.contains_key(*name) {
                _ = user.omitted_fields.insert((*name).to_owned());
            }
        }
        Ok(user)
    }

    pub(crate) fn native_user_fields(&self) -> BTreeMap<String, Value> {
        self.extension_fields
            .iter()
            .filter(|(name, _)| NATIVE_FIELDS.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    pub(crate) fn retain_native_user_fields(&mut self, native: BTreeMap<String, Value>) {
        for (name, value) in native {
            let boolean = || crate::utils::json::JsValue::from(value.clone()).is_truthy();
            let optional_boolean = || (!value.is_null()).then(boolean);
            let text = || value.as_str().map(str::to_owned);
            match name.as_str() {
                "name" => self.name = text(),
                "email" => self.email = text(),
                "image" => self.image = text(),
                "emailVerified" => self.email_verified = boolean(),
                "createdAt" => {
                    self.created_at = typed_date(&value).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
                }
                "updatedAt" => {
                    self.updated_at = typed_date(&value).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
                }
                "username" => self.username = text(),
                "displayUsername" => self.display_username = text(),
                "twoFactorEnabled" => self.two_factor_enabled = optional_boolean(),
                "role" => self.role = text(),
                "banned" => self.banned = optional_boolean(),
                "banReason" => self.ban_reason = text(),
                "banExpires" => {
                    self.ban_expires = if value.is_null() {
                        None
                    } else {
                        Some(typed_date(&value).unwrap_or(DateTime::<Utc>::UNIX_EPOCH))
                    }
                }
                "isAnonymous" => self.is_anonymous = optional_boolean(),
                "phoneNumber" => self.phone_number = text(),
                "phoneNumberVerified" => self.phone_number_verified = optional_boolean(),
                "lastLoginMethod" => self.last_login_method = text(),
                _ => continue,
            }
            _ = self.omitted_fields.remove(&name);
            _ = self.extension_fields.insert(name, value);
        }
    }

    pub(crate) fn clear_native_user_update(&mut self, update: &UpdateUser) -> AuthResult<()> {
        if update
            .adapter_native_fields
            .keys()
            .any(|name| name != "banExpires")
        {
            return Err(crate::AuthError::internal(
                "Unsupported native user update field",
            ));
        }
        for (name, present) in [
            (
                "name",
                update.name.is_some() || update.provider_name.is_some(),
            ),
            ("email", update.email.is_some()),
            (
                "image",
                update.image.is_some() || update.provider_image.is_some(),
            ),
            (
                "emailVerified",
                update.email_verified.is_some() || update.provider_email_verified.is_some(),
            ),
            ("username", update.username.is_some()),
            ("displayUsername", update.display_username.is_some()),
            ("role", update.role.is_some()),
            ("banned", update.banned.is_some()),
            (
                "banReason",
                update.clear_ban_reason || update.ban_reason.is_some(),
            ),
            ("banExpires", update.ban_expires.is_some()),
            ("twoFactorEnabled", update.two_factor_enabled.is_some()),
            ("isAnonymous", update.is_anonymous.is_some()),
            ("phoneNumber", update.phone_number.is_some()),
            (
                "phoneNumberVerified",
                update.phone_number_verified.is_some(),
            ),
            ("lastLoginMethod", update.last_login_method.is_some()),
            ("updatedAt", true),
        ] {
            if present {
                _ = self.extension_fields.remove(name);
                _ = self.omitted_fields.remove(name);
            }
        }
        Ok(())
    }
}
