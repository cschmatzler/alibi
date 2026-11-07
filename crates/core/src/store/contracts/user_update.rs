//! Canonical UPDATE input. Values have one owner; policies carry no pre-hook values.
use crate::field_policy::{FieldConfigs, FieldValues};
use crate::utils::json::{JsObject, JsValue};
use crate::{AuthResult, UpdateUser};
use indexmap::IndexMap;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct UserUpdateFieldMetadata {
    pub(crate) adapter_fields: Option<Arc<FieldConfigs>>,
    pub(crate) binding_names: IndexMap<String, String>,
    pub(crate) declared_fields: std::collections::BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PreparedUserUpdate {
    pub data: JsObject,
    pub metadata: UserUpdateFieldMetadata,
}

impl PreparedUserUpdate {
    #[must_use]
    pub fn from_typed(input: &UpdateUser) -> Self {
        Self {
            data: reify_user_update(input),
            metadata: input.additional_fields.update_metadata(),
        }
    }

    /// Resolve the source schema before physical binding. Without initialized
    /// policies a native model supplies its own declared column schema.
    #[must_use]
    pub fn declares(&self, name: &str) -> bool {
        is_core_field(name)
            || self.metadata.declared_fields.contains(name)
            || self
                .metadata
                .adapter_fields
                .as_ref()
                .is_none_or(|fields| fields.contains_key(name))
    }

    pub(crate) fn include_installed_fields<S: crate::AuthSchema>(
        &mut self,
        context: &crate::AuthContext<S>,
    ) {
        for plugin in alibi_schema_registry::plugin_schemas() {
            let flag = if plugin.name == "two-factor" {
                "two_factor.enabled".to_owned()
            } else {
                format!("{}.enabled", plugin.name)
            };
            if context.feature_enabled(&flag) {
                self.metadata.declared_fields.extend(
                    plugin
                        .user_fields
                        .iter()
                        .map(|field| field.column_name.unwrap_or(field.name).to_owned()),
                );
            }
        }
    }

    #[must_use]
    pub fn requires_binding(&self, name: &str) -> bool {
        self.metadata.adapter_fields.is_some() && self.declares(name) || is_core_field(name)
    }

    #[must_use]
    pub fn physical_binding(&self, name: &str) -> Option<&str> {
        self.metadata.binding_names.get(name).map(String::as_str)
    }

    /// Runs once, after both application and physical before hooks.
    pub async fn apply_adapter_transforms(&mut self) -> AuthResult<()> {
        let mut data = std::mem::take(&mut self.data);
        data.retain(|key, _| key.as_str().is_some_and(|key| self.declares(key)));
        let mut fields = FieldValues::from_user_update(data, self.metadata.clone())?;
        fields.apply_adapter_transforms_async().await?;
        self.data = fields.update_own_properties();
        // The source ID input transform omits falsy values, including null/NaN.
        self.data
            .retain(|key, value| key != "id" || value.is_truthy());
        Ok(())
    }
}

fn is_core_field(name: &str) -> bool {
    alibi_schema_registry::core_fields(alibi_schema_registry::EntityRole::User)
        .iter()
        .any(|field| field.column_name.unwrap_or(field.name) == name)
}

pub(crate) fn reify_user_update(input: &UpdateUser) -> JsObject {
    let mut data = input.additional_fields.update_own_properties();
    macro_rules! text {
        ($($field:ident => $name:literal),* $(,)?) => { $(
            if let Some(value) = &input.$field {
                _ = data.insert($name.into(), JsValue::String(value.clone().into()));
            }
        )* };
    }
    text! {
        email => "email", name => "name", image => "image",
        username => "username", display_username => "displayUsername",
        role => "role", ban_reason => "banReason",
    }
    macro_rules! boolean {
        ($($field:ident => $name:literal),* $(,)?) => { $(
            if let Some(value) = input.$field {
                _ = data.insert($name.into(), JsValue::Bool(value));
            }
        )* };
    }
    boolean! {
        email_verified => "emailVerified", banned => "banned",
        two_factor_enabled => "twoFactorEnabled", is_anonymous => "isAnonymous",
        phone_number_verified => "phoneNumberVerified",
    }
    if input.clear_ban_reason {
        _ = data.insert("banReason".into(), JsValue::Null);
    }
    if let Some(value) = input.ban_expires {
        _ = data.insert(
            "banExpires".into(),
            value.map_or(JsValue::Null, JsValue::Date),
        );
    }
    for (name, value) in [
        ("phoneNumber", &input.phone_number),
        ("lastLoginMethod", &input.last_login_method),
    ] {
        if let Some(value) = value {
            _ = data.insert(
                name.into(),
                value
                    .as_ref()
                    .map_or(JsValue::Null, |value| JsValue::String(value.clone().into())),
            );
        }
    }
    if let Some(value) = &input.metadata {
        _ = data.insert("metadata".into(), JsValue::from(value.clone()));
    }
    for (name, value) in [
        ("name", &input.provider_name),
        ("email", &input.provider_email),
        ("image", &input.provider_image),
        ("emailVerified", &input.provider_email_verified),
    ] {
        if let Some(value) = value {
            _ = data.insert(name.into(), value.clone());
        }
    }
    data.extend(
        input
            .adapter_native_fields
            .iter()
            .map(|(name, value)| (name.clone().into(), value.clone())),
    );
    data
}
