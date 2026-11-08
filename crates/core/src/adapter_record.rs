//! Retained adapter output alongside immutable, typed storage authority.

use crate::{AuthAccount, AuthResult, AuthSession, AuthUser, field_policy::FieldOutput};
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use std::borrow::Cow;

/// Trusted adapter output retains all own JavaScript properties in one map.
#[derive(Clone, Debug, Default)]
pub struct AdapterOutput {
    values: crate::utils::json::JsObject,
}

impl Serialize for AdapterOutput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::utils::json::JsValue::Object(self.values.clone()).serialize(serializer)
    }
}

impl AdapterOutput {
    pub fn from_values(values: FieldOutput) -> Self {
        Self::from_js_values(
            values
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        )
    }

    pub const fn from_js_values(values: crate::utils::json::JsObject) -> Self {
        Self { values }
    }

    /// None denotes an own undefined property, not absence.
    pub fn insert(&mut self, name: String, value: Option<crate::utils::json::JsValue>) {
        self.insert_js(
            name.into(),
            value.unwrap_or(crate::utils::json::JsValue::Undefined),
        );
    }

    pub fn insert_js(
        &mut self,
        name: crate::utils::json::JsString,
        value: crate::utils::json::JsValue,
    ) {
        _ = self.values.insert(name, value);
    }

    pub(crate) fn extend(&mut self, output: Self) {
        self.values.extend(output.values);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[must_use]
    pub fn contains_field(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    #[must_use]
    pub fn field_is_undefined(&self, name: &str) -> bool {
        self.values
            .get(name)
            .is_some_and(crate::utils::json::JsValue::is_undefined)
    }

    #[must_use]
    pub const fn values(&self) -> &crate::utils::json::JsObject {
        &self.values
    }

    /// Explicit ordinary-JSON projection omits undefined and rejects ill-formed UTF-16.
    pub fn to_field_output(&self) -> AuthResult<FieldOutput> {
        let serde_json::Value::Object(fields) =
            crate::utils::json::JsValue::Object(self.values.clone()).to_json_value()?
        else {
            unreachable!("an object projection remains an object");
        };
        Ok(fields)
    }

    pub(crate) fn filter_returned(&self, fields: &crate::field_policy::FieldConfigs) -> Self {
        let mut output = self.clone();
        for (name, field) in fields {
            if !field.returned {
                _ = output.values.shift_remove(name);
            }
        }
        output
    }
}

/// One actual adapter result. Output transforms may change additional values or
/// omit them, while identity, ownership and credential accessors retain the
/// physical model. Public response filtering is a separate operation.
#[derive(Clone, Debug)]
pub struct AdapterRecord<M> {
    stored: M,
    output: AdapterOutput,
}

impl<M: Serialize> AdapterRecord<M> {
    /// Retain the model's honest serialized snapshot without applying policies.
    /// Initialized stores replace this with their declared adapter output.
    ///
    /// # Errors
    /// Returns an error if the model cannot serialize to an object.
    pub fn physical(stored: M) -> AuthResult<Self> {
        let crate::utils::json::JsValue::Object(output) = crate::utils::json::to_js_value(&stored)?
        else {
            return Err(crate::AuthError::internal(
                "An adapter model must serialize to an object",
            ));
        };
        Ok(Self {
            stored,
            output: AdapterOutput::from_js_values(output),
        })
    }

    /// Keep trusted native scalar output alongside the typed storage model.
    pub fn with_native_output(stored: M, native: AdapterOutput) -> AuthResult<Self> {
        let mut record = Self::physical(stored)?;
        record.output.extend(native);
        Ok(record)
    }
}

impl<M> AdapterRecord<M> {
    /// Retain complete adapter output without adding serialized storage fields.
    /// Generated cache codecs use this after restoring their typed authority.
    pub fn with_output(stored: M, output: AdapterOutput) -> Self {
        Self { stored, output }
    }

    pub(crate) fn retain_native_scalars(
        &mut self,
        values: std::collections::BTreeMap<String, crate::utils::json::JsValue>,
    ) {
        for (field, value) in values {
            self.output.insert(field, Some(value.into()));
        }
    }

    pub(crate) fn retain_native_output(&mut self, output: AdapterOutput) {
        self.output.extend(output);
    }

    #[must_use]
    pub const fn stored(&self) -> &M {
        &self.stored
    }

    #[must_use]
    pub fn into_stored(self) -> M {
        self.stored
    }

    /// Trusted adapter output, including declared `returned: false` fields.
    /// This snapshot is immutable and must not be used as storage authority.
    #[must_use]
    pub const fn raw_snapshot(&self) -> &AdapterOutput {
        &self.output
    }
}

impl<M> Serialize for AdapterRecord<M> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.output.serialize(serializer)
    }
}

macro_rules! delegate {
    ($name:ident, $output:ty) => {
        fn $name(&self) -> $output {
            self.stored.$name()
        }
    };
}

impl<M: AuthUser> AuthUser for AdapterRecord<M> {
    fn secondary_snapshot(&self) -> AuthResult<crate::utils::json::JsValue> {
        self.stored
            .secondary_snapshot_with_native_output(&self.output)
    }
    fn secondary_snapshot_with_native_output(
        &self,
        native: &AdapterOutput,
    ) -> AuthResult<crate::utils::json::JsValue> {
        let mut retained = self.output.clone();
        retained.extend(native.clone());
        self.stored.secondary_snapshot_with_native_output(&retained)
    }
    fn adapter_snapshot(&self) -> Option<&AdapterOutput> {
        Some(&self.output)
    }
    delegate!(
        additional_js_fields,
        AuthResult<crate::utils::json::JsObject>
    );
    fn adapter_js_fields(
        &self,
        exact: &std::collections::BTreeSet<String>,
    ) -> AuthResult<crate::utils::json::JsObject> {
        self.stored.adapter_js_fields(exact)
    }
    delegate!(id, Cow<'_, str>);
    delegate!(email, Option<&str>);
    delegate!(name, Option<&str>);
    delegate!(email_verified, bool);
    delegate!(image, Option<&str>);
    delegate!(created_at, DateTime<Utc>);
    delegate!(updated_at, DateTime<Utc>);
    delegate!(username, Option<&str>);
    delegate!(display_username, Option<&str>);
    delegate!(two_factor_enabled, bool);
    delegate!(two_factor_enabled_value, Option<bool>);
    delegate!(role, Option<&str>);
    delegate!(banned, bool);
    delegate!(banned_value, Option<bool>);
    delegate!(ban_reason, Option<&str>);
    delegate!(ban_expires, Option<DateTime<Utc>>);
    delegate!(metadata, crate::utils::json::JsValue);
    delegate!(is_anonymous, Option<bool>);
    delegate!(phone_number, Option<&str>);
    delegate!(phone_number_verified, Option<bool>);
    delegate!(last_login_method, Option<&str>);
}

impl<M: AuthSession> AuthSession for AdapterRecord<M> {
    fn adapter_snapshot(&self) -> Option<&AdapterOutput> {
        Some(&self.output)
    }
    delegate!(
        additional_js_fields,
        AuthResult<crate::utils::json::JsObject>
    );
    fn adapter_js_fields(
        &self,
        exact: &std::collections::BTreeSet<String>,
    ) -> AuthResult<crate::utils::json::JsObject> {
        self.stored.adapter_js_fields(exact)
    }
    delegate!(id, Cow<'_, str>);
    delegate!(expires_at, DateTime<Utc>);
    delegate!(token, &str);
    delegate!(created_at, DateTime<Utc>);
    delegate!(updated_at, DateTime<Utc>);
    delegate!(ip_address, Option<&str>);
    delegate!(user_agent, Option<&str>);
    delegate!(user_id, Cow<'_, str>);
    delegate!(impersonated_by, Option<&str>);
    delegate!(active_organization_id, Option<&str>);
    delegate!(active_team_id, Option<&str>);
}

impl<M: AuthAccount> AuthAccount for AdapterRecord<M> {
    fn adapter_snapshot(&self) -> Option<&AdapterOutput> {
        Some(&self.output)
    }
    delegate!(
        additional_js_fields,
        AuthResult<crate::utils::json::JsObject>
    );
    fn adapter_js_fields(
        &self,
        exact: &std::collections::BTreeSet<String>,
    ) -> AuthResult<crate::utils::json::JsObject> {
        self.stored.adapter_js_fields(exact)
    }
    delegate!(id, Cow<'_, str>);
    delegate!(account_id, crate::utils::json::JsString);
    delegate!(provider_id, &str);
    delegate!(user_id, Cow<'_, str>);
    delegate!(access_token, Option<&str>);
    delegate!(refresh_token, Option<&str>);
    delegate!(id_token, Option<&str>);
    delegate!(access_token_expires_at, Option<DateTime<Utc>>);
    delegate!(refresh_token_expires_at, Option<DateTime<Utc>>);
    delegate!(scope, Option<&str>);
    delegate!(password, Option<&str>);
    delegate!(created_at, DateTime<Utc>);
    delegate!(updated_at, DateTime<Utc>);
}
