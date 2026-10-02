//! Retained adapter output alongside immutable, typed storage authority.

use crate::{AuthAccount, AuthResult, AuthSession, AuthUser, field_policy::FieldOutput};
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use std::borrow::Cow;

/// Declared adapter values retain JavaScript undefined presence for trusted
/// observers. Serialization omits undefined values, as public JSON does.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
pub struct AdapterOutput {
    values: FieldOutput,
    #[serde(skip)]
    undefined_fields: std::collections::BTreeSet<String>,
}

impl AdapterOutput {
    pub(crate) fn from_values(values: FieldOutput) -> Self {
        Self {
            values,
            undefined_fields: std::collections::BTreeSet::new(),
        }
    }

    pub(crate) fn insert(&mut self, name: String, value: Option<serde_json::Value>) {
        match value {
            Some(value) => {
                let _ignored_previous = self.undefined_fields.remove(&name);
                drop(self.values.insert(name, value));
            }
            None => {
                drop(self.values.remove(&name));
                let _ignored_clone = self.undefined_fields.insert(name);
            }
        }
    }

    pub(crate) fn extend(&mut self, output: Self) {
        for (name, value) in output.values {
            self.insert(name, Some(value));
        }
        for name in output.undefined_fields {
            self.insert(name, None);
        }
    }

    /// Whether this is an own declared output property, including undefined.
    #[must_use]
    pub fn contains_field(&self, name: &str) -> bool {
        self.values.contains_key(name) || self.undefined_fields.contains(name)
    }

    #[must_use]
    pub fn field_is_undefined(&self, name: &str) -> bool {
        self.undefined_fields.contains(name)
    }

    /// JSON-representable values. Undefined remains observable through the
    /// presence accessors and is intentionally absent from this map.
    #[must_use]
    pub const fn values(&self) -> &FieldOutput {
        &self.values
    }

    pub(crate) fn filter_returned(&self, fields: &crate::field_policy::FieldConfigs) -> Self {
        let mut output = self.clone();
        for (name, field) in fields {
            if !field.returned {
                drop(output.values.remove(name));
                let _removed = output.undefined_fields.remove(name);
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
        let serde_json::Value::Object(output) = serde_json::to_value(&stored)? else {
            return Err(crate::AuthError::internal(
                "An adapter model must serialize to an object",
            ));
        };
        Ok(Self {
            stored,
            output: AdapterOutput::from_values(output),
        })
    }
}

impl<M> AdapterRecord<M> {
    pub(crate) fn with_output(stored: M, output: AdapterOutput) -> Self {
        Self { stored, output }
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
    fn adapter_snapshot(&self) -> Option<&AdapterOutput> {
        Some(&self.output)
    }
    delegate!(additional_fields, FieldOutput);
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
    delegate!(metadata, &serde_json::Value);
    delegate!(is_anonymous, Option<bool>);
    delegate!(phone_number, Option<&str>);
    delegate!(phone_number_verified, Option<bool>);
    delegate!(last_login_method, Option<&str>);
}

impl<M: AuthSession> AuthSession for AdapterRecord<M> {
    fn adapter_snapshot(&self) -> Option<&AdapterOutput> {
        Some(&self.output)
    }
    delegate!(additional_fields, FieldOutput);
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
    delegate!(active, bool);
}

impl<M: AuthAccount> AuthAccount for AdapterRecord<M> {
    fn adapter_snapshot(&self) -> Option<&AdapterOutput> {
        Some(&self.output)
    }
    delegate!(additional_fields, FieldOutput);
    delegate!(id, Cow<'_, str>);
    delegate!(account_id, &str);
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
