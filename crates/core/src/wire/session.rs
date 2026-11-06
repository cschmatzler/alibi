use crate::AuthSession;
use crate::utils::json::{JsObject, JsValue as Value};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
/// Public session response shape.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionView {
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
    pub extension_fields: JsObject,
    pub omitted_fields: std::collections::BTreeSet<String>,
}

impl<'de> Deserialize<'de> for SessionView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = JsObject::deserialize(deserializer)?;
        macro_rules! field {
            ($name:literal) => {
                crate::utils::json::from_value(
                    fields
                        .shift_remove($name)
                        .ok_or_else(|| serde::de::Error::missing_field($name))?,
                )
                .map_err(serde::de::Error::custom)?
            };
        }
        macro_rules! optional {
            ($name:literal) => {
                fields
                    .shift_remove($name)
                    .map(crate::utils::json::from_value)
                    .transpose()
                    .map_err(serde::de::Error::custom)?
                    .flatten()
            };
        }
        Ok(Self {
            id: field!("id"),
            expires_at: field!("expiresAt"),
            token: field!("token"),
            created_at: field!("createdAt"),
            updated_at: field!("updatedAt"),
            ip_address: optional!("ipAddress"),
            user_agent: optional!("userAgent"),
            user_id: field!("userId"),
            impersonated_by: optional!("impersonatedBy"),
            active_organization_id: optional!("activeOrganizationId"),
            active_team_id: optional!("activeTeamId"),
            extension_fields: fields,
            omitted_fields: Default::default(),
        })
    }
}

impl Serialize for SessionView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = JsObject::new();
        macro_rules! entry {
            ($name:literal, $value:expr) => {
                if !self.omitted_fields.contains($name) {
                    _ = map.insert(
                        $name.into(),
                        crate::utils::json::to_js_value($value)
                            .map_err(serde::ser::Error::custom)?,
                    );
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
        if let Some(value) = self.extension_fields.get("impersonatedBy") {
            entry!("impersonatedBy", value);
        } else if let Some(value) = &self.impersonated_by {
            entry!("impersonatedBy", value);
        }
        if let Some(value) = self.extension_fields.get("activeOrganizationId") {
            entry!("activeOrganizationId", value);
        } else if let Some(value) = &self.active_organization_id {
            entry!("activeOrganizationId", value);
        }
        if let Some(value) = self.extension_fields.get("activeTeamId") {
            entry!("activeTeamId", value);
        } else if let Some(value) = &self.active_team_id {
            entry!("activeTeamId", value);
        }
        for (name, value) in &self.extension_fields {
            if !name.as_str().is_some_and(|name| {
                matches!(
                    name,
                    "impersonatedBy" | "activeOrganizationId" | "activeTeamId"
                )
            }) && !name
                .as_str()
                .is_some_and(|name| self.omitted_fields.contains(name))
            {
                _ = map.insert(name.clone(), value.clone());
            }
        }
        Value::Object(map).serialize(serializer)
    }
}

impl<T: AuthSession> From<&T> for SessionView {
    fn from(session: &T) -> Self {
        if let Some(view) = session.retained_session_view() {
            return view.clone();
        }
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
            extension_fields: session
                .adapter_snapshot()
                .map(|snapshot| snapshot.values().clone())
                .unwrap_or_default(),
            omitted_fields: std::collections::BTreeSet::default(),
        }
    }
}

impl AuthSession for SessionView {
    fn secondary_snapshot(&self) -> crate::AuthResult<Value> {
        Ok(crate::utils::json::to_js_value(self)?)
    }

    fn secondary_snapshot_with_native_output(
        &self,
        native: &crate::AdapterOutput,
    ) -> crate::AuthResult<Value> {
        let Value::Object(mut snapshot) = self.secondary_snapshot()? else {
            return Err(crate::AuthError::internal(
                "Invalid secondary session snapshot",
            ));
        };
        for (name, value) in native.values() {
            if value.is_undefined() {
                _ = snapshot.shift_remove(name);
            } else {
                _ = snapshot.insert(name.clone(), value.clone());
            }
        }
        Ok(Value::Object(snapshot))
    }

    fn secondary_snapshot_for_creation_with_native_output(
        &self,
        created_at: DateTime<Utc>,
        native: &crate::AdapterOutput,
    ) -> crate::AuthResult<Value> {
        let mut snapshot = self.secondary_snapshot_with_native_output(native)?;
        snapshot["createdAt"] = Value::String(
            crate::utils::datetime::json_date_millis(created_at.timestamp_millis()).into(),
        );
        Ok(snapshot)
    }

    fn secondary_snapshot_for_creation(
        &self,
        created_at: DateTime<Utc>,
    ) -> crate::AuthResult<Value> {
        let mut session = self.clone();
        session.created_at = created_at;
        _ = session.omitted_fields.remove("createdAt");
        _ = session.extension_fields.shift_remove("createdAt");
        session.secondary_snapshot()
    }

    fn from_secondary_snapshot(mut snapshot: Value) -> crate::AuthResult<Self> {
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            let value = snapshot.get(name).ok_or_else(|| {
                crate::AuthError::internal(format!("Missing secondary session {name}"))
            })?;
            let milliseconds = match value {
                Value::String(text) => text
                    .as_str()
                    .and_then(crate::utils::datetime::parse_date_millis),
                Value::Array(_) => crate::utils::datetime::parse_date_millis(
                    &crate::utils::json::JsValue::from(value.clone())
                        .coerce_string()
                        .map_err(crate::AuthError::internal)?,
                ),
                Value::Null => Some(0),
                Value::Bool(value) => Some(i64::from(*value)),
                Value::Number(number) => Some(*number)
                    .filter(|value| value.is_finite() && value.abs() <= 8_640_000_000_000_000.0)
                    .map(|value| value.trunc() as i64),
                Value::Object(_) | Value::Undefined => None,
                Value::Date(date) => Some(date.timestamp_millis()),
            };
            let date = milliseconds
                .and_then(DateTime::<Utc>::from_timestamp_millis)
                .ok_or_else(|| {
                    crate::AuthError::not_implemented(format!(
                        "Unrepresentable secondary session {name}"
                    ))
                })?;
            snapshot[name] = Value::String(
                crate::utils::datetime::json_date_millis(date.timestamp_millis()).into(),
            );
        }
        let mut session: Self = crate::utils::json::from_value(snapshot.clone())?;
        for name in ["ipAddress", "userAgent"] {
            if snapshot.get(name).is_none() {
                _ = session.omitted_fields.insert(name.to_owned());
            }
        }
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            if snapshot.get(name).is_some_and(Value::is_null) {
                _ = session.extension_fields.insert(name.into(), Value::Null);
            }
        }
        Ok(session)
    }

    fn output_from_secondary_snapshot(snapshot: Value) -> crate::AuthResult<crate::AdapterOutput> {
        let Value::Object(values) = snapshot else {
            return Err(crate::AuthError::internal(
                "Invalid secondary session snapshot",
            ));
        };
        Ok(crate::AdapterOutput::from_js_values(values))
    }

    fn retained_session_view(&self) -> Option<&SessionView> {
        Some(self)
    }
    fn additional_js_fields(&self) -> crate::AuthResult<JsObject> {
        Ok(self.extension_fields.clone())
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
}
