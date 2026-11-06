use crate::AuthSession;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
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
    #[serde(rename = "impersonatedBy", default)]
    pub impersonated_by: Option<String>,
    #[serde(rename = "activeOrganizationId", default)]
    pub active_organization_id: Option<String>,
    #[serde(rename = "activeTeamId", default)]
    pub active_team_id: Option<String>,
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    pub extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
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
            if !matches!(
                name.as_str(),
                "impersonatedBy" | "activeOrganizationId" | "activeTeamId"
            ) && !self.omitted_fields.contains(name)
            {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
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
            extension_fields: session.additional_fields().into_iter().collect(),
            omitted_fields: std::collections::BTreeSet::default(),
        }
    }
}

impl AuthSession for SessionView {
    fn secondary_snapshot(&self) -> crate::AuthResult<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }

    fn secondary_snapshot_with_native_output(
        &self,
        native: &crate::AdapterOutput,
    ) -> crate::AuthResult<serde_json::Value> {
        let serde_json::Value::Object(mut snapshot) = self.secondary_snapshot()? else {
            return Err(crate::AuthError::internal(
                "Invalid secondary session snapshot",
            ));
        };
        for name in snapshot.keys().cloned().collect::<Vec<_>>() {
            if native.field_is_undefined(&name) {
                _ = snapshot.remove(&name);
            }
        }
        snapshot.extend(native.values().clone());
        Ok(serde_json::Value::Object(snapshot))
    }

    fn secondary_snapshot_for_creation_with_native_output(
        &self,
        created_at: DateTime<Utc>,
        native: &crate::AdapterOutput,
    ) -> crate::AuthResult<serde_json::Value> {
        let mut snapshot = self.secondary_snapshot_with_native_output(native)?;
        snapshot["createdAt"] = serde_json::Value::String(
            crate::utils::datetime::json_date_millis(created_at.timestamp_millis()),
        );
        Ok(snapshot)
    }

    fn secondary_snapshot_for_creation(
        &self,
        created_at: DateTime<Utc>,
    ) -> crate::AuthResult<serde_json::Value> {
        let mut session = self.clone();
        session.created_at = created_at;
        _ = session.omitted_fields.remove("createdAt");
        _ = session.extension_fields.remove("createdAt");
        session.secondary_snapshot()
    }

    fn from_secondary_snapshot(mut snapshot: serde_json::Value) -> crate::AuthResult<Self> {
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            let value = snapshot.get(name).ok_or_else(|| {
                crate::AuthError::internal(format!("Missing secondary session {name}"))
            })?;
            let milliseconds = match value {
                serde_json::Value::String(text) => crate::utils::datetime::parse_date_millis(text),
                serde_json::Value::Array(_) => crate::utils::datetime::parse_date_millis(
                    &crate::utils::json::JsValue::from(value.clone())
                        .coerce_string()
                        .map_err(crate::AuthError::internal)?,
                ),
                serde_json::Value::Null => Some(0),
                serde_json::Value::Bool(value) => Some(i64::from(*value)),
                serde_json::Value::Number(number) => number
                    .as_f64()
                    .filter(|value| value.is_finite() && value.abs() <= 8_640_000_000_000_000.0)
                    .map(|value| value.trunc() as i64),
                serde_json::Value::Object(_) => None,
            };
            let date = milliseconds
                .and_then(DateTime::<Utc>::from_timestamp_millis)
                .ok_or_else(|| {
                    crate::AuthError::not_implemented(format!(
                        "Unrepresentable secondary session {name}"
                    ))
                })?;
            snapshot[name] = serde_json::Value::String(crate::utils::datetime::json_date_millis(
                date.timestamp_millis(),
            ));
        }
        let mut session: Self = serde_json::from_value(snapshot.clone())?;
        for name in ["ipAddress", "userAgent"] {
            if snapshot.get(name).is_none() {
                _ = session.omitted_fields.insert(name.to_owned());
            }
        }
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            if snapshot.get(name).is_some_and(serde_json::Value::is_null) {
                _ = session
                    .extension_fields
                    .insert(name.to_owned(), serde_json::Value::Null);
            }
        }
        Ok(session)
    }

    fn output_from_secondary_snapshot(
        snapshot: serde_json::Value,
    ) -> crate::AuthResult<crate::AdapterOutput> {
        let serde_json::Value::Object(values) = snapshot else {
            return Err(crate::AuthError::internal(
                "Invalid secondary session snapshot",
            ));
        };
        Ok(crate::AdapterOutput::from_values(values))
    }

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
}
