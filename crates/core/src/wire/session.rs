use super::*;
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
