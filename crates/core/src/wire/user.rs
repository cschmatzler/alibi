use super::*;
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
pub(in crate::wire) struct UserViewInput {
    pub(in crate::wire) id: String,
    pub(in crate::wire) name: Option<String>,
    pub(in crate::wire) email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub(in crate::wire) email_verified: serde_json::Value,
    pub(in crate::wire) image: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub(in crate::wire) created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub(in crate::wire) updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::wire) username: Option<String>,
    #[serde(
        rename = "displayUsername",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::wire) display_username: Option<String>,
    #[serde(
        rename = "twoFactorEnabled",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::wire) two_factor_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::wire) role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::wire) banned: Option<bool>,
    #[serde(rename = "banReason", default, skip_serializing_if = "Option::is_none")]
    pub(in crate::wire) ban_reason: Option<String>,
    #[serde(
        rename = "banExpires",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    pub(in crate::wire) ban_expires: Option<DateTime<Utc>>,
    #[serde(
        rename = "isAnonymous",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::wire) is_anonymous: Option<bool>,
    #[serde(
        rename = "phoneNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::wire) phone_number: Option<String>,
    #[serde(
        rename = "phoneNumberVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::wire) phone_number_verified: Option<bool>,
    #[serde(
        rename = "lastLoginMethod",
        default,
        skip_serializing_if = "Option::is_none"
    )]
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
