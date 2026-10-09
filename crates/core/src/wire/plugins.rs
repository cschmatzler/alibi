use super::*;
/// Public organization response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationView {
    #[serde(default, flatten)]
    pub additional_fields: std::collections::BTreeMap<String, serde_json::Value>,
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(
        serialize_with = "serialize_json_option_as_string",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
}

impl<T: AuthOrganization> From<&T> for OrganizationView {
    fn from(org: &T) -> Self {
        Self {
            additional_fields: org.additional_fields(),
            id: org.id().into_owned(),
            name: org.name().to_owned(),
            slug: org.slug().to_owned(),
            logo: org.logo().map(str::to_owned),
            metadata: org.metadata().cloned(),
            created_at: org.created_at(),
            updated_at: org.updated_at(),
        }
    }
}

/// Public invitation response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationView {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub email: String,
    pub role: Option<String>,
    pub status: InvitationStatus,
    #[serde(rename = "inviterId")]
    pub inviter_id: String,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "teamId", default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(
        flatten,
        default,
        deserialize_with = "crate::utils::json::deserialize_btree_map"
    )]
    pub extension_fields: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<T: AuthInvitation> From<&T> for InvitationView {
    fn from(inv: &T) -> Self {
        Self {
            id: inv.id().into_owned(),
            organization_id: inv.organization_id().into_owned(),
            email: inv.email().to_owned(),
            role: inv.optional_role().map(str::to_owned),
            status: inv.status().clone(),
            inviter_id: inv.inviter_id().into_owned(),
            expires_at: inv.expires_at(),
            created_at: inv.created_at(),
            team_id: inv.team_id().map(str::to_owned),
            extension_fields: std::collections::BTreeMap::default(),
        }
    }
}

/// Public passkey response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyView {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
}

impl<T: AuthPasskey> From<&T> for PasskeyView {
    fn from(pk: &T) -> Self {
        Self {
            id: pk.id().into_owned(),
            name: pk.name().map(str::to_owned),
            credential_id: pk.credential_id().to_owned(),
            user_id: pk.user_id().into_owned(),
            public_key: pk.public_key().to_owned(),
            counter: pk.counter(),
            device_type: pk.device_type().to_owned(),
            backed_up: pk.backed_up(),
            transports: pk.transports().map(str::to_owned),
            created_at: pk
                .created_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            aaguid: pk.aaguid().map(str::to_owned),
        }
    }
}

/// Public API key response shape.
///
/// Intentionally omits `key_hash` — the hashed key value is never returned
/// over the wire (matches upstream TS behavior).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyView {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "configId")]
    pub config_id: String,
    #[serde(rename = "refillInterval")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub refill_interval: Option<f64>,
    #[serde(rename = "refillAmount")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub refill_amount: Option<f64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub rate_limit_time_window: Option<f64>,
    #[serde(rename = "rateLimitMax")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub rate_limit_max: Option<f64>,
    #[serde(rename = "requestCount")]
    #[serde(serialize_with = "serialize_api_key_number")]
    pub request_count: Option<f64>,
    #[serde(serialize_with = "serialize_api_key_number")]
    pub remaining: Option<f64>,
    #[serde(rename = "lastRequest")]
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub permissions: Option<serde_json::Value>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
}

impl<T: AuthApiKey> From<&T> for ApiKeyView {
    fn from(ak: &T) -> Self {
        Self {
            id: ak.id().into_owned(),
            name: ak.name().map(str::to_owned),
            start: ak.start().map(str::to_owned),
            prefix: ak.prefix().map(str::to_owned),
            reference_id: ak.reference_id().into_owned(),
            config_id: ak.config_id().into_owned(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at().map(api_key_wire_date),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request().map(api_key_wire_date),
            expires_at: ak.expires_at().map(api_key_wire_date),
            created_at: api_key_wire_date(ak.created_at()),
            updated_at: api_key_wire_date(ak.updated_at()),
            permissions: ak
                .permissions()
                .and_then(|s| crate::utils::json::from_slice(s.as_bytes()).ok())
                .map(|mut value| {
                    normalize_api_key_permission_dates(&mut value);
                    value
                }),
            metadata: ak.metadata().and_then(|s| {
                let value = crate::utils::json::parse_value(s).ok()?;
                if let crate::utils::json::JsValue::String(encoded) = value {
                    let mut value = crate::utils::json::parse_value(&encoded)
                        .ok()?
                        .to_json_value()
                        .ok()?;
                    normalize_api_key_permission_dates(&mut value);
                    Some(value)
                } else {
                    value.to_json_value().ok()
                }
            }),
        }
    }
}

pub(in crate::wire) fn normalize_api_key_permission_dates(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(date) = crate::utils::datetime::normalize_json_date(text) {
                *text = date;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_api_key_permission_dates(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                normalize_api_key_permission_dates(value);
            }
        }
        _ => {}
    }
}

// Plugin entity views

#[expect(
    clippy::ref_option,
    reason = "Serde field serializers receive a reference to the declared Option field type"
)]
pub(in crate::wire) fn serialize_json_option_as_string<S>(
    value: &Option<serde_json::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(inner) => serializer
            .serialize_some(&serde_json::to_string(inner).map_err(serde::ser::Error::custom)?),
        None => serializer.serialize_none(),
    }
}

// JSON.stringify emits safe integral JavaScript numbers without a decimal suffix.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
#[expect(
    clippy::ref_option,
    reason = "Serde field serializers receive a reference to the declared Option field type"
)]
pub(in crate::wire) fn serialize_api_key_number<S: Serializer>(
    value: &Option<f64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) if value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0 => {
            serializer.serialize_i64(*value as i64)
        }
        value => value.serialize(serializer),
    }
}

// The source adapter exposes dates to JSON through Date.toJSON(). Keep native
// accessor/storage precision intact while projecting valid RFC3339 wire dates.
pub(in crate::wire) fn api_key_wire_date(value: &str) -> String {
    DateTime::parse_from_rfc3339(value).map_or_else(
        |_| value.to_owned(),
        |date| {
            date.with_timezone(&Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        },
    )
}
