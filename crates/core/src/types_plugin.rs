use crate::entity::{AuthApiKey, AuthPasskey, AuthTwoFactor};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Private keyring persistence. Public JWKS responses must select public material explicitly.
#[derive(Debug, Clone)]
pub struct Jwk {
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateJwk {
    pub id: Option<String>,
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

/// An address linked to a SIWE identity on one chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAddress {
    pub id: String,
    pub user_id: String,
    pub address: String,
    /// Upstream uses a JavaScript Number, which may exceed u64's range.
    pub chain_id: f64,
    pub is_primary: bool,
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateWalletAddress {
    pub user_id: String,
    pub address: String,
    pub chain_id: f64,
    pub is_primary: bool,
}

impl CreateWalletAddress {
    #[must_use]
    pub fn new(user_id: impl Into<String>, address: impl Into<String>, chain_id: f64) -> Self {
        Self {
            user_id: user_id.into(),
            address: address.into(),
            chain_id,
            is_primary: false,
        }
    }
}

/// Two-factor authentication response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub id: String,
    pub secret: String,
    #[serde(rename = "backupCodes")]
    pub backup_codes: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub verified: Option<bool>,
    #[serde(rename = "failedVerificationCount")]
    pub failed_verification_count: Option<f64>,
    #[serde(rename = "lockedUntil")]
    pub locked_until: Option<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Two-factor authentication creation data.
#[derive(Debug, Clone)]
pub struct CreateTwoFactor {
    pub user_id: String,
    pub secret: String,
    pub backup_codes: String,
    pub verified: Option<bool>,
    pub failed_verification_count: Option<f64>,
    pub locked_until: Option<DateTime<Utc>>,
}

impl Default for CreateTwoFactor {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            secret: String::new(),
            backup_codes: String::new(),
            verified: Some(true),
            failed_verification_count: Some(0.0),
            locked_until: None,
        }
    }
}

/// Mutate one exact factor generation without resetting its lockout state.
#[derive(Debug, Clone, Default)]
pub struct UpdateTwoFactor {
    pub secret: Option<String>,
    pub backup_codes: Option<String>,
    pub verified: Option<bool>,
}

/// Passkey response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub credential: String,
}

/// Input for creating a new passkey.
#[derive(Debug, Clone)]
pub struct CreatePasskey {
    pub user_id: String,
    pub name: Option<String>,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub credential: String,
    pub aaguid: Option<String>,
}

/// Input for updating a passkey.
#[derive(Debug, Clone)]
pub struct UpdatePasskey {
    pub name: Option<String>,
}

/// Input for updating stored passkey credential state after authentication.
#[derive(Debug, Clone)]
pub struct UpdatePasskeyAuthentication {
    pub credential: String,
    pub counter: u64,
    pub backed_up: bool,
    pub device_type: String,
}

/// Device authorization code storage shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCode {
    pub id: String,
    #[serde(rename = "deviceCode")]
    pub device_code: String,
    #[serde(rename = "userCode")]
    pub user_code: String,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub status: String,
    #[serde(rename = "lastPolledAt", skip_serializing_if = "Option::is_none")]
    pub last_polled_at: Option<DateTime<Utc>>,
    #[serde(rename = "pollingInterval", skip_serializing_if = "Option::is_none")]
    pub polling_interval: Option<i64>,
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Input for creating a new device authorization code.
#[derive(Debug, Clone)]
pub struct CreateDeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub polling_interval: Option<i64>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

/// Input for updating an existing device authorization code.
#[derive(Debug, Clone, Default)]
pub struct UpdateDeviceCode {
    /// Update the status. `None` leaves it unchanged.
    pub status: Option<String>,
    /// Update the approving/denying user. `Some(None)` clears it, `None` leaves
    /// it unchanged.
    pub user_id: Option<Option<String>>,
    /// Update the last poll timestamp. `Some(None)` clears it, `None` leaves it
    /// unchanged.
    pub last_polled_at: Option<Option<DateTime<Utc>>>,
}

/// API key response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    /// SHA-256 hash of the key (column name: `key` in SQL)
    #[serde(rename = "key")]
    pub key_hash: String,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "configId")]
    pub config_id: String,
    #[serde(rename = "refillInterval")]
    pub refill_interval: Option<f64>,
    #[serde(rename = "refillAmount")]
    pub refill_amount: Option<f64>,
    #[serde(rename = "lastRefillAt")]
    pub last_refill_at: Option<String>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<f64>,
    #[serde(rename = "rateLimitMax")]
    pub rate_limit_max: Option<f64>,
    #[serde(rename = "requestCount")]
    pub request_count: Option<f64>,
    pub remaining: Option<f64>,
    #[serde(rename = "lastRequest")]
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

/// UTF-16 code units selected from the beginning of a generated API key.
///
/// JavaScript substring may end between a surrogate pair. Stores receive the
/// original units so they can retain their encoding instead of replacing the
/// substring before it reaches persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyStartingCharacters(Vec<u16>);

impl ApiKeyStartingCharacters {
    #[must_use]
    pub const fn from_utf16(units: Vec<u16>) -> Self {
        Self(units)
    }

    #[must_use]
    pub fn as_utf16(&self) -> &[u16] {
        &self.0
    }

    /// The text a store persists: UTF-8 when the UTF-16 units are well
    /// formed, otherwise the WTF-8 bytes the reference SQLite adapter writes.
    #[must_use]
    pub fn storage_text(&self) -> ApiKeyStartText {
        if let Ok(text) = String::from_utf16(&self.0) {
            return ApiKeyStartText::Utf8(text);
        }
        let mut bytes = Vec::new();
        for scalar in char::decode_utf16(self.0.iter().copied()) {
            match scalar {
                Ok(scalar) => {
                    bytes.extend_from_slice(scalar.encode_utf8(&mut [0_u8; 4]).as_bytes());
                }
                Err(error) => {
                    let [high, low] = error.unpaired_surrogate().to_be_bytes();
                    bytes.extend_from_slice(&[
                        0xe0 | (high >> 4),
                        0x80 | ((high & 0x0f) << 2) | (low >> 6),
                        0x80 | (low & 0x3f),
                    ]);
                }
            }
        }
        ApiKeyStartText::Wtf8(bytes)
    }
}

/// How API-key starting characters are persisted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiKeyStartText {
    Utf8(String),
    /// Unpaired surrogates encoded as WTF-8; only SQLite stores these.
    Wtf8(Vec<u8>),
}

impl From<String> for ApiKeyStartingCharacters {
    fn from(value: String) -> Self {
        Self(value.encode_utf16().collect())
    }
}

impl From<&str> for ApiKeyStartingCharacters {
    fn from(value: &str) -> Self {
        Self(value.encode_utf16().collect())
    }
}

/// API key creation data.
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    /// Owner of the key — a user id, or an organization id when the key's
    /// configuration references organizations.
    pub reference_id: String,
    /// Name of the API-key configuration this key belongs to.
    pub config_id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub key_hash: String,
    pub start: Option<ApiKeyStartingCharacters>,
    pub expires_at: Option<String>,
    pub remaining: Option<f64>,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    pub enabled: bool,
}

/// API key update data.
#[derive(Debug, Clone, Default)]
pub struct UpdateApiKey {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<f64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    /// Update the expiration time. `Some(Some("..."))` sets a new value,
    /// `Some(None)` clears it, `None` leaves it unchanged.
    pub expires_at: Option<Option<String>>,
    /// Last request timestamp (updated during verify).
    pub last_request: Option<Option<String>>,
    /// Request count within the current rate-limit window.
    pub request_count: Option<f64>,
    /// Last refill timestamp (updated during verify).
    pub last_refill_at: Option<Option<String>>,
}

impl AuthTwoFactor for TwoFactor {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn secret(&self) -> &str {
        &self.secret
    }
    fn backup_codes(&self) -> &str {
        &self.backup_codes
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn verified(&self) -> Option<bool> {
        self.verified
    }
    fn failed_verification_count(&self) -> Option<f64> {
        self.failed_verification_count
    }
    fn locked_until(&self) -> Option<DateTime<Utc>> {
        self.locked_until
    }
}

impl<T: AuthTwoFactor> From<&T> for TwoFactor {
    fn from(two_factor: &T) -> Self {
        Self {
            id: two_factor.id().into_owned(),
            secret: two_factor.secret().to_owned(),
            backup_codes: two_factor.backup_codes().to_owned(),
            user_id: two_factor.user_id().into_owned(),
            verified: two_factor.verified(),
            failed_verification_count: two_factor.failed_verification_count(),
            locked_until: two_factor.locked_until(),
            created_at: two_factor.created_at(),
            updated_at: two_factor.updated_at(),
        }
    }
}

impl AuthApiKey for ApiKey {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn start(&self) -> Option<&str> {
        self.start.as_deref()
    }
    fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    fn key_hash(&self) -> &str {
        &self.key_hash
    }
    fn reference_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.reference_id)
    }
    fn config_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.config_id)
    }
    fn refill_interval(&self) -> Option<f64> {
        self.refill_interval
    }
    fn refill_amount(&self) -> Option<f64> {
        self.refill_amount
    }
    fn last_refill_at(&self) -> Option<&str> {
        self.last_refill_at.as_deref()
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn rate_limit_enabled(&self) -> bool {
        self.rate_limit_enabled
    }
    fn rate_limit_time_window(&self) -> Option<f64> {
        self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> Option<f64> {
        self.rate_limit_max
    }
    fn request_count(&self) -> Option<f64> {
        self.request_count
    }
    fn remaining(&self) -> Option<f64> {
        self.remaining
    }
    fn last_request(&self) -> Option<&str> {
        self.last_request.as_deref()
    }
    fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
    fn created_at(&self) -> &str {
        &self.created_at
    }
    fn updated_at(&self) -> &str {
        &self.updated_at
    }
    fn permissions(&self) -> Option<&str> {
        self.permissions.as_deref()
    }
    fn metadata(&self) -> Option<&str> {
        self.metadata.as_deref()
    }
}

impl<T: AuthApiKey> From<&T> for ApiKey {
    fn from(api_key: &T) -> Self {
        Self {
            id: api_key.id().into_owned(),
            name: api_key.name().map(str::to_owned),
            start: api_key.start().map(str::to_owned),
            prefix: api_key.prefix().map(str::to_owned),
            key_hash: api_key.key_hash().to_owned(),
            reference_id: api_key.reference_id().into_owned(),
            config_id: api_key.config_id().into_owned(),
            refill_interval: api_key.refill_interval(),
            refill_amount: api_key.refill_amount(),
            last_refill_at: api_key.last_refill_at().map(str::to_owned),
            enabled: api_key.enabled(),
            rate_limit_enabled: api_key.rate_limit_enabled(),
            rate_limit_time_window: api_key.rate_limit_time_window(),
            rate_limit_max: api_key.rate_limit_max(),
            request_count: api_key.request_count(),
            remaining: api_key.remaining(),
            last_request: api_key.last_request().map(str::to_owned),
            expires_at: api_key.expires_at().map(str::to_owned),
            created_at: api_key.created_at().to_owned(),
            updated_at: api_key.updated_at().to_owned(),
            permissions: api_key.permissions().map(str::to_owned),
            metadata: api_key.metadata().map(str::to_owned),
        }
    }
}

impl AuthPasskey for Passkey {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn public_key(&self) -> &str {
        &self.public_key
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn credential_id(&self) -> &str {
        &self.credential_id
    }
    fn counter(&self) -> u64 {
        self.counter
    }
    fn device_type(&self) -> &str {
        &self.device_type
    }
    fn backed_up(&self) -> bool {
        self.backed_up
    }
    fn transports(&self) -> Option<&str> {
        self.transports.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn aaguid(&self) -> Option<&str> {
        self.aaguid.as_deref()
    }
    fn credential(&self) -> &str {
        &self.credential
    }
}

impl<T: AuthPasskey> From<&T> for Passkey {
    fn from(passkey: &T) -> Self {
        Self {
            id: passkey.id().into_owned(),
            name: passkey.name().map(str::to_owned),
            public_key: passkey.public_key().to_owned(),
            user_id: passkey.user_id().into_owned(),
            credential_id: passkey.credential_id().to_owned(),
            counter: passkey.counter(),
            device_type: passkey.device_type().to_owned(),
            backed_up: passkey.backed_up(),
            transports: passkey.transports().map(str::to_owned),
            created_at: passkey.created_at(),
            updated_at: passkey.updated_at(),
            aaguid: passkey.aaguid().map(str::to_owned),
            credential: passkey.credential().to_owned(),
        }
    }
}
