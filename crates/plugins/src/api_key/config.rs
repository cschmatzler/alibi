use super::callbacks::{
    ApiKeyDefaultPermissions, ApiKeyGenerator, ApiKeyGetter, ApiKeyPermissions, ApiKeyValidator,
};
use super::storage::{ApiKeyStorage, ApiKeyStorageMode};
use std::sync::Arc;

/// Which kind of entity a configuration's keys belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApiKeyReferences {
    /// Keys are owned by the signed-in user.
    #[default]
    User,
    /// Keys are owned by an organization; callers pass `organizationId` and
    /// must hold the matching `apiKey` permission in that organization.
    Organization,
}

/// Configuration for the API Key plugin, aligned with the TypeScript `ApiKeyOptions`.
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct ApiKeyConfig {
    /// Name of this configuration, stored on every key it creates.
    /// Upstream defaults it to `"default"`.
    pub config_id: String,
    /// Whether keys from this configuration belong to a user or to an
    /// organization.
    pub references: ApiKeyReferences,

    /// Database persistence (default) or application-owned secondary storage.
    pub storage: ApiKeyStorageMode,
    /// Use database rows for durable writes and admission in secondary mode.
    pub fallback_to_database: bool,
    /// Shared secondary cache for this plugin, independent of session persistence.
    pub secondary_storage: Option<Arc<dyn alibi_core::store::CacheAdapter>>,
    /// Application storage overriding the plugin's secondary cache.
    pub custom_storage: Option<Arc<dyn ApiKeyStorage>>,

    // -- key generation --
    /// Raw length excluding the prefix. Zero and NaN use 64; the built-in
    /// generator admits safely terminating fractions from 0.5 upward.
    /// A custom generator receives the number unchanged after that fallback.
    pub key_length: f64,
    pub prefix: Option<String>,
    /// Permissions applied when creation does not supply explicit permissions.
    pub default_permissions: Option<ApiKeyPermissions>,
    /// Optional application generator, receiving only length and effective prefix.
    pub custom_key_generator: Option<Arc<dyn ApiKeyGenerator>>,
    /// Dynamic defaults replace static `default_permissions` when configured.
    pub default_permissions_callback: Option<Arc<dyn ApiKeyDefaultPermissions>>,

    // -- header --
    pub api_key_headers: Vec<String>,
    /// Trusted application lookup, replacing `api_key_headers` when configured.
    pub custom_api_key_getter: Option<Arc<dyn ApiKeyGetter>>,
    /// Trusted acceptance predicate, checked before quota and rate-limit writes.
    pub custom_api_key_validator: Option<Arc<dyn ApiKeyValidator>>,

    // -- hashing --
    pub disable_key_hashing: bool,

    // -- starting characters --
    /// UTF-16 substring end: finite fractions truncate, negative/NaN select an
    /// empty prefix, and positive infinity selects the whole credential.
    /// SQLite retains a cut through a surrogate pair as actual WTF-8 TEXT.
    pub starting_characters_length: f64,
    pub store_starting_characters: bool,

    // -- prefix length validation --
    /// Compare the actual UTF-16 prefix length against this raw number.
    pub max_prefix_length: f64,
    /// Compare the actual UTF-16 prefix length against this raw number.
    pub min_prefix_length: f64,

    // -- name validation --
    /// Compare the actual UTF-16 name length against this raw number.
    pub max_name_length: f64,
    /// Compare the actual UTF-16 name length against this raw number.
    pub min_name_length: f64,
    pub require_name: bool,

    // -- metadata --
    pub enable_metadata: bool,

    // -- key expiration --
    pub key_expiration: KeyExpirationConfig,

    // -- rate limit defaults --
    pub rate_limit: RateLimitDefaults,

    // -- session emulation --
    pub enable_session_for_api_keys: bool,
    /// Start secondary-only usage merges and automatic cleanup in background work.
    /// The application background handler receives completion observations.
    /// Successful trusted verification launches cleanup only when enabled.
    /// Database quota and rate-limit admission remain atomic and awaited.
    pub defer_updates: bool,
}

impl ApiKeyConfig {
    pub(in crate::api_key) const fn normalized(mut self) -> Self {
        // Upstream resolves defaultKeyLength using JavaScript's `|| 64`.
        if self.key_length == 0.0 || self.key_length.is_nan() {
            self.key_length = 64.0;
        }
        self
    }
}

impl std::fmt::Debug for ApiKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyConfig")
            .field("config_id", &self.config_id)
            .field("references", &self.references)
            .field("key_length", &self.key_length)
            .field("prefix", &self.prefix)
            .field("custom_key_generator", &self.custom_key_generator.is_some())
            .field(
                "default_permissions_callback",
                &self.default_permissions_callback.is_some(),
            )
            .field("api_key_headers", &self.api_key_headers)
            .field(
                "custom_api_key_getter",
                &self.custom_api_key_getter.is_some(),
            )
            .field(
                "custom_api_key_validator",
                &self.custom_api_key_validator.is_some(),
            )
            .field(
                "enable_session_for_api_keys",
                &self.enable_session_for_api_keys,
            )
            .field("storage", &self.storage)
            .field("fallback_to_database", &self.fallback_to_database)
            .field("secondary_storage", &self.secondary_storage.is_some())
            .field("custom_storage", &self.custom_storage.is_some())
            .field("defer_updates", &self.defer_updates)
            .finish_non_exhaustive()
    }
}

/// Key expiration constraints.
#[derive(Debug, Clone)]
pub struct KeyExpirationConfig {
    /// Raw default `expiresIn` in seconds when none is provided. Zero/NaN omit
    /// expiry; finite fractions retain milliseconds, and invalid dates reject
    /// creation after generation and before the database write.
    pub default_expires_in: Option<f64>,
    /// If true, clients cannot set a custom `expiresIn`.
    pub disable_custom_expires_time: bool,
    /// Maximum `expiresIn` in **days**.
    pub max_expires_in: f64,
    /// Minimum `expiresIn` in **days**.
    pub min_expires_in: f64,
}

impl Default for KeyExpirationConfig {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            max_expires_in: 365.0,
            min_expires_in: 1.0,
        }
    }
}

/// Global rate-limit defaults applied to newly-created keys.
#[derive(Debug, Clone)]
pub struct RateLimitDefaults {
    pub enabled: bool,
    /// Default time window in milliseconds.
    pub time_window: f64,
    /// Default max requests per window.
    pub max_requests: f64,
}

impl Default for RateLimitDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window: 86_400_000.0, // 24 hours
            max_requests: 10.0,
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            storage: ApiKeyStorageMode::Database,
            fallback_to_database: false,
            custom_storage: None,
            secondary_storage: None,
            config_id: "default".to_owned(),
            references: ApiKeyReferences::default(),
            key_length: 64.0,
            prefix: None,
            default_permissions: None,
            custom_key_generator: None,
            default_permissions_callback: None,
            api_key_headers: vec!["x-api-key".to_owned()],
            custom_api_key_getter: None,
            custom_api_key_validator: None,
            disable_key_hashing: false,
            starting_characters_length: 6.0,
            store_starting_characters: true,
            max_prefix_length: 32.0,
            min_prefix_length: 1.0,
            max_name_length: 32.0,
            min_name_length: 1.0,
            require_name: false,
            enable_metadata: false,
            key_expiration: KeyExpirationConfig::default(),
            rate_limit: RateLimitDefaults::default(),
            enable_session_for_api_keys: false,
            defer_updates: false,
        }
    }
}
