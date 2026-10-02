mod callbacks;
mod secondary_usage;
mod storage;
pub use storage::{ApiKeyStorage, ApiKeyStorageMode};
mod endpoint;
pub use endpoint::{ApiKeyVerificationInput, ApiKeyVerificationOutput};

pub(super) mod handlers;

pub(super) mod types;

mod verification;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_auth_core::entity::AuthUser;
use better_auth_core::{AuthContext, AuthError, AuthResult, BeforeRequestAction};
use better_auth_core::{AuthRequest, AuthResponse};
pub use callbacks::{
    ApiKeyCallbackContext, ApiKeyDefaultPermissions, ApiKeyGenerationOptions, ApiKeyGenerator,
    ApiKeyGetter, ApiKeyPermissions, ApiKeyValidator,
};
use handlers::{create_key_core, delete_key_core, get_key_core, list_keys_core, update_key_core};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
pub use types::{
    CreateKeyRequest, CreateKeyResponse, DeleteExpiredApiKeysResponse, UpdateKeyRequest,
};
use types::{DeleteKeyRequest, ListKeysQuery, parse_api_key_body};
pub use verification::{
    ApiKeyErrorDetails, ApiKeyErrorMessage, ApiKeyValidationError, ApiKeyVerificationError,
    VerifyApiKey,
};

// ---------------------------------------------------------------------------
// Error codes -- mirrors the TypeScript `API_KEY_ERROR_CODES`
// ---------------------------------------------------------------------------

/// Dedicated API Key error codes aligned with the TypeScript `API_KEY_ERROR_CODES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyErrorCode {
    InvalidApiKey,
    KeyDisabled,
    KeyExpired,
    UsageExceeded,
    KeyNotFound,
    RateLimited,
    UnauthorizedSession,
    InvalidPrefixLength,
    InvalidNameLength,
    MetadataDisabled,
    NoValuesToUpdate,
    KeyDisabledExpiration,
    ExpiresInTooSmall,
    ExpiresInTooLarge,
    InvalidRemaining,
    RefillAmountAndIntervalRequired,
    RefillIntervalAndAmountRequired,
    NameRequired,
    InvalidUserIdFromApiKey,
    InvalidReferenceIdFromApiKey,
    NoDefaultConfiguration,
    OrganizationIdRequired,
    OrganizationPluginRequired,
    UserNotMemberOfOrganization,
    InsufficientApiKeyPermissions,
    ServerOnlyProperty,
    FailedToUpdateApiKey,
    InvalidMetadataType,
}

impl ApiKeyErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidApiKey => "INVALID_API_KEY",
            Self::KeyDisabled => "KEY_DISABLED",
            Self::KeyExpired => "KEY_EXPIRED",
            Self::UsageExceeded => "USAGE_EXCEEDED",
            Self::KeyNotFound => "KEY_NOT_FOUND",
            Self::RateLimited => "RATE_LIMITED",
            Self::UnauthorizedSession => "UNAUTHORIZED_SESSION",
            Self::InvalidPrefixLength => "INVALID_PREFIX_LENGTH",
            Self::InvalidNameLength => "INVALID_NAME_LENGTH",
            Self::MetadataDisabled => "METADATA_DISABLED",
            Self::NoValuesToUpdate => "NO_VALUES_TO_UPDATE",
            Self::KeyDisabledExpiration => "KEY_DISABLED_EXPIRATION",
            Self::ExpiresInTooSmall => "EXPIRES_IN_IS_TOO_SMALL",
            Self::ExpiresInTooLarge => "EXPIRES_IN_IS_TOO_LARGE",
            Self::InvalidRemaining => "INVALID_REMAINING",
            Self::RefillAmountAndIntervalRequired => "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
            Self::RefillIntervalAndAmountRequired => "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
            Self::NameRequired => "NAME_REQUIRED",
            Self::InvalidUserIdFromApiKey => "INVALID_USER_ID_FROM_API_KEY",
            Self::InvalidReferenceIdFromApiKey => "INVALID_REFERENCE_ID_FROM_API_KEY",
            Self::NoDefaultConfiguration => "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
            Self::OrganizationIdRequired => "ORGANIZATION_ID_REQUIRED",
            Self::OrganizationPluginRequired => "ORGANIZATION_PLUGIN_REQUIRED",
            Self::UserNotMemberOfOrganization => "USER_NOT_MEMBER_OF_ORGANIZATION",
            Self::InsufficientApiKeyPermissions => "INSUFFICIENT_API_KEY_PERMISSIONS",
            Self::ServerOnlyProperty => "SERVER_ONLY_PROPERTY",
            Self::FailedToUpdateApiKey => "FAILED_TO_UPDATE_API_KEY",
            Self::InvalidMetadataType => "INVALID_METADATA_TYPE",
        }
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidApiKey => "Invalid API key.",
            Self::KeyDisabled => "API Key is disabled",
            Self::KeyExpired => "API Key has expired",
            Self::UsageExceeded => "API Key has reached its usage limit",
            Self::KeyNotFound => "API Key not found",
            Self::RateLimited => "Rate limit exceeded.",
            Self::UnauthorizedSession => "Unauthorized or invalid session",
            Self::InvalidPrefixLength => "The prefix length is either too large or too small.",
            Self::InvalidNameLength => "The name length is either too large or too small.",
            Self::MetadataDisabled => "Metadata is disabled.",
            Self::NoValuesToUpdate => "No values to update.",
            Self::KeyDisabledExpiration => "Custom key expiration values are disabled.",
            Self::ExpiresInTooSmall => {
                "The expiresIn is smaller than the predefined minimum value."
            }
            Self::ExpiresInTooLarge => "The expiresIn is larger than the predefined maximum value.",
            Self::InvalidRemaining => "The remaining count is either too large or too small.",
            Self::RefillAmountAndIntervalRequired => {
                "refillAmount is required when refillInterval is provided"
            }
            Self::RefillIntervalAndAmountRequired => {
                "refillInterval is required when refillAmount is provided"
            }
            Self::NameRequired => "API Key name is required.",
            Self::InvalidUserIdFromApiKey => "The user id from the API key is invalid.",
            Self::InvalidReferenceIdFromApiKey => "The reference id from the API key is invalid.",
            Self::NoDefaultConfiguration => "No default api-key configuration found.",
            Self::OrganizationIdRequired => {
                "Organization ID is required for organization-owned API keys."
            }
            Self::OrganizationPluginRequired => {
                "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin."
            }
            Self::UserNotMemberOfOrganization => {
                "You are not a member of the organization that owns this API key."
            }
            Self::InsufficientApiKeyPermissions => {
                "You do not have permission to perform this action on organization API keys."
            }
            Self::ServerOnlyProperty => {
                "The property you're trying to set can only be set from the server auth instance only."
            }
            Self::FailedToUpdateApiKey => "Failed to update API key",
            Self::InvalidMetadataType => "metadata must be an object or undefined",
        }
    }
}

impl serde::Serialize for ApiKeyErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

// Pinned api-key module state is shared by all plugin instances and databases.
static LAST_EXPIRED_CHECK: Mutex<Option<i64>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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

/// API Key management plugin.
#[derive(Clone)]
pub struct ApiKeyPlugin {
    /// Registered configurations. Unscoped requests use the default configuration.
    pub(super) configurations: Vec<ApiKeyConfig>,
}

impl ApiKeyPlugin {
    /// Register an additional named configuration.
    ///
    /// Upstream allows several api-key configurations side by side, each with
    /// its own `config_id`, ownership model and limits.
    #[must_use]
    pub fn configuration(mut self, config: ApiKeyConfig) -> Self {
        self.configurations.push(config.normalized());
        self
    }

    /// Pick the configuration a request addressed, mirroring upstream's
    /// `resolveConfiguration`: an unknown or absent `config_id` falls back to
    /// the default one, and a missing default is a client error.
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn resolve_configuration(
        &self,
        config_id: Option<&str>,
    ) -> AuthResult<&ApiKeyConfig> {
        if let Some(config_id) = config_id
            && let Some(found) = self
                .configurations
                .iter()
                .find(|config| config.config_id == config_id)
        {
            return Ok(found);
        }

        self.configurations
            .iter()
            .find(|config| is_default_config_id(&config.config_id))
            .ok_or_else(|| api_key_error(ApiKeyErrorCode::NoDefaultConfiguration))
    }
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
    pub secondary_storage: Option<Arc<dyn better_auth_core::store::CacheAdapter>>,
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
    const fn normalized(mut self) -> Self {
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

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

/// Builder for [`ApiKeyPlugin`] powered by the `bon` crate.
///
/// Usage:
/// ```ignore
/// let plugin = ApiKeyPlugin::builder()
///     .key_length(48)
///     .prefix("ba_".to_string())
///     .enable_metadata(true)
///     .rate_limit(RateLimitDefaults { enabled: true, time_window: 60_000.0, max_requests: 5.0 })
///     .build();
/// ```
#[bon::bon]
impl ApiKeyPlugin {
    #[builder]
    #[must_use]
    pub fn new(
        #[builder(default = "default".to_owned())] config_id: String,
        #[builder(default)] references: ApiKeyReferences,
        #[builder(default)] storage: ApiKeyStorageMode,
        #[builder(default)] fallback_to_database: bool,
        custom_storage: Option<Arc<dyn ApiKeyStorage>>,
        secondary_storage: Option<Arc<dyn better_auth_core::store::CacheAdapter>>,
        #[builder(default = 64.0, into)] key_length: f64,
        prefix: Option<String>,
        default_permissions: Option<ApiKeyPermissions>,
        custom_key_generator: Option<Arc<dyn ApiKeyGenerator>>,
        default_permissions_callback: Option<Arc<dyn ApiKeyDefaultPermissions>>,
        #[builder(default = vec!["x-api-key".to_owned()])] api_key_headers: Vec<String>,
        custom_api_key_getter: Option<Arc<dyn ApiKeyGetter>>,
        custom_api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
        #[builder(default = false)] disable_key_hashing: bool,
        #[builder(default = 6.0, into)] starting_characters_length: f64,
        #[builder(default = true)] store_starting_characters: bool,
        #[builder(default = 32.0, into)] max_prefix_length: f64,
        #[builder(default = 1.0, into)] min_prefix_length: f64,
        #[builder(default = 32.0, into)] max_name_length: f64,
        #[builder(default = 1.0, into)] min_name_length: f64,
        #[builder(default = false)] require_name: bool,
        #[builder(default = false)] enable_metadata: bool,
        #[builder(default)] key_expiration: KeyExpirationConfig,
        #[builder(default)] rate_limit: RateLimitDefaults,
        #[builder(default = false)] enable_session_for_api_keys: bool,
        #[builder(default = false)] defer_updates: bool,
    ) -> Self {
        Self {
            configurations: vec![
                ApiKeyConfig {
                    config_id,
                    references,
                    storage,
                    fallback_to_database,
                    custom_storage,
                    secondary_storage,
                    key_length,
                    prefix,
                    default_permissions,
                    custom_key_generator,
                    default_permissions_callback,
                    api_key_headers,
                    custom_api_key_getter,
                    custom_api_key_validator,
                    disable_key_hashing,
                    starting_characters_length,
                    store_starting_characters,
                    max_prefix_length,
                    min_prefix_length,
                    max_name_length,
                    min_name_length,
                    require_name,
                    enable_metadata,
                    key_expiration,
                    rate_limit,
                    enable_session_for_api_keys,
                    defer_updates,
                }
                .normalized(),
            ],
        }
    }

    #[must_use]
    pub fn with_config(config: ApiKeyConfig) -> Self {
        Self {
            configurations: vec![config.normalized()],
        }
    }

    // -- internal helpers --

    pub(super) fn generate_key(
        config: &ApiKeyConfig,
        custom_prefix: Option<&str>,
    ) -> AuthResult<(String, String, better_auth_core::ApiKeyStartingCharacters)> {
        if config.key_length <= 0.0 {
            return Err(AuthError::internal("Length must be a positive integer."));
        }
        // Source's zero-byte random buffer cannot advance positive lengths
        // below one half. Nonfinite built-in lengths also cannot terminate.
        if !config.key_length.is_finite() || config.key_length < 0.5 {
            return Err(AuthError::internal("Unsupported random key length"));
        }
        let capacity = config
            .key_length
            .ceil()
            .to_string()
            .parse::<u32>()
            .map_err(|error| AuthError::internal(error.to_string()))?;
        // Match TS: generateRandomString(length, "a-z", "A-Z") — alpha only
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut rng = rand::thread_rng();
        let mut raw = String::new();
        raw.try_reserve_exact(
            usize::try_from(capacity).map_err(|error| AuthError::internal(error.to_string()))?,
        )
        .map_err(|error| AuthError::internal(error.to_string()))?;
        while f64::from(
            u32::try_from(raw.len()).map_err(|error| AuthError::internal(error.to_string()))?,
        ) < config.key_length
        {
            raw.push(ALPHABET.choose(&mut rng).copied().map_or('a', char::from));
        }

        let prefix = custom_prefix
            .filter(|prefix| !prefix.is_empty())
            .or(config.prefix.as_deref())
            .unwrap_or("");
        let full_key = format!("{prefix}{raw}");

        // TS computes start from the full key (including prefix):
        //   start = key.substring(0, charactersLength)
        let start = Self::starting_characters(&full_key, config.starting_characters_length);

        let hash = if config.disable_key_hashing {
            full_key.clone()
        } else {
            Self::hash_key(&full_key)
        };

        Ok((full_key, hash, start))
    }

    pub(super) fn starting_characters(
        key: &str,
        length: f64,
    ) -> better_auth_core::ApiKeyStartingCharacters {
        // substring(0, length) clamps negatives/NaN to zero, truncates finite
        // fractions, and preserves all code units for positive infinity.
        let end = if length.is_nan() || length < 0.0 {
            0.0
        } else {
            length.trunc()
        };
        let units = key
            .encode_utf16()
            .scan(0_u32, |position, unit| {
                let keep = f64::from(*position) < end;
                *position = position.saturating_add(1);
                keep.then_some(unit)
            })
            .collect();
        better_auth_core::ApiKeyStartingCharacters::from_utf16(units)
    }

    pub(super) fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Start automatic cleanup without awaiting its deletion.
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn maybe_delete_expired(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        drop(self.start_configured_cleanup(ctx).await?);
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn register_expired_cleanup(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        let completion = self.start_configured_cleanup(ctx).await?;
        if let Some(handler) = &ctx.config.background_tasks {
            handler.handle(completion)
        } else {
            drop(completion);
            Ok(())
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn start_configured_cleanup(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<better_auth_core::BackgroundTaskCompletion> {
        if self.configurations.iter().any(ApiKeyConfig::uses_database) {
            Self::start_expired_cleanup(ctx).await
        } else {
            Ok(Box::pin(async { Ok(()) }))
        }
    }

    pub(super) async fn start_expired_cleanup(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<better_auth_core::BackgroundTaskCompletion> {
        if !admit_expired_cleanup(false) {
            return Ok(Box::pin(async { Ok(()) }));
        }
        let database = Arc::clone(&ctx.database);
        Self::start_background_work(async move {
            if let Err(error) = database.delete_expired_api_keys().await {
                tracing::error!(%error, "Failed to delete expired API keys");
            }
            Ok(())
        })
        .await
    }

    // Both automatic bulk cleanup and deferred single-row rejection own their
    // work before application completion registration, preserving hook context.
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn start_background_work(
        operation: impl Future<Output = AuthResult<()>> + Send + 'static,
    ) -> AuthResult<better_auth_core::BackgroundTaskCompletion> {
        better_auth_core::start_background_task(operation).await
    }

    /// Force cleanup across owners/configurations, updating the same global
    /// automatic-cleanup timestamp and awaiting deletion despite the throttle.
    pub async fn delete_all_expired_api_keys(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> DeleteExpiredApiKeysResponse {
        let _ignored_result = admit_expired_cleanup(true);
        if !self.configurations.iter().any(ApiKeyConfig::uses_database) {
            return DeleteExpiredApiKeysResponse {
                success: true,
                error: None,
            };
        }
        if let Err(error) = ctx.database.delete_expired_api_keys().await {
            tracing::error!(%error, "Failed to delete expired API keys");
        }
        DeleteExpiredApiKeysResponse {
            success: true,
            error: None,
        }
    }

    // -- Validation helpers --

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn validate_prefix(config: &ApiKeyConfig, prefix: Option<&str>) -> AuthResult<()> {
        if let Some(p) = prefix.filter(|prefix| !prefix.is_empty()) {
            let len = f64::from(
                u32::try_from(p.encode_utf16().count())
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            );
            if len < config.min_prefix_length || len > config.max_prefix_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidPrefixLength));
            }
        }
        Ok(())
    }

    /// Validate the `name` field.
    ///
    /// When `is_create` is true, `require_name` is enforced (name must be
    /// present).  On updates `require_name` is **not** enforced -- the
    /// caller may be updating unrelated fields without resending the name.
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn validate_name(
        config: &ApiKeyConfig,
        name: Option<&str>,
        is_create: bool,
    ) -> AuthResult<()> {
        if is_create && config.require_name && name.is_none_or(str::is_empty) {
            return Err(api_key_error(ApiKeyErrorCode::NameRequired));
        }
        if let Some(n) = name.filter(|name| !is_create || !name.is_empty()) {
            let len = f64::from(
                u32::try_from(n.encode_utf16().count())
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            );
            if len < config.min_name_length || len > config.max_name_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidNameLength));
            }
        }
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn validate_expires_in(
        config: &ApiKeyConfig,
        expires_in: Option<f64>,
    ) -> AuthResult<Option<f64>> {
        let cfg = &config.key_expiration;
        if let Some(secs) = expires_in {
            if cfg.disable_custom_expires_time {
                return Err(api_key_error(ApiKeyErrorCode::KeyDisabledExpiration));
            }
            // expiresIn is in seconds; min/max are in days
            let days = secs / 86_400.0;
            if days < cfg.min_expires_in {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooSmall));
            }
            if days > cfg.max_expires_in {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooLarge));
            }
            Ok(Some(secs))
        } else {
            Ok(cfg.default_expires_in)
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn validate_metadata(
        config: &ApiKeyConfig,
        metadata: Option<&better_auth_core::utils::json::JsValue>,
    ) -> AuthResult<()> {
        if let Some(value) = metadata.filter(|value| match value {
            better_auth_core::utils::json::JsValue::Null => false,
            better_auth_core::utils::json::JsValue::Bool(value) => *value,
            better_auth_core::utils::json::JsValue::Number(value) => {
                *value != 0.0 && !value.is_nan()
            }
            better_auth_core::utils::json::JsValue::String(value) => !value.is_empty(),
            better_auth_core::utils::json::JsValue::Array(_)
            | better_auth_core::utils::json::JsValue::Object(_) => true,
        }) {
            if !config.enable_metadata {
                return Err(api_key_error(ApiKeyErrorCode::MetadataDisabled));
            }
            if !value.is_object() && !value.is_array() {
                return Err(api_key_error(ApiKeyErrorCode::InvalidMetadataType));
            }
        }
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn validate_refill(
        refill_interval: Option<f64>,
        refill_amount: Option<f64>,
    ) -> AuthResult<()> {
        match (
            refill_interval.filter(|value| *value != 0.0),
            refill_amount.filter(|value| *value != 0.0),
        ) {
            (None, Some(_)) => Err(api_key_error(
                ApiKeyErrorCode::RefillAmountAndIntervalRequired,
            )),
            (Some(_), None) => Err(api_key_error(
                ApiKeyErrorCode::RefillIntervalAndAmountRequired,
            )),
            _ => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // Route handlers
    // -----------------------------------------------------------------------

    async fn handle_create(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut resolution = req.clone();
        drop(
            resolution
                .query
                .insert("disableCookieCache".into(), "true".into()),
        );
        let (user, _session) = ctx
            .require_cached_session(&resolution)
            .await
            .map_err(|error| match error {
                AuthError::Unauthenticated => api_key_error(ApiKeyErrorCode::UnauthorizedSession),
                error @ (AuthError::Api { .. }
                | AuthError::Upstream { .. }
                | AuthError::BadRequest(_)
                | AuthError::InvalidRequest(_)
                | AuthError::Validation(_)
                | AuthError::InvalidCredentials
                | AuthError::AuthenticationFailed(_)
                | AuthError::SessionNotFound
                | AuthError::Forbidden(_)
                | AuthError::UserCreationCancelled
                | AuthError::SessionCreationCancelled
                | AuthError::BannedUser(_)
                | AuthError::Unauthorized
                | AuthError::UserNotFound
                | AuthError::NotFound(_)
                | AuthError::Conflict(_)
                | AuthError::MethodNotAllowed(_)
                | AuthError::PayloadTooLarge(_)
                | AuthError::UnprocessableEntity(_)
                | AuthError::RateLimited
                | AuthError::NotImplemented(_)
                | AuthError::Config(_)
                | AuthError::Database(_)
                | AuthError::Serialization(_)
                | AuthError::Plugin { .. }
                | AuthError::CallbackFailure(_)
                | AuthError::Internal(_)
                | AuthError::Encryption(_)
                | AuthError::PasswordHash(_)
                | AuthError::Jwt(_)) => error,
            })?;
        let body: CreateKeyRequest = match parse_api_key_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = match create_key_core(&body, user.id(), self, ctx, Some(req)).await {
            Ok(response) => response,
            Err(error)
                if error.status_code() >= 500
                    && !matches!(error, AuthError::Upstream { .. } | AuthError::Api { .. }) =>
            {
                return Ok(AuthResponse::new(500));
            }
            Err(error) => return Err(error),
        };
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_get(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut resolution = req.clone();
        drop(resolution.query.remove("disableCookieCache"));
        drop(resolution.query.remove("disableRefresh"));
        let (user, _session) = super::helpers::ordinary_session(&resolution, ctx).await?;
        let id = req
            .query
            .get("id")
            .ok_or_else(|| AuthError::bad_request("Query parameter 'id' is required"))?;
        let config_id = req.query.get("configId").map(String::as_str);
        let response = get_key_core(id, config_id, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_list(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut resolution = req.clone();
        drop(resolution.query.remove("disableCookieCache"));
        drop(resolution.query.remove("disableRefresh"));
        let (user, _session) = super::helpers::ordinary_session(&resolution, ctx).await?;
        let query = match ListKeysQuery::from_request(req) {
            Ok(query) => query,
            Err(response) => return Ok(response),
        };
        let response = list_keys_core(user.id(), &query, self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_update(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut resolution = req.clone();
        drop(
            resolution
                .query
                .insert("disableCookieCache".into(), "true".into()),
        );
        let (user, _session) = ctx
            .require_cached_session(&resolution)
            .await
            .map_err(|error| match error {
                AuthError::Unauthenticated => api_key_error(ApiKeyErrorCode::UnauthorizedSession),
                error @ (AuthError::Api { .. }
                | AuthError::Upstream { .. }
                | AuthError::BadRequest(_)
                | AuthError::InvalidRequest(_)
                | AuthError::Validation(_)
                | AuthError::InvalidCredentials
                | AuthError::AuthenticationFailed(_)
                | AuthError::SessionNotFound
                | AuthError::Forbidden(_)
                | AuthError::UserCreationCancelled
                | AuthError::SessionCreationCancelled
                | AuthError::BannedUser(_)
                | AuthError::Unauthorized
                | AuthError::UserNotFound
                | AuthError::NotFound(_)
                | AuthError::Conflict(_)
                | AuthError::MethodNotAllowed(_)
                | AuthError::PayloadTooLarge(_)
                | AuthError::UnprocessableEntity(_)
                | AuthError::RateLimited
                | AuthError::NotImplemented(_)
                | AuthError::Config(_)
                | AuthError::Database(_)
                | AuthError::Serialization(_)
                | AuthError::Plugin { .. }
                | AuthError::CallbackFailure(_)
                | AuthError::Internal(_)
                | AuthError::Encryption(_)
                | AuthError::PasswordHash(_)
                | AuthError::Jwt(_)) => error,
            })?;
        let body: UpdateKeyRequest = match parse_api_key_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = update_key_core(&body, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_delete(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        if user.banned() {
            return Err(AuthError::authentication_failed("User is banned"));
        }
        let body: DeleteKeyRequest = match parse_api_key_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = delete_key_core(&body, user.id(), self, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

// ---------------------------------------------------------------------------
// AuthPlugin trait implementation
// ---------------------------------------------------------------------------

better_auth_core::impl_auth_plugin! {
    ApiKeyPlugin, "api-key";
    routes {
        post "/api-key/create"                    => handle_create,             "api_key_create";
        get  "/api-key/get"                       => handle_get,                "api_key_get";
        post "/api-key/update"                    => handle_update,             "api_key_update";
        post "/api-key/delete"                    => handle_delete,             "api_key_delete";
        get  "/api-key/list"                      => handle_list,               "api_key_list";
    }
    extra {
        fn openapi_metadata(&self,ctx:&better_auth_core::AuthInitContext<S>)->better_auth_core::PluginOpenApiMetadata {
            let mut metadata=better_auth_core::openapi::annotations::instance_plugin_metadata("api-key",&<Self as better_auth_core::AuthPlugin<S>>::routes(self),ctx);
            let defaults=self.configurations.first().filter(|_|self.configurations.len()==1).map(|config|config.rate_limit.clone()).unwrap_or_default();
            for model in &mut metadata.models {
                if model.name!="Apikey" {continue;}
                for field in &mut model.fields {
                    let value=match field.name.as_str() {"rateLimitTimeWindow"=>defaults.time_window,"rateLimitMax"=>defaults.max_requests,_=>continue};
                    if let Some(schema)=field.schema.as_object_mut() {drop(schema.insert("default".into(),serde_json::json!(value)));}
                }
            }
            metadata
        }
        async fn on_init(&self, _ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
            if self.configurations.len() > 1 {
                let mut ids = std::collections::HashSet::new();
                for config in &self.configurations {
                    if config.config_id.is_empty() {
                        return Err(AuthError::config("configId is required for each API key configuration in the api-key plugin."));
                    }
                    if !ids.insert(&config.config_id) {
                        return Err(AuthError::config("configId must be unique for each API key configuration in the api-key plugin."));
                    }
                }
            }
            Ok(())
        }

        fn server_endpoints(&self) -> Vec<better_auth_core::endpoint::EndpointDefinition> { endpoint::definitions() }

    fn endpoint_hooks(&self) -> Vec<&dyn better_auth_core::endpoint::EndpointHook<S>> { vec![self] }

    fn validate_endpoint(&self, call: &better_auth_core::endpoint::EndpointCall, _ctx: &AuthContext<S>) -> AuthResult<better_auth_core::endpoint::EndpointInput> { endpoint::validate(call) }

    async fn on_endpoint(&self, call: &better_auth_core::endpoint::EndpointCall, ctx: &AuthContext<S>) -> AuthResult<better_auth_core::endpoint::EndpointResponse> { self.call_endpoint(call, ctx).await }

    async fn before_request(
            &self,
            req: &AuthRequest,
            ctx: &AuthContext<S>,
        ) -> AuthResult<Option<BeforeRequestAction>> {
            self.api_key_session(req, ctx).await
        }
    }
}

impl std::fmt::Debug for ApiKeyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyPlugin").finish_non_exhaustive()
    }
}

pub(super) const fn api_key_error(code: ApiKeyErrorCode) -> AuthError {
    let status = match code {
        ApiKeyErrorCode::UnauthorizedSession => 401,
        ApiKeyErrorCode::OrganizationPluginRequired => 500,
        ApiKeyErrorCode::UserNotMemberOfOrganization
        | ApiKeyErrorCode::InsufficientApiKeyPermissions => 403,
        ApiKeyErrorCode::InvalidApiKey
        | ApiKeyErrorCode::KeyDisabled
        | ApiKeyErrorCode::KeyExpired
        | ApiKeyErrorCode::UsageExceeded
        | ApiKeyErrorCode::KeyNotFound
        | ApiKeyErrorCode::RateLimited
        | ApiKeyErrorCode::InvalidPrefixLength
        | ApiKeyErrorCode::InvalidNameLength
        | ApiKeyErrorCode::MetadataDisabled
        | ApiKeyErrorCode::NoValuesToUpdate
        | ApiKeyErrorCode::KeyDisabledExpiration
        | ApiKeyErrorCode::ExpiresInTooSmall
        | ApiKeyErrorCode::ExpiresInTooLarge
        | ApiKeyErrorCode::InvalidRemaining
        | ApiKeyErrorCode::RefillAmountAndIntervalRequired
        | ApiKeyErrorCode::RefillIntervalAndAmountRequired
        | ApiKeyErrorCode::NameRequired
        | ApiKeyErrorCode::InvalidUserIdFromApiKey
        | ApiKeyErrorCode::InvalidReferenceIdFromApiKey
        | ApiKeyErrorCode::NoDefaultConfiguration
        | ApiKeyErrorCode::OrganizationIdRequired
        | ApiKeyErrorCode::ServerOnlyProperty
        | ApiKeyErrorCode::FailedToUpdateApiKey
        | ApiKeyErrorCode::InvalidMetadataType => 400,
    };
    AuthError::Upstream {
        status,
        code: code.as_str(),
        message: code.message(),
    }
}

fn admit_expired_cleanup(bypass: bool) -> bool {
    let mut last = LAST_EXPIRED_CHECK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = chrono::Utc::now().timestamp_millis();
    if !bypass && last.is_some_and(|previous| now.saturating_sub(previous) < 10_000) {
        return false;
    }
    *last = Some(now);
    true
}

/// Keys written before `config_id` existed carry no value, so absent and
/// `"default"` denote the same configuration.
pub(super) fn is_default_config_id(config_id: &str) -> bool {
    config_id.is_empty() || config_id == "default"
}

/// Whether a stored key belongs to the addressed configuration.
pub(super) fn config_id_matches(key_config_id: &str, expected: &str) -> bool {
    if is_default_config_id(key_config_id) && is_default_config_id(expected) {
        return true;
    }
    key_config_id == expected
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {

    use super::*;
    use better_auth_core::wire::{SessionView, UserView};
    use better_auth_core::{
        AuthContext, AuthPlugin, CreateSession, CreateUser, HttpMethod, UpdateApiKey,
    };
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    async fn create_test_context_with_user() -> (AuthContext<TestSchema>, UserView, SessionView) {
        let config = Arc::new(better_auth_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = crate::plugins::test_helpers::create_test_database().await;
        let ctx = AuthContext::new(config, Arc::clone(&database));

        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("test@example.com")
                    .with_name("Test User"),
            )
            .await
            .unwrap();
        let wire_user = UserView::from(&user);

        let session = database
            .create_session(CreateSession {
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
                token: None,
                active_team_id: None,
                user_id: user.id().to_string(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let wire_session = SessionView::from(&session);

        (ctx, wire_user, wire_session)
    }

    async fn create_user_with_session(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        email: &str,
    ) -> (UserView, SessionView) {
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email(email.to_owned())
                    .with_name("Another User"),
            )
            .await
            .unwrap();
        let wire_user = UserView::from(&user);

        let session = ctx
            .database
            .create_session(CreateSession {
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
                token: None,
                active_team_id: None,
                user_id: user.id().to_string(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let wire_session = SessionView::from(&session);

        (wire_user, wire_session)
    }

    fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        query: Option<HashMap<String, String>>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert(
                "cookie".to_owned(),
                format!(
                    "better-auth.session_token={}",
                    better_auth_core::utils::cookie_utils::sign_cookie_value(
                        token,
                        &crate::plugins::test_helpers::create_test_config().secret
                    )
                ),
            );
        }

        AuthRequest::from_parts(
            method,
            path.to_owned(),
            headers,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
            query.unwrap_or_default(),
        )
    }

    fn json_body(response: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    /// Test helper: verify a key and return the same JSON shape the old HTTP
    /// handler produced. Calls the public server-only verification method.
    async fn verify_key(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        raw_key: &str,
        permissions: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        match plugin
            .verify_api_key(
                &VerifyApiKey {
                    key: raw_key,
                    config_id: None,
                    permissions,
                },
                ctx,
            )
            .await
        {
            Ok(view) => serde_json::json!({ "valid": true, "error": null, "key": view }),
            Err(ApiKeyVerificationError::Validation(error)) => serde_json::json!({
                "valid": false,
                "error": error,
                "key": null,
            }),
            Err(
                ApiKeyVerificationError::Internal(error)
                | ApiKeyVerificationError::ExplicitValidator(error),
            ) => panic!("Verification failed: {error}"),
        }
    }

    /// Create a key via the HTTP handler (client-allowed fields only), then
    /// patch server-only fields directly through the database.
    ///
    /// `server_fields` may contain: remaining, `refill_interval`, `refill_amount`,
    /// `rate_limit_enabled`, `rate_limit_time_window`, `rate_limit_max`, permissions.
    async fn create_key_with_server_fields(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        token: &str,
        client_body: serde_json::Value,
        server_fields: UpdateApiKey,
    ) -> (String, String) {
        let (id, raw_key) = create_key_and_get_raw(plugin, ctx, token, client_body).await;
        ctx.database
            .update_api_key(&id, server_fields)
            .await
            .unwrap();
        (id, raw_key)
    }

    /// Test helper: delete all expired keys and return a success JSON.
    async fn delete_all_expired(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> serde_json::Value {
        let _ignored_result = ctx.database.delete_expired_api_keys().await.unwrap();
        serde_json::json!({ "success": true, "error": null })
    }

    async fn create_key_and_get_id(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        token: &str,
        name: &str,
    ) -> String {
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(token),
            Some(serde_json::json!({ "name": name })),
            None,
        );
        let response = plugin.handle_create(&req, ctx).await.unwrap();
        assert_eq!(response.status, 200);
        (*(json_body(&response))
            .get("id")
            .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned()
    }

    /// Helper: create a key and return (id, `raw_key`)
    async fn create_key_and_get_raw(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        token: &str,
        body: serde_json::Value,
    ) -> (String, String) {
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(token),
            Some(body),
            None,
        );
        let response = plugin.handle_create(&req, ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let b = json_body(&response);
        (
            (*(b).get("id").expect("fixture contains the requested index"))
                .as_str()
                .unwrap()
                .to_owned(),
            (*(b)
                .get("key")
                .expect("fixture contains the requested index"))
            .as_str()
            .unwrap()
            .to_owned(),
        )
    }

    // -----------------------------------------------------------------------
    // Existing tests (kept)
    // -----------------------------------------------------------------------

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_create_and_get_do_not_expose_hash() {
        let plugin = ApiKeyPlugin::builder().prefix("ba_".to_owned()).build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let create_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "primary" })),
            None,
        );
        let create_response = plugin.handle_create(&create_req, &ctx).await.unwrap();
        assert_eq!(create_response.status, 200);

        let body = json_body(&create_response);
        assert!(body.get("key").is_some());
        assert!(body.get("key_hash").is_none());
        assert!(body.get("hash").is_none());

        let id = (*(body).get("id").unwrap_or(&serde_json::Value::Null))
            .as_str()
            .unwrap();
        let mut query = HashMap::new();
        query.insert("id".to_owned(), id.to_owned());

        let get_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/get",
            Some(&session.token),
            None,
            Some(query),
        );
        let get_response = plugin.handle_get(&get_req, &ctx).await.unwrap();
        assert_eq!(get_response.status, 200);

        let get_body = json_body(&get_response);
        assert!(get_body.get("key").is_none());
        assert!(get_body.get("key_hash").is_none());
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_create_rejects_invalid_expires_in() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "expiresIn": -1 })),
            None,
        );
        let response = plugin.handle_create(&req, &ctx).await;
        // Should be rejected due to validation (negative expires_in)
        assert!(response.is_err() || response.unwrap().status != 200);
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_get_update_delete_return_404_for_non_owner() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user1, session1) = create_test_context_with_user().await;
        let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session1.token, "owner-key").await;

        let mut get_query = HashMap::new();
        get_query.insert("id".to_owned(), key_id.clone());
        let get_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/get",
            Some(&session2.token),
            None,
            Some(get_query),
        );
        let get_err = plugin.handle_get(&get_req, &ctx).await.unwrap_err();
        assert_eq!(get_err.status_code(), 404);

        let update_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/update",
            Some(&session2.token),
            Some(serde_json::json!({ "keyId": key_id, "name": "new-name" })),
            None,
        );
        let update_err = plugin.handle_update(&update_req, &ctx).await.unwrap_err();
        assert_eq!(update_err.status_code(), 404);

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(&session2.token),
            Some(serde_json::json!({ "keyId": key_id })),
            None,
        );
        let delete_err = plugin.handle_delete(&delete_req, &ctx).await.unwrap_err();
        assert_eq!(delete_err.status_code(), 404);
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_list_returns_only_user_keys() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, user1, session1) = create_test_context_with_user().await;
        let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;

        drop(create_key_and_get_id(&plugin, &ctx, &session1.token, "u1-key").await);
        drop(create_key_and_get_id(&plugin, &ctx, &session2.token, "u2-key").await);

        let list_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/list",
            Some(&session1.token),
            None,
            None,
        );
        let list_response = plugin.handle_list(&list_req, &ctx).await.unwrap();
        assert_eq!(list_response.status, 200);

        let list_body = json_body(&list_response);
        // Upstream returns a paginated envelope rather than a bare array.
        let list = (*(list_body)
            .get("apiKeys")
            .unwrap_or(&serde_json::Value::Null))
        .as_array()
        .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(
            (*(list_body).get("total").unwrap_or(&serde_json::Value::Null)),
            1
        );
        // Upstream renamed the owner field to `referenceId` (a user or an
        // organization id) and stamps the owning configuration on every key.
        assert_eq!(
            (*(*(list)
                .first()
                .expect("fixture contains the requested index"))
            .get("referenceId")
            .expect("fixture contains the requested index"))
            .as_str()
            .unwrap(),
            user1.id
        );
        assert_eq!(
            (*(*(list)
                .first()
                .expect("fixture contains the requested index"))
            .get("configId")
            .expect("fixture contains the requested index"))
            .as_str()
            .unwrap(),
            "default"
        );
        assert!(
            (*(list)
                .first()
                .expect("fixture contains the requested index"))
            .get("userId")
            .is_none()
        );
        assert!(
            (*(list)
                .first()
                .expect("fixture contains the requested index"))
            .get("key")
            .is_none()
        );
        assert!(
            (*(list)
                .first()
                .expect("fixture contains the requested index"))
            .get("key_hash")
            .is_none()
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_owner_can_delete_key() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "to-delete").await;

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(&session.token),
            Some(serde_json::json!({ "keyId": key_id })),
            None,
        );
        let delete_response = plugin.handle_delete(&delete_req, &ctx).await.unwrap();
        assert_eq!(delete_response.status, 200);

        let deleted = ctx.database.get_api_key_by_id(&key_id).await.unwrap();
        assert!(deleted.is_none());
    }

    // -----------------------------------------------------------------------
    // New tests: verify, rate-limit, remaining/refill, delete expired, config
    // -----------------------------------------------------------------------

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_verify_valid_key() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "verify-test" }),
        )
        .await;

        let body = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(body).get("valid").unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert!((*(body).get("key").unwrap_or(&serde_json::Value::Null)).is_object());
    }

    #[tokio::test]
    async fn test_verify_invalid_key() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = verify_key(&plugin, &ctx, "definitely-not-a-valid-key", None).await;
        assert_eq!(
            (*(body).get("valid").unwrap_or(&serde_json::Value::Null)),
            false
        );
        assert!((*(body).get("error").unwrap_or(&serde_json::Value::Null)).is_object());
    }

    #[tokio::test]
    async fn test_verify_disabled_key() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "disable-test" }),
        )
        .await;

        let update = UpdateApiKey {
            enabled: Some(false),
            ..Default::default()
        };
        ctx.database.update_api_key(&id, update).await.unwrap();

        let body = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(body).get("valid").unwrap_or(&serde_json::Value::Null)),
            false
        );
        assert_eq!(
            (*(*(body).get("error").unwrap_or(&serde_json::Value::Null))
                .get("code")
                .unwrap_or(&serde_json::Value::Null)),
            "KEY_DISABLED"
        );
    }

    #[tokio::test]
    async fn test_verify_expired_key() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (id, raw_key) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "expire-test" }),
        )
        .await;

        let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
        let update = UpdateApiKey {
            expires_at: Some(Some(past)),
            ..Default::default()
        };
        ctx.database.update_api_key(&id, update).await.unwrap();

        let body = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(body).get("valid").unwrap_or(&serde_json::Value::Null)),
            false
        );
        assert_eq!(
            (*(*(body).get("error").unwrap_or(&serde_json::Value::Null))
                .get("code")
                .unwrap_or(&serde_json::Value::Null)),
            "KEY_EXPIRED"
        );

        // The key should have been deleted
        let deleted = ctx.database.get_api_key_by_id(&id).await.unwrap();
        assert!(deleted.is_none());
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_verify_remaining_consumption() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_with_server_fields(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "remain-test" }),
            UpdateApiKey {
                remaining: Some(2.0),
                ..Default::default()
            },
        )
        .await;

        // First verify - remaining goes from 2 to 1
        let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert_eq!(
            (*(*(r1).get("key").unwrap_or(&serde_json::Value::Null))
                .get("remaining")
                .unwrap_or(&serde_json::Value::Null)),
            1
        );

        // Second verify - remaining goes from 1 to 0
        let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert_eq!(
            (*(*(r2).get("key").unwrap_or(&serde_json::Value::Null))
                .get("remaining")
                .unwrap_or(&serde_json::Value::Null)),
            0
        );

        // Third verify - should fail (usage exceeded)
        let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(r3).get("valid").unwrap_or(&serde_json::Value::Null)),
            false
        );
        assert_eq!(
            (*(*(r3).get("error").unwrap_or(&serde_json::Value::Null))
                .get("code")
                .unwrap_or(&serde_json::Value::Null)),
            "USAGE_EXCEEDED"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_verify_rate_limiting() {
        let plugin = ApiKeyPlugin::builder()
            .rate_limit(RateLimitDefaults {
                enabled: true,
                time_window: 60_000.0,
                max_requests: 2.0,
            })
            .build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_with_server_fields(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "rl-test" }),
            UpdateApiKey {
                rate_limit_enabled: Some(true),
                rate_limit_time_window: Some(60_000.0),
                rate_limit_max: Some(2.0),
                ..Default::default()
            },
        )
        .await;

        // First two should succeed
        let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
            true
        );

        let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
            true
        );

        // Third should fail with rate limit
        let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
        assert_eq!(
            (*(r3).get("valid").unwrap_or(&serde_json::Value::Null)),
            false
        );
        assert_eq!(
            (*(*(r3).get("error").unwrap_or(&serde_json::Value::Null))
                .get("code")
                .unwrap_or(&serde_json::Value::Null)),
            "RATE_LIMITED"
        );
    }

    #[tokio::test]
    async fn test_delete_all_expired() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, fixture_user, session) = create_test_context_with_user().await;

        // Create two keys
        let (id1, _) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "will-expire" }),
        )
        .await;
        let (_id2, _) = create_key_and_get_raw(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "wont-expire" }),
        )
        .await;

        // Expire the first key
        let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
        ctx.database
            .update_api_key(
                &id1,
                UpdateApiKey {
                    expires_at: Some(Some(past)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let body = delete_all_expired(&ctx).await;
        assert_eq!(
            (*(body).get("success").unwrap_or(&serde_json::Value::Null)),
            true
        );

        // Only the non-expired key should remain
        let remaining_keys = ctx
            .database
            .list_api_keys_by_reference(&fixture_user.id)
            .await
            .unwrap();
        assert_eq!(remaining_keys.len(), 1);
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_verify_permissions() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let (_id, raw_key) = create_key_with_server_fields(
            &plugin,
            &ctx,
            &session.token,
            serde_json::json!({ "name": "perm-test" }),
            UpdateApiKey {
                permissions: Some(
                    serde_json::to_string(&serde_json::json!({
                        "admin": ["read", "write"],
                        "user": ["read"]
                    }))
                    .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

        // Verify with matching permissions -> should pass
        let perms_ok = serde_json::json!({ "admin": ["read"] });
        let r1 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_ok)).await;
        assert_eq!(
            (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
            true
        );

        // Verify with non-matching permissions -> should fail
        let perms_fail = serde_json::json!({ "superadmin": ["delete"] });
        let r2 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_fail)).await;
        assert_eq!(
            (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
            false
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_config_validation_prefix_length() {
        let plugin = ApiKeyPlugin::builder()
            .min_prefix_length(2)
            .max_prefix_length(5)
            .build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Too short prefix
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "prefix": "a" })),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("prefix length"));

        // Too long prefix
        let req2 = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "prefix": "toolong" })),
            None,
        );
        let err2 = plugin.handle_create(&req2, &ctx).await.unwrap_err();
        assert!(err2.to_string().contains("prefix length"));
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_config_require_name() {
        let plugin = ApiKeyPlugin::builder().require_name(true).build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // No name provided -> should fail
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({})),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("name is required"));
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_config_metadata_disabled() {
        let plugin = ApiKeyPlugin::builder().build(); // enable_metadata defaults to false
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "metadata": { "env": "prod" } })),
            None,
        );
        let err = plugin.handle_create(&req, &ctx).await.unwrap_err();
        assert!(err.to_string().contains("Metadata is disabled"));
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_config_metadata_enabled() {
        let plugin = ApiKeyPlugin::builder().enable_metadata(true).build();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "test", "metadata": { "env": "prod" } })),
            None,
        );
        let resp = plugin.handle_create(&req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert_eq!(
            (*(*(body).get("metadata").unwrap_or(&serde_json::Value::Null))
                .get("env")
                .unwrap_or(&serde_json::Value::Null)),
            "prod"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
    #[tokio::test]
    async fn test_update_with_expires_in() {
        let plugin = ApiKeyPlugin::builder().build();
        let (ctx, _user, session) = create_test_context_with_user().await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "update-exp").await;

        let update_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/update",
            Some(&session.token),
            Some(serde_json::json!({
                "keyId": key_id,
                "expiresIn": 86400
            })),
            None,
        );
        let resp = plugin.handle_update(&update_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);
        let body = json_body(&resp);
        assert!((*(body).get("expiresAt").unwrap_or(&serde_json::Value::Null)).is_string());
    }

    // Note: /api-key/verify and /api-key/delete-all-expired-api-keys are
    // server-only in TS (no HTTP routes), so the Rust plugin does not expose
    // them either. Route dispatch tests for these have been removed.

    // Ensure refillInterval + refillAmount require each other (validation logic)
    #[tokio::test]
    async fn test_refill_logic() {
        let result = ApiKeyPlugin::validate_refill(Some(60_000.0), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("refillAmount"));

        let result_2 = ApiKeyPlugin::validate_refill(None, Some(10.0));
        assert!(result_2.is_err());

        let result_3 = ApiKeyPlugin::validate_refill(Some(60_000.0), Some(10.0));
        assert!(result_3.is_ok());
    }

    mod session_tests {
        use super::*;

        // =======================================================================
        // Comprehensive integration tests (9 scenarios from the test plan)
        // =======================================================================

        #[tokio::test]
        async fn test_virtual_session_answers_get_and_post_get_session() {
            use better_auth_core::AuthPlugin;

            let plugin = ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build();
            let (ctx, user, session) = create_test_context_with_user().await;
            let (id, raw_key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "get-session" }),
            )
            .await;

            for method in [HttpMethod::Get, HttpMethod::Post] {
                let mut request = create_auth_request(method, "/get-session", None, None, None);
                drop(
                    request
                        .headers
                        .insert("x-api-key".to_owned(), raw_key.clone()),
                );
                let action = AuthPlugin::<TestSchema>::before_request(&plugin, &request, &ctx)
                    .await
                    .unwrap();
                let Some(BeforeRequestAction::Respond(response)) = action else {
                    panic!("API key sessions must answer GET and POST before route dispatch")
                };
                assert_eq!(response.status, 200);
                let body = json_body(&response);
                assert_eq!(
                    (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                        .get("id")
                        .unwrap_or(&serde_json::Value::Null)),
                    id
                );
                assert_eq!(
                    (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                        .get("token")
                        .unwrap_or(&serde_json::Value::Null)),
                    raw_key
                );
                assert_eq!(
                    (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                        .get("userId")
                        .unwrap_or(&serde_json::Value::Null)),
                    user.id
                );
            }
        }

        // 1. Virtual session: before_request injects session without DB writes
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_virtual_session_creates_no_db_session() {
            let plugin = ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build();
            let (ctx, fixture_user, session) = create_test_context_with_user().await;

            // Create an API key
            let (_id, raw_key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "virtual-session-test" }),
            )
            .await;

            // Count sessions before
            let sessions_before = ctx
                .database
                .get_user_sessions(&fixture_user.id)
                .await
                .unwrap()
                .len();

            // Simulate a request to a protected route with only x-api-key header
            let mut headers = HashMap::new();
            headers.insert("x-api-key".to_owned(), raw_key.clone());
            let req = AuthRequest::from_parts(
                HttpMethod::Post,
                "/update-user".to_owned(),
                headers,
                None,
                HashMap::new(),
            );

            // Call before_request -- should return InjectSession
            let action = plugin.before_request(&req, &ctx).await.unwrap();
            assert!(action.is_some(), "before_request should return an action");
            match action.unwrap() {
                BeforeRequestAction::InjectSession { session: session_2 } => {
                    assert_eq!(session_2.user_id, fixture_user.id);
                }
                BeforeRequestAction::Respond(_) | BeforeRequestAction::ReplaceHeaders { .. } => {
                    panic!("Expected InjectSession, got Respond");
                }
            }

            // Count sessions after -- should be unchanged (no DB writes)
            let sessions_after = ctx
                .database
                .get_user_sessions(&fixture_user.id)
                .await
                .unwrap()
                .len();
            assert_eq!(
                sessions_before, sessions_after,
                "No new sessions should be created in the database"
            );
        }

        // 2. Virtual session on /get-session: synthetic response
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_virtual_session_on_get_session() {
            let plugin = ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build();
            let (ctx, user, session) = create_test_context_with_user().await;

            let (_id, raw_key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "get-session-test" }),
            )
            .await;

            // Send request to /get-session with x-api-key header
            let mut headers = HashMap::new();
            headers.insert("x-api-key".to_owned(), raw_key.clone());
            let req = AuthRequest::from_parts(
                HttpMethod::Get,
                "/get-session".to_owned(),
                headers,
                None,
                HashMap::new(),
            );

            let action = plugin.before_request(&req, &ctx).await.unwrap();
            assert!(action.is_some());
            match action.unwrap() {
                BeforeRequestAction::Respond(resp) => {
                    assert_eq!(resp.status, 200);
                    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
                    // Should contain user data
                    assert_eq!(
                        (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                            .get("id")
                            .unwrap_or(&serde_json::Value::Null)),
                        user.id
                    );
                    assert_eq!(
                        (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                            .get("email")
                            .unwrap_or(&serde_json::Value::Null)),
                        "test@example.com"
                    );
                    // Should contain session-like data
                    assert!(
                        (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                            .get("id")
                            .unwrap_or(&serde_json::Value::Null))
                        .is_string()
                    );
                    assert_eq!(
                        (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                            .get("userId")
                            .unwrap_or(&serde_json::Value::Null)),
                        user.id
                    );
                }
                BeforeRequestAction::InjectSession { .. }
                | BeforeRequestAction::ReplaceHeaders { .. } => {
                    panic!("Expected Respond for /get-session, got InjectSession");
                }
            }
        }

        // 3. Rate limiting: create key with rateLimitMax=2, 3rd call fails
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_rate_limiting_third_call_fails() {
            let plugin = ApiKeyPlugin::builder()
                .rate_limit(RateLimitDefaults {
                    enabled: true,
                    time_window: 60_000.0,
                    max_requests: 2.0,
                })
                .build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            let (_id, raw_key) = create_key_with_server_fields(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "rl-integration" }),
                UpdateApiKey {
                    rate_limit_enabled: Some(true),
                    rate_limit_time_window: Some(60_000.0),
                    rate_limit_max: Some(2.0),
                    ..Default::default()
                },
            )
            .await;

            // First two pass
            let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
                true,
                "1st request should pass"
            );

            let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
                true,
                "2nd request should pass"
            );

            // Third should fail
            let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r3).get("valid").unwrap_or(&serde_json::Value::Null)),
                false,
                "3rd request should be rate-limited"
            );
            assert_eq!(
                (*(*(r3).get("error").unwrap_or(&serde_json::Value::Null))
                    .get("code")
                    .unwrap_or(&serde_json::Value::Null)),
                "RATE_LIMITED"
            );
        }

        // 4. Remaining consumption: remaining=2, no refill, 3rd fails
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_remaining_consumption_no_refill() {
            let plugin = ApiKeyPlugin::builder().build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            let (_id, raw_key) = create_key_with_server_fields(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "remaining-test" }),
                UpdateApiKey {
                    remaining: Some(2.0),
                    ..Default::default()
                },
            )
            .await;

            // 1st: remaining 2->1
            let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
                true
            );
            assert_eq!(
                (*(*(r1).get("key").unwrap_or(&serde_json::Value::Null))
                    .get("remaining")
                    .unwrap_or(&serde_json::Value::Null)),
                1
            );

            // 2nd: remaining 1->0
            let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
                true
            );
            assert_eq!(
                (*(*(r2).get("key").unwrap_or(&serde_json::Value::Null))
                    .get("remaining")
                    .unwrap_or(&serde_json::Value::Null)),
                0
            );

            // 3rd: usage exceeded
            let r3 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r3).get("valid").unwrap_or(&serde_json::Value::Null)),
                false
            );
            assert_eq!(
                (*(*(r3).get("error").unwrap_or(&serde_json::Value::Null))
                    .get("code")
                    .unwrap_or(&serde_json::Value::Null)),
                "USAGE_EXCEEDED"
            );
        }

        // 5. Refill logic: remaining=1, refillInterval=100ms, refillAmount=10,
        //    verify once -> remaining=0, wait 150ms, verify -> refill to 10 then
        //    decrement to 9.
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_refill_resets_remaining_after_interval() {
            let plugin = ApiKeyPlugin::builder().build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            // Use a very short refill interval for testing (100 ms)
            let (_id, raw_key) = create_key_with_server_fields(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "refill-test" }),
                UpdateApiKey {
                    remaining: Some(1.0),
                    refill_interval: Some(100.0),
                    refill_amount: Some(10.0),
                    ..Default::default()
                },
            )
            .await;

            // First verify: remaining 1->0
            let r1 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
                true
            );
            assert_eq!(
                (*(*(r1).get("key").unwrap_or(&serde_json::Value::Null))
                    .get("remaining")
                    .unwrap_or(&serde_json::Value::Null)),
                0
            );

            // Wait for refill interval to elapse
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;

            // Second verify: should refill to 10 and then decrement -> 9
            let r2 = verify_key(&plugin, &ctx, &raw_key, None).await;
            assert_eq!(
                (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
                true,
                "Should succeed after refill"
            );
            assert_eq!(
                (*(*(r2).get("key").unwrap_or(&serde_json::Value::Null))
                    .get("remaining")
                    .unwrap_or(&serde_json::Value::Null)),
                9,
                "Should be refillAmount - 1 = 9"
            );
        }

        // 6. Permissions: key with {"admin": ["read"]}, verify with
        //    {"admin": ["write"]} should fail
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_permissions_mismatch_fails() {
            let plugin = ApiKeyPlugin::builder().build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            let (_id, raw_key) = create_key_with_server_fields(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "perm-mismatch" }),
                UpdateApiKey {
                    permissions: Some(
                        serde_json::to_string(&serde_json::json!({ "admin": ["read"] })).unwrap(),
                    ),
                    ..Default::default()
                },
            )
            .await;

            // Verify with matching permission -> pass
            let perms_ok = serde_json::json!({ "admin": ["read"] });
            let r1 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_ok)).await;
            assert_eq!(
                (*(r1).get("valid").unwrap_or(&serde_json::Value::Null)),
                true
            );

            // Verify with mismatched permission -> fail
            let perms_fail = serde_json::json!({ "admin": ["write"] });
            let r2 = verify_key(&plugin, &ctx, &raw_key, Some(&perms_fail)).await;
            assert_eq!(
                (*(r2).get("valid").unwrap_or(&serde_json::Value::Null)),
                false
            );
        }

        // 7. Concurrent rate limiting: send 5 sequential verify requests with
        //    rateLimitMax=2, only first 2 succeed (sequential proves logic is
        //    correct; true concurrency race conditions are documented above).
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_concurrent_rate_limiting() {
            let plugin = ApiKeyPlugin::builder()
                .rate_limit(RateLimitDefaults {
                    enabled: true,
                    time_window: 60_000.0,
                    max_requests: 2.0,
                })
                .build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            let (_id, raw_key) = create_key_with_server_fields(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "concurrent-rl" }),
                UpdateApiKey {
                    rate_limit_enabled: Some(true),
                    rate_limit_time_window: Some(60_000.0),
                    rate_limit_max: Some(2.0),
                    ..Default::default()
                },
            )
            .await;

            let mut success_count = 0;
            let mut fail_count = 0;

            for _ in 0..5 {
                let body = verify_key(&plugin, &ctx, &raw_key, None).await;
                if (*(body).get("valid").unwrap_or(&serde_json::Value::Null)) == true {
                    success_count += 1;
                } else {
                    fail_count += 1;
                    assert_eq!(
                        (*(*(body).get("error").unwrap_or(&serde_json::Value::Null))
                            .get("code")
                            .unwrap_or(&serde_json::Value::Null)),
                        "RATE_LIMITED"
                    );
                }
            }

            assert_eq!(success_count, 2, "Only 2 out of 5 should succeed");
            assert_eq!(fail_count, 3, "3 out of 5 should be rate-limited");
        }

        // 8. Database compatibility: test delete_expired_api_keys through the
        //    in-repo auth store implementation.
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_delete_expired_api_keys_memory_adapter() {
            let (ctx, fixture_user, session) = create_test_context_with_user().await;
            let plugin = ApiKeyPlugin::builder().build();

            // Create two keys
            let (id1, _) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "will-expire" }),
            )
            .await;
            let (_id2, _) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "wont-expire" }),
            )
            .await;

            // Expire the first key by setting expires_at to the past
            let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
            ctx.database
                .update_api_key(
                    &id1,
                    UpdateApiKey {
                        expires_at: Some(Some(past)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

            // Delete expired keys
            let deleted = ctx.database.delete_expired_api_keys().await.unwrap();
            assert_eq!(deleted, 1, "Should delete exactly 1 expired key");

            // Verify only the non-expired key remains
            let remaining = ctx
                .database
                .list_api_keys_by_reference(&fixture_user.id)
                .await
                .unwrap();
            assert_eq!(remaining.len(), 1);
        }

        // 9. Delete expired: calling the store function directly removes only expired keys
        #[tokio::test]
        async fn test_delete_expired_removes_only_expired() {
            let plugin = ApiKeyPlugin::builder().build();
            let (ctx, fixture_user, session) = create_test_context_with_user().await;

            // Create two keys, expire one
            let (id1, _) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "expired" }),
            )
            .await;
            let (_id2, _) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "active" }),
            )
            .await;

            let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
            ctx.database
                .update_api_key(
                    &id1,
                    UpdateApiKey {
                        expires_at: Some(Some(past)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

            let deleted = ctx.database.delete_expired_api_keys().await.unwrap();
            assert_eq!(deleted, 1);

            let remaining = ctx
                .database
                .list_api_keys_by_reference(&fixture_user.id)
                .await
                .unwrap();
            assert_eq!(remaining.len(), 1);
        }

        // 10. before_request returns None when enableSessionForAPIKeys is false
        // Upstream reference: packages/better-auth/src/plugins/api-key/api-key.test.ts :: describe("api-key"); adapted to the Rust API key plugin handlers.
        #[tokio::test]
        async fn test_before_request_disabled_returns_none() {
            let plugin = ApiKeyPlugin::builder().build(); // enable_session_for_api_keys defaults to false
            let (ctx, _user, session) = create_test_context_with_user().await;

            let (_id, raw_key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "name": "disabled-session" }),
            )
            .await;

            let mut headers = HashMap::new();
            headers.insert("x-api-key".to_owned(), raw_key);
            let req = AuthRequest::from_parts(
                HttpMethod::Get,
                "/get-session".to_owned(),
                headers,
                None,
                HashMap::new(),
            );

            let action = plugin.before_request(&req, &ctx).await.unwrap();
            assert!(
                action.is_none(),
                "before_request should return None when session emulation is disabled"
            );
        }

        // Upstream reference: @better-auth/api-key :: resolveConfiguration — an absent
        // or unknown configId falls back to the default configuration.
        #[tokio::test]
        async fn test_resolve_configuration_falls_back_to_default() {
            let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
                config_id: "billing".to_owned(),
                ..ApiKeyConfig::default()
            });

            assert_eq!(
                plugin.resolve_configuration(None).unwrap().config_id,
                "default"
            );
            assert_eq!(
                plugin
                    .resolve_configuration(Some("billing"))
                    .unwrap()
                    .config_id,
                "billing"
            );
            // Unknown ids fall back rather than erroring.
            assert_eq!(
                plugin
                    .resolve_configuration(Some("nope"))
                    .unwrap()
                    .config_id,
                "default"
            );
        }

        // Upstream reference: @better-auth/api-key :: resolveConfiguration errors when
        // no configuration is registered as the default.
        #[tokio::test]
        async fn test_resolve_configuration_without_default_is_an_error() {
            let plugin = ApiKeyPlugin::builder()
                .config_id("billing".to_owned())
                .build();

            let err = plugin.resolve_configuration(None).unwrap_err();
            assert_eq!(err.status_code(), 400);
            assert_eq!(err.to_string(), "No default api-key configuration found.");
        }

        // Upstream reference: @better-auth/api-key :: configIdMatches treats a missing
        // configId as the default, for keys written before the column existed.
        #[tokio::test]
        async fn test_config_id_matches_treats_missing_as_default() {
            assert!(config_id_matches("", "default"));
            assert!(config_id_matches("default", ""));
            assert!(config_id_matches("billing", "billing"));
            assert!(!config_id_matches("billing", "default"));
        }

        // Upstream reference: @better-auth/api-key :: create with `references:
        // "organization"` requires organizationId.
        #[tokio::test]
        async fn test_create_for_organization_requires_organization_id() {
            let plugin = ApiKeyPlugin::builder()
                .references(ApiKeyReferences::Organization)
                .build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            let req = create_auth_request(
                HttpMethod::Post,
                "/api-key/create",
                Some(&session.token),
                Some(serde_json::json!({ "name": "org-key" })),
                None,
            );
            let err = plugin.handle_create(&req, &ctx).await.unwrap_err();

            assert_eq!(err.status_code(), 400);
            assert_eq!(
                err.to_string(),
                "Organization ID is required for organization-owned API keys."
            );
        }

        // Upstream reference: @better-auth/api-key :: checkOrgApiKeyPermission fails
        // when the organization plugin, which supplies the access control, is absent.
        #[tokio::test]
        async fn test_create_for_organization_requires_the_organization_plugin() {
            let plugin = ApiKeyPlugin::builder()
                .references(ApiKeyReferences::Organization)
                .build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            let req = create_auth_request(
                HttpMethod::Post,
                "/api-key/create",
                Some(&session.token),
                Some(serde_json::json!({ "name": "org-key", "organizationId": "org-1" })),
                None,
            );
            let err = plugin.handle_create(&req, &ctx).await.unwrap_err();

            assert_eq!(
                err.to_string(),
                "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin."
            );
        }

        // Upstream reference: @better-auth/api-key :: checkOrgApiKeyPermission rejects
        // a caller who is not a member of the owning organization.
        #[tokio::test]
        async fn test_create_for_organization_rejects_non_member() {
            let plugin = ApiKeyPlugin::builder()
                .references(ApiKeyReferences::Organization)
                .build();
            let (ctx, _user, session) = create_test_context_with_user().await;

            // Stand in for a registered organization plugin.
            let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
            drop(metadata.insert(
                crate::plugins::organization::METADATA_ENABLED.to_owned(),
                serde_json::Value::Bool(true),
            ));
            let ctx = AuthContext::with_metadata(
                Arc::clone(&ctx.config),
                Arc::clone(&ctx.database),
                metadata,
            );

            let req = create_auth_request(
                HttpMethod::Post,
                "/api-key/create",
                Some(&session.token),
                Some(
                    serde_json::json!({ "name": "org-key", "organizationId": "org-the-user-is-not-in" }),
                ),
                None,
            );
            let err = plugin.handle_create(&req, &ctx).await.unwrap_err();

            assert_eq!(
                err.to_string(),
                "You are not a member of the organization that owns this API key."
            );
        }
    }

    mod verification_tests {
        use super::*;

        #[tokio::test]
        async fn scoped_verification_uses_the_configuration_hashing_and_rejects_other_configs() {
            let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
                config_id: "machines".to_owned(),
                disable_key_hashing: true,
                ..Default::default()
            });
            let (ctx, _, session) = create_test_context_with_user().await;
            let (id, key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "configId": "machines", "name": "machine" }),
            )
            .await;
            let scoped = VerifyApiKey {
                key: &key,
                config_id: Some("machines"),
                permissions: None,
            };
            let verified = plugin.verify_api_key(&scoped, &ctx).await.unwrap();
            assert_eq!(verified.id, id);
            assert_eq!(verified.config_id, "machines");
            let serialized = serde_json::to_value(verified).unwrap();
            assert!(serialized.get("key").is_none());
            assert!(serialized.get("keyHash").is_none());

            for config_id in [None, Some("default"), Some("unknown")] {
                let error = plugin
                    .verify_api_key(
                        &VerifyApiKey {
                            config_id,
                            ..scoped
                        },
                        &ctx,
                    )
                    .await
                    .unwrap_err();
                assert!(matches!(
                    error,
                    ApiKeyVerificationError::Validation(ApiKeyValidationError {
                        code: ApiKeyErrorCode::InvalidApiKey,
                        ..
                    })
                ));
            }
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .request_count,
                Some(1.0)
            );
        }

        #[tokio::test]
        async fn unscoped_verification_uses_the_issuing_configuration_limits() {
            let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
                config_id: "machines".to_owned(),
                rate_limit: RateLimitDefaults {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            });
            let (ctx, _, session) = create_test_context_with_user().await;
            let (id, key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "configId": "machines" }),
            )
            .await;
            ctx.database
                .update_api_key(
                    &id,
                    UpdateApiKey {
                        rate_limit_enabled: Some(true),
                        rate_limit_max: Some(1.0),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

            let input = VerifyApiKey {
                key: &key,
                config_id: None,
                permissions: None,
            };
            for _ in 0..3 {
                assert_eq!(plugin.verify_api_key(&input, &ctx).await.unwrap().id, id);
            }
            let error = plugin
                .verify_api_key(
                    &VerifyApiKey {
                        config_id: Some("default"),
                        ..input
                    },
                    &ctx,
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                ApiKeyVerificationError::Validation(ApiKeyValidationError {
                    code: ApiKeyErrorCode::InvalidApiKey,
                    ..
                })
            ));
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .request_count,
                Some(0.0)
            );
        }

        #[tokio::test]
        async fn permissions_failure_preserves_usage_and_rate_limit_reports_retry_time() {
            let plugin = ApiKeyPlugin::builder().build();
            let (ctx, _, session) = create_test_context_with_user().await;
            let (id, key) = create_key_with_server_fields(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({}),
                UpdateApiKey {
                    remaining: Some(3.0),
                    permissions: Some(serde_json::json!({ "nodes": ["read"] }).to_string()),
                    rate_limit_max: Some(1.0),
                    rate_limit_time_window: Some(60_000.0),
                    ..Default::default()
                },
            )
            .await;
            let denied = serde_json::json!({ "nodes": ["delete"] });
            let allowed = serde_json::json!({ "nodes": ["read"] });
            let input = VerifyApiKey {
                key: &key,
                config_id: None,
                permissions: Some(&denied),
            };
            let error = plugin.verify_api_key(&input, &ctx).await.unwrap_err();
            assert!(matches!(
                error,
                ApiKeyVerificationError::Validation(ApiKeyValidationError {
                    code: ApiKeyErrorCode::KeyNotFound,
                    ..
                })
            ));
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .remaining,
                Some(3.0)
            );
            let input = VerifyApiKey {
                permissions: Some(&allowed),
                ..input
            };
            assert_eq!(
                plugin.verify_api_key(&input, &ctx).await.unwrap().remaining,
                Some(2.0)
            );
            let error_2 = plugin.verify_api_key(&input, &ctx).await.unwrap_err();
            let ApiKeyVerificationError::Validation(error_2_3) = error_2 else {
                panic!("Expected rate limit rejection")
            };
            assert_eq!(error_2_3.code, ApiKeyErrorCode::RateLimited);
            let retry = error_2_3.details.unwrap().try_again_in;
            assert!(retry > 0.0 && retry <= 60_000.0);
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .remaining,
                Some(1.0)
            );
        }

        #[tokio::test]
        async fn session_header_selects_a_named_config_without_a_default() {
            let plugin = ApiKeyPlugin::builder()
                .config_id("machines".to_owned())
                .api_key_headers(vec![
                    "x-machine-key".to_owned(),
                    "x-alternate-key".to_owned(),
                ])
                .enable_session_for_api_keys(true)
                .build();
            let (ctx, user, session) = create_test_context_with_user().await;
            let (_, key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "configId": "machines" }),
            )
            .await;
            let mut request =
                create_auth_request(HttpMethod::Get, "/get-session", None, None, None);
            request
                .headers
                .insert("x-alternate-key".to_owned(), key.clone());
            let result = plugin
                .before_request(&request, &ctx)
                .await
                .unwrap()
                .unwrap();
            let BeforeRequestAction::Respond(response) = result else {
                panic!("Expected virtual session")
            };
            assert_eq!(response.status, 200);
            let body = json_body(&response);
            assert_eq!(
                (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                    .get("token")
                    .unwrap_or(&serde_json::Value::Null)),
                key
            );
            assert_eq!(
                (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                    .get("userId")
                    .unwrap_or(&serde_json::Value::Null)),
                user.id
            );
            assert_eq!(
                (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                    .get("emailVerified")
                    .unwrap_or(&serde_json::Value::Null)),
                false
            );
            assert!(
                (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                    .get("createdAt")
                    .unwrap_or(&serde_json::Value::Null))
                .is_string()
            );
            assert!(
                (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
                    .get("expiresAt")
                    .unwrap_or(&serde_json::Value::Null))
                .is_string()
            );
        }

        #[tokio::test]
        async fn session_header_cannot_authenticate_a_different_configuration() {
            let plugin = ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build()
                .configuration(ApiKeyConfig {
                    config_id: "machines".to_owned(),
                    api_key_headers: vec!["x-machine-key".to_owned()],
                    enable_session_for_api_keys: true,
                    ..Default::default()
                });
            let (ctx, _, session) = create_test_context_with_user().await;
            let (id, key) = create_key_and_get_raw(
                &plugin,
                &ctx,
                &session.token,
                serde_json::json!({ "configId": "machines" }),
            )
            .await;
            let mut request =
                create_auth_request(HttpMethod::Get, "/get-session", None, None, None);
            request.headers.insert("x-api-key".to_owned(), key);
            let result = plugin
                .before_request(&request, &ctx)
                .await
                .unwrap()
                .unwrap();
            let BeforeRequestAction::Respond(response) = result else {
                panic!("Expected credential rejection")
            };
            assert_eq!(response.status, 401);
            assert_eq!(
                (*(json_body(&response))
                    .get("code")
                    .unwrap_or(&serde_json::Value::Null)),
                "INVALID_API_KEY"
            );
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&id)
                    .await
                    .unwrap()
                    .unwrap()
                    .request_count,
                Some(0.0)
            );
        }

        #[tokio::test]
        async fn organization_key_verifies_without_emulating_a_user_session() {
            let plugin = ApiKeyPlugin::builder()
                .references(ApiKeyReferences::Organization)
                .enable_session_for_api_keys(true)
                .build();
            let (ctx, user, _) = create_test_context_with_user().await;
            let (key, key_hash, start) =
                ApiKeyPlugin::generate_key(&ApiKeyConfig::default(), None).unwrap();
            ctx.database
                .create_api_key(better_auth_core::CreateApiKey {
                    // A colliding user ID must not turn an organization key into a user session.
                    reference_id: user.id,
                    config_id: "default".to_owned(),
                    key_hash,
                    start: Some(start),
                    enabled: true,
                    name: None,
                    prefix: None,
                    expires_at: None,
                    remaining: None,
                    rate_limit_enabled: false,
                    rate_limit_time_window: None,
                    rate_limit_max: None,
                    refill_interval: None,
                    refill_amount: None,
                    permissions: None,
                    metadata: None,
                })
                .await
                .unwrap();
            plugin
                .verify_api_key(
                    &VerifyApiKey {
                        key: &key,
                        config_id: None,
                        permissions: None,
                    },
                    &ctx,
                )
                .await
                .unwrap();
            let mut request =
                create_auth_request(HttpMethod::Get, "/get-session", None, None, None);
            request.headers.insert("x-api-key".to_owned(), key);
            let result = plugin
                .before_request(&request, &ctx)
                .await
                .unwrap()
                .unwrap();
            let BeforeRequestAction::Respond(response) = result else {
                panic!("Expected organization rejection")
            };
            assert_eq!(response.status, 401);
            assert_eq!(
                (*(json_body(&response))
                    .get("code")
                    .unwrap_or(&serde_json::Value::Null)),
                "INVALID_REFERENCE_ID_FROM_API_KEY"
            );
        }

        #[tokio::test]
        async fn api_key_initialization_rejects_ambiguous_configurations() {
            let (ctx, _, _) = create_test_context_with_user().await;
            for config_id in ["", "default"] {
                let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
                    config_id: config_id.to_owned(),
                    ..Default::default()
                });
                let mut init = better_auth_core::AuthInitContext::new(
                    Arc::clone(&ctx.config),
                    Arc::clone(&ctx.database),
                );
                assert!(matches!(
                    plugin.on_init(&mut init).await,
                    Err(AuthError::Config(_))
                ));
            }
        }

        #[tokio::test]
        async fn verification_preserves_database_failures() {
            let connection = better_auth_seaorm::Database::connect("sqlite::memory:")
                .await
                .unwrap();
            connection.clone().close().await.unwrap();
            let config = Arc::new(crate::plugins::test_helpers::create_test_config());
            let database = Arc::new(better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
                Arc::clone(&config),
                connection,
            ));
            let ctx = AuthContext::new(config, database);
            let plugin = ApiKeyPlugin::builder().build();
            let error = plugin
                .verify_api_key(
                    &VerifyApiKey {
                        key: "not-looked-up",
                        config_id: None,
                        permissions: None,
                    },
                    &ctx,
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                ApiKeyVerificationError::Internal(AuthError::Database(_))
            ));
        }

        #[tokio::test]
        async fn verified_session_authenticates_a_protected_plugin_route_without_a_database_session()
         {
            let plugin = ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build();
            let (ctx, user, session) = create_test_context_with_user().await;
            let (id, key) =
                create_key_and_get_raw(&plugin, &ctx, &session.token, serde_json::json!({})).await;
            let mut request =
                create_auth_request(HttpMethod::Get, "/api-key/list", None, None, None);
            request.headers.insert("x-api-key".to_owned(), key.clone());
            let action = plugin
                .before_request(&request, &ctx)
                .await
                .unwrap()
                .unwrap();
            let BeforeRequestAction::InjectSession { session: session_2 } = action else {
                panic!("Expected virtual session")
            };
            assert_eq!(session_2.token, key);
            request.set_virtual_session(session_2);
            let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(
                (*(*(*(json_body(&response))
                    .get("apiKeys")
                    .unwrap_or(&serde_json::Value::Null))
                .get(0)
                .unwrap_or(&serde_json::Value::Null))
                .get("id")
                .unwrap_or(&serde_json::Value::Null)),
                id
            );
            assert_eq!(
                ctx.database
                    .get_user_sessions(&user.id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }

        // The SDK uses an actual HTTP request. This guards the separate public Rust
        // contract: server-only verification without a request can use typed application
        // policy from immutable context extensions and preserves quota on rejection.
        #[tokio::test]
        async fn programmatic_validator_uses_typed_policy_without_a_request() {
            use std::sync::atomic::{AtomicBool, Ordering};
            struct Policy(AtomicBool);
            struct Predicate {
                private_policy_secret: String,
            }
            #[async_trait::async_trait]
            impl ApiKeyValidator for Predicate {
                async fn validate(
                    &self,
                    context: &ApiKeyCallbackContext<'_>,
                    _key: &str,
                ) -> AuthResult<bool> {
                    Ok(context.request.is_none()
                        && context.configuration_id == "programmatic"
                        && context.auth_config.secret == "test-secret-key-at-least-32-chars-long"
                        && self.private_policy_secret == "application-private-policy-secret"
                        && context
                            .extensions
                            .get::<Policy>()
                            .is_some_and(|policy| policy.0.load(Ordering::SeqCst)))
                }
            }
            let (mut ctx, user, _) = create_test_context_with_user().await;
            ctx.extensions.insert(Policy(AtomicBool::new(false)));
            let configuration = ApiKeyConfig {
                config_id: "programmatic".to_owned(),
                custom_api_key_validator: Some(Arc::new(Predicate {
                    private_policy_secret: "application-private-policy-secret".to_owned(),
                })),
                rate_limit: RateLimitDefaults {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(!format!("{configuration:?}").contains("application-private-policy-secret"));
            let plugin = ApiKeyPlugin::with_config(configuration);
            let created = plugin
                .create_key(
                    &ctx,
                    &CreateKeyRequest {
                        config_id: Some("programmatic".to_owned()),
                        user_id: Some(user.id.clone()),
                        remaining: Some(2.0),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let input = VerifyApiKey {
                key: &created.key,
                config_id: Some("programmatic"),
                permissions: None,
            };
            let rejected = plugin.verify_api_key(&input, &ctx).await.unwrap_err();
            assert!(matches!(
                rejected,
                ApiKeyVerificationError::Validation(ApiKeyValidationError {
                    code: ApiKeyErrorCode::KeyNotFound,
                    ..
                })
            ));
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&created.api_key.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .remaining,
                Some(2.0)
            );
            ctx.extensions
                .get::<Policy>()
                .unwrap()
                .0
                .store(true, Ordering::SeqCst);
            let accepted = plugin.verify_api_key(&input, &ctx).await.unwrap();
            assert_eq!(accepted.reference_id, user.id);
            assert_eq!(accepted.id, created.api_key.id);
            assert_eq!(accepted.remaining, Some(1.0));
            assert_eq!(
                ctx.database
                    .get_api_key_by_id(&created.api_key.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .remaining,
                Some(1.0)
            );
        }
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod crud_tests {
    use super::*;
    use better_auth_core::{AuthConfig, CreateSession, CreateUser, HttpMethod};
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    async fn context() -> (AuthContext<TestSchema>, String, String) {
        let database = crate::plugins::test_helpers::create_test_database().await;
        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("crud@example.com")
                    .with_name("CRUD user"),
            )
            .await
            .unwrap();
        let user_id = user.id().to_string();
        let session = database
            .create_session(CreateSession {
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
                token: None,
                active_team_id: None,
                user_id: user_id.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        let token = better_auth_core::entity::AuthSession::token(&session).to_owned();
        (
            AuthContext::new(
                Arc::new(AuthConfig::new("a-secret-that-is-at-least-32-characters")),
                database,
            ),
            user_id,
            token,
        )
    }

    fn request(token: &str, path: &str, body: &serde_json::Value) -> AuthRequest {
        AuthRequest::from_parts(
            HttpMethod::Post,
            path.to_owned(),
            HashMap::from([(
                "cookie".to_owned(),
                format!(
                    "better-auth.session_token={}",
                    better_auth_core::utils::cookie_utils::sign_cookie_value(
                        token,
                        "a-secret-that-is-at-least-32-characters"
                    )
                ),
            )]),
            Some(serde_json::to_vec(&body).unwrap()),
            HashMap::new(),
        )
    }

    async fn server_key(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<TestSchema>,
        user_id: &str,
        config_id: &str,
    ) -> CreateKeyResponse {
        plugin
            .create_key(
                ctx,
                &CreateKeyRequest {
                    user_id: Some(user_id.to_owned()),
                    config_id: Some(config_id.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn list_without_configuration_includes_all_user_configurations() {
        let (ctx, user_id, _) = context().await;
        let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
            config_id: "secondary".to_owned(),
            ..Default::default()
        });
        server_key(&plugin, &ctx, &user_id, "default").await;
        server_key(&plugin, &ctx, &user_id, "secondary").await;
        let list = list_keys_core(&user_id, &ListKeysQuery::default(), &plugin, &ctx)
            .await
            .unwrap();
        assert_eq!(list.total, 2);
        let list_2 = list_keys_core(
            &user_id,
            &ListKeysQuery {
                config_id: Some("secondary".to_owned()),
                ..Default::default()
            },
            &plugin,
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(list_2.total, 1);
        assert_eq!(
            (list_2.api_keys)
                .first()
                .expect("fixture contains the requested index")
                .config_id,
            "secondary"
        );
        let list_3 = list_keys_core(
            &user_id,
            &ListKeysQuery {
                config_id: Some("missing".to_owned()),
                ..Default::default()
            },
            &plugin,
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(list_3.total, 0);

        let no_default = ApiKeyPlugin::builder()
            .config_id("secondary".to_owned())
            .build();
        assert_eq!(
            list_keys_core(&user_id, &ListKeysQuery::default(), &no_default, &ctx)
                .await
                .unwrap()
                .total,
            2
        );
    }

    #[tokio::test]
    async fn http_requests_cannot_impersonate_users_or_change_server_permissions() {
        let (ctx, user_id, token) = context().await;
        let plugin = ApiKeyPlugin::builder().build();
        let create = request(&token, "/api-key/create", &(json!({"userId":user_id})));
        assert_eq!(
            plugin
                .handle_create(&create, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            401
        );
        let key = server_key(&plugin, &ctx, &user_id, "default").await;
        let update = request(
            &token,
            "/api-key/update",
            &(json!({"keyId":key.api_key.id,"userId":"someone-else","enabled":false})),
        );
        assert_eq!(
            plugin
                .handle_update(&update, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            401
        );
        let update_2 = request(
            &token,
            "/api-key/update",
            &(json!({"keyId":key.api_key.id,"permissions":null})),
        );
        assert_eq!(
            plugin
                .handle_update(&update_2, &ctx)
                .await
                .unwrap_err()
                .to_string(),
            ApiKeyErrorCode::ServerOnlyProperty.message()
        );
        let update_3 = request(&token, "/api-key/update", &(json!({"keyId":"missing"})));
        assert_eq!(
            plugin
                .handle_update(&update_3, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            404
        );
    }

    #[tokio::test]
    async fn metadata_can_be_cleared_and_disabled_metadata_is_ignored_on_update() {
        let (ctx, user_id, token) = context().await;
        let enabled = ApiKeyPlugin::builder().enable_metadata(true).build();
        let key = enabled
            .create_key(
                &ctx,
                &CreateKeyRequest {
                    user_id: Some(user_id.clone()),
                    metadata: Some(json!(["initial"]).into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(key.api_key.metadata, Some(json!(["initial"])));
        let update = request(
            &token,
            "/api-key/update",
            &(json!({"keyId":key.api_key.id,"metadata":null})),
        );
        let response = enabled.handle_update(&update, &ctx).await.unwrap();
        assert!(
            (*(serde_json::from_slice::<serde_json::Value>(&response.body).unwrap())
                .get("metadata")
                .unwrap_or(&serde_json::Value::Null))
            .is_null()
        );
        let disabled = ApiKeyPlugin::builder().build();
        let update_2 = request(
            &token,
            "/api-key/update",
            &(json!({"keyId":key.api_key.id,"metadata":{"ignored":true},"enabled":false})),
        );
        let response_2 = disabled.handle_update(&update_2, &ctx).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&response_2.body).unwrap();
        assert!((*(result).get("metadata").unwrap_or(&serde_json::Value::Null)).is_null());
        assert_eq!(
            (*(result).get("enabled").unwrap_or(&serde_json::Value::Null)),
            false
        );
        let update_3 = request(
            &token,
            "/api-key/update",
            &(json!({"keyId":key.api_key.id,"metadata":null})),
        );
        assert_eq!(
            disabled
                .handle_update(&update_3, &ctx)
                .await
                .unwrap_err()
                .to_string(),
            ApiKeyErrorCode::NoValuesToUpdate.message()
        );
    }

    #[tokio::test]
    async fn trusted_creation_and_update_preserve_permissions_and_fractional_expiration() {
        let (ctx, user_id, _) = context().await;
        let plugin = ApiKeyPlugin::builder()
            .key_expiration(KeyExpirationConfig {
                min_expires_in: 0.0,
                ..Default::default()
            })
            .build();
        let before = Utc::now();
        let key = plugin
            .create_key(
                &ctx,
                &CreateKeyRequest {
                    user_id: Some(user_id.clone()),
                    expires_in: Some(86400.25),
                    remaining: Some(3.0),
                    permissions: Some(ApiKeyPermissions::from([(
                        "device".to_owned(),
                        vec!["read".to_owned()],
                    )])),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(key.api_key.remaining, Some(3.0));
        assert_eq!(key.api_key.permissions, Some(json!({"device":["read"]})));
        let expires_at =
            chrono::DateTime::parse_from_rfc3339(key.api_key.expires_at.as_deref().unwrap())
                .unwrap()
                .with_timezone(&Utc);
        assert!((expires_at - before).num_milliseconds() >= 86_400_249);
        assert!((expires_at - Utc::now()).num_milliseconds() <= 86_400_250);
        let updated = plugin
            .update_key(
                &ctx,
                &UpdateKeyRequest {
                    key_id: key.api_key.id.clone(),
                    user_id: Some(user_id),
                    remaining: Some(5.0),
                    permissions: Some(None),
                    expires_in: Some(None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.remaining, Some(5.0));
        assert_eq!(updated.permissions, Some(serde_json::Value::Null));
        assert_eq!(updated.expires_at, None);
        let stored = ctx
            .database
            .get_api_key_by_id(&key.api_key.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored.key_hash, key.key);
    }

    #[tokio::test]
    async fn list_rejects_invalid_pagination_instead_of_ignoring_it() {
        let (ctx, _, token) = context().await;
        let plugin = ApiKeyPlugin::builder().build();
        for (field, value) in [
            ("limit", "-1"),
            ("offset", "1.5"),
            ("limit", "bad"),
            ("sortDirection", "sideways"),
        ] {
            let mut req = request(&token, "/api-key/list", &(json!({})));
            req.query.insert(field.to_owned(), value.to_owned());
            let response = plugin.handle_list(&req, &ctx).await.unwrap();
            assert_eq!(response.status, 400);
            assert_eq!(
                (*(serde_json::from_slice::<serde_json::Value>(&response.body).unwrap())
                    .get("code")
                    .unwrap_or(&serde_json::Value::Null)),
                "VALIDATION_ERROR"
            );
        }
    }

    #[tokio::test]
    async fn forced_cleanup_preserves_rows_on_store_failure_and_retries_without_throttle() {
        use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
        let config = Arc::new(AuthConfig::new("forced-cleanup-application-secret32"));
        let connection = better_auth_seaorm::Database::connect("sqlite::memory:")
            .await
            .unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&connection)
            .await
            .unwrap();
        let database = Arc::new(better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
            std::sync::Arc::clone(&config),
            connection.clone(),
        ));
        let ctx = AuthContext::new(config, database);
        let owner = ctx
            .database
            .create_user(CreateUser::new().with_email("cleanup@native.local"))
            .await
            .unwrap();
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            key_expiration: KeyExpirationConfig {
                min_expires_in: 0.0,
                ..Default::default()
            },
            ..Default::default()
        });
        let key = plugin
            .create_key(
                &ctx,
                &CreateKeyRequest {
                    user_id: Some(owner.id().to_string()),
                    name: Some("expired".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let expired = ctx
            .database
            .update_api_key(
                &key.api_key.id,
                better_auth_core::UpdateApiKey {
                    expires_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        connection.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER reject_api_key_cleanup BEFORE DELETE ON api_keys BEGIN SELECT RAISE(ABORT,'application cleanup rejected'); END")).await.unwrap();
        let failed = plugin.delete_all_expired_api_keys(&ctx).await;
        assert!(failed.success);
        assert!(failed.error.is_none());
        let retained = ctx
            .database
            .get_api_key_by_id(&key.api_key.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            better_auth_core::utils::json::to_value(&retained).unwrap(),
            better_auth_core::utils::json::to_value(&expired).unwrap()
        );
        connection
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                "DROP TRIGGER reject_api_key_cleanup",
            ))
            .await
            .unwrap();
        let retry = plugin.delete_all_expired_api_keys(&ctx).await;
        assert!(retry.success);
        assert!(retry.error.is_none());
        assert!(
            ctx.database
                .get_api_key_by_id(&key.api_key.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(owner.id().as_ref())
                .await
                .unwrap()
                .unwrap(),
            owner
        );
    }
    struct ApplicationKeyStorage {
        cache: Arc<better_auth_core::store::MemoryCacheAdapter>,
        fail_writes: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl ApiKeyStorage for ApplicationKeyStorage {
        async fn get(&self, key: &str) -> AuthResult<Option<String>> {
            use better_auth_core::store::CacheAdapter as _;
            self.cache.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> AuthResult<()> {
            use better_auth_core::store::CacheAdapter as _;
            if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AuthError::internal("application storage unavailable"));
            }
            match ttl {
                Some(ttl) => self.cache.set(key, value, ttl).await,
                None => self.cache.set_without_expiry(key, value).await,
            }
        }
        async fn delete(&self, key: &str) -> AuthResult<()> {
            use better_auth_core::store::CacheAdapter as _;
            self.cache.delete(key).await
        }
    }
    #[derive(Default)]
    struct ApplicationCompletions(std::sync::Mutex<Vec<better_auth_core::BackgroundTaskCompletion>>);
    impl better_auth_core::BackgroundTaskHandler for ApplicationCompletions {
        fn handle(&self, completion: better_auth_core::BackgroundTaskCompletion) -> AuthResult<()> {
            self.0.lock().unwrap().push(completion);
            Ok(())
        }
    }
    impl ApplicationCompletions {
        async fn drain(&self) {
            let tasks = std::mem::take(&mut *self.0.lock().unwrap());
            for task in tasks {
                task.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn application_storage_preserves_authority_indexes_and_usage() {
        use better_auth_core::store::{CacheAdapter, MemoryCacheAdapter};
        // HTTP creation and trusted verification use the real plugin and stores;
        // independent database reads prove secondary-only keys create no SQL rows.
        for (fallback, custom, deferred) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (true, true, false),
            (false, true, true),
            (true, true, true),
        ] {
            let (mut ctx, owner, token) = context().await;
            let completions = Arc::new(ApplicationCompletions::default());
            Arc::make_mut(&mut ctx.config).background_tasks = Some(completions.clone());
            let outsider = ctx
                .database
                .create_user(
                    CreateUser::new()
                        .with_email("outsider@example.com")
                        .with_name("outsider"),
                )
                .await
                .unwrap();
            let cache = Arc::new(MemoryCacheAdapter::new());
            let decoy = Arc::new(MemoryCacheAdapter::new());
            let application = Arc::new(ApplicationKeyStorage {
                cache: cache.clone(),
                fail_writes: std::sync::atomic::AtomicBool::new(false),
            });
            let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
                storage: ApiKeyStorageMode::SecondaryStorage,
                secondary_storage: Some(
                    if custom { decoy.clone() } else { cache.clone() } as Arc<dyn CacheAdapter>
                ),
                custom_storage: custom.then(|| application.clone() as Arc<dyn ApiKeyStorage>),
                fallback_to_database: fallback,
                defer_updates: deferred,
                rate_limit: RateLimitDefaults {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            });
            let response = plugin
                .handle_create(
                    &request(&token, "/api-key/create", &json!({"name":"stored"})),
                    &ctx,
                )
                .await
                .unwrap();
            let created: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            let id = created.get("id").unwrap().as_str().unwrap();
            let raw = created.get("key").unwrap().as_str().unwrap();
            plugin
                .update_key(
                    &ctx,
                    &UpdateKeyRequest {
                        key_id: id.to_owned(),
                        user_id: Some(owner.clone()),
                        remaining: Some(2.0),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let hash = ApiKeyPlugin::hash_key(raw);
            let by_id = format!("api-key:by-id:{id}");
            let by_hash = format!("api-key:{hash}");
            let by_ref = format!("api-key:by-ref:{owner}");
            let initial = cache.get(&by_id).await.unwrap().unwrap();
            assert_eq!(cache.get(&by_hash).await.unwrap(), Some(initial.clone()));
            assert_eq!(
                ctx.database.get_api_key_by_id(id).await.unwrap().is_some(),
                fallback
            );
            assert_eq!(cache.get(&by_ref).await.unwrap().is_none(), fallback);
            assert!(
                get_key_core(id, None, &outsider.id().to_string(), &plugin, &ctx)
                    .await
                    .is_err()
            );
            assert_eq!(cache.get(&by_id).await.unwrap(), Some(initial.clone()));
            assert!(
                plugin
                    .verify_api_key(
                        &VerifyApiKey {
                            key: raw,
                            config_id: Some("wrong"),
                            permissions: None
                        },
                        &ctx
                    )
                    .await
                    .is_err()
            );
            assert_eq!(cache.get(&by_id).await.unwrap(), Some(initial));
            let list = list_keys_core(&owner, &ListKeysQuery::default(), &plugin, &ctx)
                .await
                .unwrap();
            assert_eq!(list.total, 1);
            let input = VerifyApiKey {
                key: raw,
                config_id: None,
                permissions: None,
            };
            assert_eq!(
                plugin.verify_api_key(&input, &ctx).await.unwrap().remaining,
                Some(1.0)
            );
            completions.drain().await;
            assert!(decoy.get(&by_id).await.unwrap().is_none());
            let row: better_auth_core::ApiKey =
                serde_json::from_str(&cache.get(&by_id).await.unwrap().unwrap()).unwrap();
            assert_eq!(row.remaining, Some(1.0));
            assert_eq!(row.reference_id, owner);
            assert_eq!(
                cache.get(&by_hash).await.unwrap(),
                cache.get(&by_id).await.unwrap()
            );
            if fallback {
                let persisted = ctx.database.get_api_key_by_id(id).await.unwrap().unwrap();
                assert_eq!(
                    serde_json::to_value(&persisted).unwrap(),
                    serde_json::to_value(&row).unwrap()
                );
                cache.delete(&by_id).await.unwrap();
                cache.delete(&by_hash).await.unwrap();
                assert_eq!(
                    get_key_core(id, None, &owner, &plugin, &ctx)
                        .await
                        .unwrap()
                        .remaining,
                    Some(1.0)
                );
                assert_eq!(
                    cache.get(&by_hash).await.unwrap(),
                    cache.get(&by_id).await.unwrap()
                );
            }
            assert_eq!(
                plugin.verify_api_key(&input, &ctx).await.unwrap().remaining,
                Some(0.0)
            );
            completions.drain().await;
            assert!(plugin.verify_api_key(&input, &ctx).await.is_err());
            completions.drain().await;
            assert!(cache.get(&by_id).await.unwrap().is_none());
            assert!(cache.get(&by_hash).await.unwrap().is_none());
            assert!(cache.get(&by_ref).await.unwrap().is_none());
            assert!(ctx.database.get_api_key_by_id(id).await.unwrap().is_none());
            if custom {
                let target = plugin
                    .create_key(
                        &ctx,
                        &CreateKeyRequest {
                            user_id: Some(owner.clone()),
                            remaining: Some(4.0),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                let raw = target.key.as_str();
                let key_id = &target.api_key.id;
                let id_index = format!("api-key:by-id:{key_id}");
                let hash_index = format!("api-key:{}", ApiKeyPlugin::hash_key(raw));
                let before = cache.get(&id_index).await.unwrap();
                application
                    .fail_writes
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                let input = VerifyApiKey {
                    key: raw,
                    config_id: None,
                    permissions: None,
                };
                let failed = plugin.verify_api_key(&input, &ctx).await;
                assert_eq!(failed.is_ok(), deferred && !fallback);
                completions.drain().await;
                assert_eq!(cache.get(&id_index).await.unwrap(), before);
                assert_eq!(cache.get(&hash_index).await.unwrap(), before);
                if fallback {
                    assert_eq!(
                        ctx.database
                            .get_api_key_by_id(key_id)
                            .await
                            .unwrap()
                            .unwrap()
                            .remaining,
                        Some(3.0)
                    );
                } else {
                    assert!(
                        ctx.database
                            .get_api_key_by_id(key_id)
                            .await
                            .unwrap()
                            .is_none()
                    );
                }
                application
                    .fail_writes
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                let retried = plugin.verify_api_key(&input, &ctx).await.unwrap();
                assert_eq!(retried.remaining, Some(if fallback { 2.0 } else { 3.0 }));
                completions.drain().await;
                assert_eq!(
                    cache.get(&hash_index).await.unwrap(),
                    cache.get(&id_index).await.unwrap()
                );
                let row: better_auth_core::ApiKey =
                    serde_json::from_str(&cache.get(&id_index).await.unwrap().unwrap()).unwrap();
                assert_eq!(row.remaining, retried.remaining);
            }
        }
    }
}
// LCOV_EXCL_STOP
