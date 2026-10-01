mod callbacks;

pub(super) mod handlers;

pub(super) mod types;

mod verification;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod crud_tests;

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

    // -- key generation --
    pub key_length: usize,
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
    pub starting_characters_length: usize,
    pub store_starting_characters: bool,

    // -- prefix length validation --
    pub max_prefix_length: usize,
    pub min_prefix_length: usize,

    // -- name validation --
    pub max_name_length: usize,
    pub min_name_length: usize,
    pub require_name: bool,

    // -- metadata --
    pub enable_metadata: bool,

    // -- key expiration --
    pub key_expiration: KeyExpirationConfig,

    // -- rate limit defaults --
    pub rate_limit: RateLimitDefaults,

    // -- session emulation --
    pub enable_session_for_api_keys: bool,
    /// Register automatic cleanup with the application background handler.
    /// Successful trusted verification launches cleanup only when enabled.
    /// Database quota and rate-limit admission remain atomic and awaited.
    pub defer_updates: bool,
}

impl ApiKeyConfig {
    const fn normalized(mut self) -> Self {
        // Upstream resolves defaultKeyLength using JavaScript's `|| 64`.
        if self.key_length == 0 {
            self.key_length = 64;
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
            .field("defer_updates", &self.defer_updates)
            .finish_non_exhaustive()
    }
}

/// Key expiration constraints.
#[derive(Debug, Clone)]
pub struct KeyExpirationConfig {
    /// Default `expiresIn` (in seconds) when none is provided. `None` = no default.
    pub default_expires_in: Option<i64>,
    /// If true, clients cannot set a custom `expiresIn`.
    pub disable_custom_expires_time: bool,
    /// Maximum `expiresIn` in **days**.
    pub max_expires_in: i64,
    /// Minimum `expiresIn` in **days**.
    pub min_expires_in: i64,
}

impl Default for KeyExpirationConfig {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            max_expires_in: 365,
            min_expires_in: 1,
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
            config_id: "default".to_owned(),
            references: ApiKeyReferences::default(),
            key_length: 64,
            prefix: None,
            default_permissions: None,
            custom_key_generator: None,
            default_permissions_callback: None,
            api_key_headers: vec!["x-api-key".to_owned()],
            custom_api_key_getter: None,
            custom_api_key_validator: None,
            disable_key_hashing: false,
            starting_characters_length: 6,
            store_starting_characters: true,
            max_prefix_length: 32,
            min_prefix_length: 1,
            max_name_length: 32,
            min_name_length: 1,
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
        #[builder(default = 64)] key_length: usize,
        prefix: Option<String>,
        default_permissions: Option<ApiKeyPermissions>,
        custom_key_generator: Option<Arc<dyn ApiKeyGenerator>>,
        default_permissions_callback: Option<Arc<dyn ApiKeyDefaultPermissions>>,
        #[builder(default = vec!["x-api-key".to_owned()])] api_key_headers: Vec<String>,
        custom_api_key_getter: Option<Arc<dyn ApiKeyGetter>>,
        custom_api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
        #[builder(default = false)] disable_key_hashing: bool,
        #[builder(default = 6)] starting_characters_length: usize,
        #[builder(default = true)] store_starting_characters: bool,
        #[builder(default = 32)] max_prefix_length: usize,
        #[builder(default = 1)] min_prefix_length: usize,
        #[builder(default = 32)] max_name_length: usize,
        #[builder(default = 1)] min_name_length: usize,
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
    ) -> (String, String, String) {
        // Match TS: generateRandomString(length, "a-z", "A-Z") — alpha only
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut rng = rand::thread_rng();
        let raw: String = (0..config.key_length)
            .map(|_| ALPHABET.choose(&mut rng).copied().map_or('a', char::from))
            .collect();

        let prefix = custom_prefix.or(config.prefix.as_deref()).unwrap_or("");
        let full_key = format!("{prefix}{raw}");

        // TS computes start from the full key (including prefix):
        //   start = key.substring(0, charactersLength)
        let start_len = config.starting_characters_length;
        let units: Vec<_> = full_key.encode_utf16().take(start_len).collect();
        let start = String::from_utf16_lossy(&units);

        let hash = if config.disable_key_hashing {
            full_key.clone()
        } else {
            Self::hash_key(&full_key)
        };

        (full_key, hash, start)
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
        drop(Self::start_expired_cleanup(ctx).await?);
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn register_expired_cleanup(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        let completion = Self::start_expired_cleanup(ctx).await?;
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
            let len = p.encode_utf16().count();
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
            let len = n.encode_utf16().count();
            if len < config.min_name_length || len > config.max_name_length {
                return Err(api_key_error(ApiKeyErrorCode::InvalidNameLength));
            }
        }
        Ok(())
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
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
            if days < cfg.min_expires_in as f64 {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooSmall));
            }
            if days > cfg.max_expires_in as f64 {
                return Err(api_key_error(ApiKeyErrorCode::ExpiresInTooLarge));
            }
            Ok(Some(secs))
        } else {
            Ok(cfg.default_expires_in.map(|seconds| seconds as f64))
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
        let (user, _session) = ctx
            .require_session(req)
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
        let (user, _session) = ctx.require_session(req).await?;
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
        let (user, _session) = ctx.require_session(req).await?;
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
        let (user, _session) = ctx
            .require_session(req)
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
        let (user, _session) = ctx.require_session(req).await?;
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
