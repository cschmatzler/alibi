use crate::{ApiKey, AuthError, AuthResult, CreateApiKey, UpdateApiKey};
use async_trait::async_trait;
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey>;
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>>;
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>>;
    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>>;
    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey>;
    async fn delete_api_key(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_api_keys(&self) -> AuthResult<usize>;

    /// Atomically consume one use of an API key: decrement remaining
    /// (with refill), increment rate-limit counter, and update timestamps.
    ///
    /// All counter mutations are derived from the locked row inside a
    /// transaction, preventing concurrent requests from corrupting counters.
    /// Read-only checks (enabled, expired, permissions) happen before this
    /// call in the plugin layer.
    ///
    /// `global_rate_limit_enabled`: whether the plugin-level rate limiting
    /// is turned on. Per-key settings are read from the locked row.
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult>;

    /// Consume usage from the validated database snapshot with Source write phases.
    /// Quota/refill and rate claims are independently guarded atomic writes;
    /// successful earlier writes survive a later storage failure. Finally touch
    /// `updated_at` and return the current row. This is distinct from the combined
    /// transactional operation above and cannot be supplied by delegating to it.
    async fn consume_api_key_usage_from_snapshot(
        &self,
        _observed: &ApiKey,
        _global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        Err(AuthError::internal(
            "snapshot-aware API key consumption is unsupported by this store",
        ))
    }
}

/// Outcome of an atomic API key usage consumption.
pub enum ConsumeApiKeyResult {
    /// The key was valid and counters were updated. Contains the updated key.
    Allowed(Box<ApiKey>),
    /// The rate limit was exceeded after consuming the request's usage quota.
    RateLimited {
        /// Milliseconds until the current rate-limit window ends.
        try_again_in: f64,
    },
    /// The quota was exhausted. Non-refillable keys at zero quota are deleted.
    UsageExhausted,
}

impl std::fmt::Debug for ConsumeApiKeyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed(..) => f.write_str("ConsumeApiKeyResult::Allowed"),
            Self::RateLimited { .. } => f.write_str("ConsumeApiKeyResult::RateLimited"),
            Self::UsageExhausted => f.write_str("ConsumeApiKeyResult::UsageExhausted"),
        }
    }
}
