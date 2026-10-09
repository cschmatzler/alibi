mod memory;
#[cfg(feature = "redis-cache")]
mod redis_adapter;

use crate::error::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::Duration;
pub use memory::MemoryCacheAdapter;
#[cfg(feature = "redis-cache")]
pub use redis_adapter::RedisAdapter;

/// Cache adapter trait for session caching
#[async_trait]
pub trait CacheAdapter: Send + Sync {
    /// Set a value with expiration
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()>;

    /// Persist a value without expiration. Adapters must explicitly support this capability.
    async fn set_without_expiry(&self, _key: &str, _value: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "persistent cache writes are unsupported by this adapter",
        ))
    }

    /// Get a value by key
    async fn get(&self, key: &str) -> AuthResult<Option<String>>;

    /// Atomically fetch and remove a value. A read followed by a separate
    /// delete does not satisfy single-use token semantics.
    async fn get_and_delete(&self, _key: &str) -> AuthResult<Option<String>> {
        Err(AuthError::internal(
            "atomic cache consumption is not supported by this adapter",
        ))
    }

    /// Atomically increment a counter, setting its TTL only on creation.
    /// Existing TTLs must not be extended by admitted or rejected requests.
    async fn increment(&self, _key: &str, _expires_in: std::time::Duration) -> AuthResult<f64> {
        Err(AuthError::internal(
            "atomic cache increment is not supported by this adapter",
        ))
    }

    /// Delete a value by key
    async fn delete(&self, key: &str) -> AuthResult<()>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> AuthResult<bool>;

    /// Set expiration for a key
    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()>;

    /// Clear all cached values
    async fn clear(&self) -> AuthResult<()>;
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tokio::task::JoinSet;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn atomic_cache_consumption_has_one_winner_and_rejects_expired_values() -> AuthResult<()>
    {
        let cache = Arc::new(MemoryCacheAdapter::new());
        cache.set_without_expiry("token", "single-use").await?;
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = JoinSet::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            _ = tasks.spawn(async move {
                _ = barrier.wait().await;
                cache.get_and_delete("token").await
            });
        }
        let mut winners = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Some(value) =
                result.map_err(|error| AuthError::internal(error.to_string()))??
            {
                winners.push(value);
            }
        }
        assert_eq!(winners, ["single-use"]);
        assert!(cache.get_and_delete("token").await?.is_none());
        cache
            .set("expired", "expired-value", Duration::seconds(-1))
            .await?;
        assert!(cache.get_and_delete("expired").await?.is_none());
        assert!(!cache.exists("expired").await?);
        cache.set_without_expiry("expired", "renewed").await?;
        assert!(cache.exists("expired").await?);
        assert_eq!(cache.get("expired").await?.as_deref(), Some("renewed"));
        cache.expire("expired", Duration::seconds(-1)).await?;
        assert!(cache.get_and_delete("expired").await?.is_none());
        let ttl = std::time::Duration::from_secs(60);
        assert_eq!(cache.increment("counter", ttl).await?, 1.0);
        assert_eq!(
            cache
                .increment("counter", std::time::Duration::ZERO)
                .await?,
            2.0
        );
        assert_eq!(cache.get("counter").await?.as_deref(), Some("2"));
        cache.set_without_expiry("corrupt", "not-a-number").await?;
        assert!(cache.increment("corrupt", ttl).await.is_err());
        assert_eq!(cache.get("corrupt").await?.as_deref(), Some("not-a-number"));
        cache.expire("counter", Duration::seconds(-1)).await?;
        assert_eq!(cache.increment("counter", ttl).await?, 1.0);
        Ok(())
    }
}
// LCOV_EXCL_STOP
