#[cfg(feature = "redis-cache")]
pub mod redis_adapter {
    use super::{AuthResult, CacheAdapter, Duration, async_trait};
    use crate::error::AuthError;
    use redis::{Client, Commands};

    pub struct RedisAdapter {
        client: Client,
    }

    impl std::fmt::Debug for RedisAdapter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisAdapter").finish_non_exhaustive()
        }
    }

    impl RedisAdapter {
        #[expect(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "preserve the public async constructor API"
        )]
        /// Create a Redis cache adapter from a URL.
        ///
        /// # Errors
        ///
        /// Returns an error when the Redis URL is invalid.
        pub async fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
            let client = Client::open(redis_url)?;
            Ok(Self { client })
        }
    }

    #[async_trait]
    impl CacheAdapter for RedisAdapter {
        async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {e}")))?;

            let seconds = u64::try_from(expires_in.num_seconds())
                .map_err(|_error| AuthError::internal("Redis set_ex requires non-negative TTL"))?;
            conn.set_ex::<_, _, ()>(key, value, seconds)
                .map_err(|e| AuthError::internal(format!("Redis set error: {e}")))?;

            Ok(())
        }

        async fn get(&self, key: &str) -> AuthResult<Option<String>> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {e}")))?;

            let result: Option<String> = conn
                .get(key)
                .map_err(|e| AuthError::internal(format!("Redis get error: {e}")))?;

            Ok(result)
        }

        async fn delete(&self, key: &str) -> AuthResult<()> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {e}")))?;

            _ = conn
                .del::<_, usize>(key)
                .map_err(|e| AuthError::internal(format!("Redis delete error: {e}")))?;

            Ok(())
        }

        async fn get_and_delete(&self, key: &str) -> AuthResult<Option<String>> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|error| AuthError::internal(format!("Redis connection error: {error}")))?;
            // GETDEL requires Redis 6.2; a single script preserves the same
            // atomic contract on supported older Redis deployments as well.
            redis::Script::new("local value = redis.call('GET', KEYS[1]); redis.call('DEL', KEYS[1]); return value")
                .key(key)
                .invoke(&mut conn)
                .map_err(|error| AuthError::internal(format!("Redis consume error: {error}")))
        }

        async fn increment(&self, key: &str, expires_in: std::time::Duration) -> AuthResult<f64> {
            if expires_in.is_zero() || expires_in.subsec_nanos() != 0 {
                return Err(AuthError::internal(
                    "Redis counter TTL must be a positive integer number of seconds",
                ));
            }
            let mut connection = self
                .client
                .get_connection()
                .map_err(|_| AuthError::internal("Redis counter connection failed"))?;
            redis::Script::new("local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count")
                .key(key).arg(expires_in.as_secs()).invoke(&mut connection)
                .map_err(|_| AuthError::internal("Redis counter increment failed"))
        }

        async fn exists(&self, key: &str) -> AuthResult<bool> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {e}")))?;

            let exists: bool = conn
                .exists(key)
                .map_err(|e| AuthError::internal(format!("Redis exists error: {e}")))?;

            Ok(exists)
        }

        async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {e}")))?;

            let seconds = expires_in.num_seconds();
            _ = conn
                .expire::<_, bool>(key, seconds)
                .map_err(|e| AuthError::internal(format!("Redis expire error: {e}")))?;

            Ok(())
        }

        async fn clear(&self) -> AuthResult<()> {
            let mut conn = self
                .client
                .get_connection()
                .map_err(|e| AuthError::internal(format!("Redis connection error: {e}")))?;

            redis::cmd("FLUSHDB")
                .query::<()>(&mut conn)
                .map_err(|e| AuthError::internal(format!("Redis flushdb error: {e}")))?;

            Ok(())
        }
    }
}

use crate::error::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
#[cfg(feature = "redis-cache")]
pub use redis_adapter::RedisAdapter;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Cache adapter trait for session caching
#[async_trait]
pub trait CacheAdapter: Send + Sync {
    /// Set a value with expiration
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()>;

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

/// In-memory cache adapter for testing and development
pub struct MemoryCacheAdapter {
    data: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl std::fmt::Debug for MemoryCacheAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCacheAdapter").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: String,
    expires_at: DateTime<Utc>,
}

impl MemoryCacheAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Clean up expired entries
    fn cleanup_expired(&self) {
        if let Ok(mut data) = self.data.lock() {
            let now = Utc::now();
            data.retain(|_, entry| entry.expires_at > now);
        }
    }
}

impl Default for MemoryCacheAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheAdapter for MemoryCacheAdapter {
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
        self.cleanup_expired();

        let expires_at = Utc::now() + expires_in;
        let entry = CacheEntry {
            value: value.to_owned(),
            expires_at,
        };

        let mut data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;
        drop(data.insert(key.to_owned(), entry));
        drop(data);

        Ok(())
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now();

        data.get(key).map_or(Ok(None), |entry| {
            if entry.expires_at > now {
                Ok(Some(entry.value.clone()))
            } else {
                Ok(None)
            }
        })
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;
        drop(data.remove(key));
        drop(data);

        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<String>> {
        let mut data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;
        Ok(data
            .remove(key)
            .filter(|entry| entry.expires_at > Utc::now())
            .map(|entry| entry.value))
    }

    async fn increment(&self, key: &str, expires_in: std::time::Duration) -> AuthResult<f64> {
        let now = Utc::now();
        let duration = Duration::from_std(expires_in)
            .map_err(|_| AuthError::internal("Cache counter TTL is too large"))?;
        let expires_at = now
            .checked_add_signed(duration)
            .ok_or_else(|| AuthError::internal("Cache counter TTL is too large"))?;
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        if let Some(entry) = data.get_mut(key).filter(|entry| entry.expires_at > now) {
            let count =
                entry.value.parse::<f64>().map_err(|_| {
                    AuthError::internal("Cache counter contains a non-numeric value")
                })? + 1.0;
            entry.value = count.to_string();
            return Ok(count);
        }
        drop(data.insert(
            key.to_owned(),
            CacheEntry {
                value: "1".to_owned(),
                expires_at,
            },
        ));
        drop(data);
        Ok(1.0)
    }

    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;
        let now = Utc::now();

        data.get(key)
            .map_or(Ok(false), |entry| Ok(entry.expires_at > now))
    }

    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;

        if let Some(entry) = data.get_mut(key) {
            entry.expires_at = Utc::now() + expires_in;
        }
        drop(data);

        Ok(())
    }

    async fn clear(&self) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_error| AuthError::internal("Cache lock poisoned"))?;
        data.clear();
        drop(data);

        Ok(())
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
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
        cache
            .set("token", "single-use", Duration::minutes(1))
            .await?;
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = JoinSet::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            drop(tasks.spawn(async move {
                let _ignored_wait = barrier.wait().await;
                cache.get_and_delete("token").await
            }));
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
        Ok(())
    }
}
// LCOV_EXCL_STOP
