use super::CacheAdapter;
use crate::error::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::Duration;
use redis::{Client, Commands, Connection, RedisError};

pub struct RedisAdapter {
    client: Client,
}

impl std::fmt::Debug for RedisAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisAdapter").finish_non_exhaustive()
    }
}

fn failed(action: &str, error: &RedisError) -> AuthError {
    AuthError::internal(format!("Redis {action} error: {error}"))
}

impl RedisAdapter {
    /// Create a Redis cache adapter from a URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the Redis URL is invalid.
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "preserve the public async constructor API"
    )]
    pub async fn new(redis_url: &str) -> Result<Self, RedisError> {
        let client = Client::open(redis_url)?;
        Ok(Self { client })
    }

    fn connection(&self) -> AuthResult<Connection> {
        self.client
            .get_connection()
            .map_err(|error| AuthError::internal(format!("Redis connection error: {error}")))
    }
}

#[async_trait]
impl CacheAdapter for RedisAdapter {
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
        let mut conn = self.connection()?;
        let seconds = u64::try_from(expires_in.num_seconds())
            .map_err(|_| AuthError::internal("Redis set_ex requires non-negative TTL"))?;
        conn.set_ex::<_, _, ()>(key, value, seconds)
            .map_err(|error| failed("set", &error))
    }

    async fn set_without_expiry(&self, key: &str, value: &str) -> AuthResult<()> {
        self.connection()?
            .set::<_, _, ()>(key, value)
            .map_err(|error| failed("set", &error))
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.connection()?
            .get(key)
            .map_err(|error| failed("get", &error))
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        _ = self
            .connection()?
            .del::<_, usize>(key)
            .map_err(|error| failed("delete", &error))?;
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<String>> {
        let mut conn = self.connection()?;
        // GETDEL requires Redis 6.2; a single script preserves the same
        // atomic contract on supported older Redis deployments as well.
        redis::Script::new(
            "local value = redis.call('GET', KEYS[1]); redis.call('DEL', KEYS[1]); return value",
        )
        .key(key)
        .invoke(&mut conn)
        .map_err(|error| failed("consume", &error))
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
        redis::Script::new(
            "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count",
        )
        .key(key)
        .arg(expires_in.as_secs())
        .invoke(&mut connection)
        .map_err(|_| AuthError::internal("Redis counter increment failed"))
    }

    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.connection()?
            .exists(key)
            .map_err(|error| failed("exists", &error))
    }

    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
        _ = self
            .connection()?
            .expire::<_, bool>(key, expires_in.num_seconds())
            .map_err(|error| failed("expire", &error))?;
        Ok(())
    }

    async fn clear(&self) -> AuthResult<()> {
        redis::cmd("FLUSHDB")
            .query::<()>(&mut self.connection()?)
            .map_err(|error| failed("flushdb", &error))
    }
}
