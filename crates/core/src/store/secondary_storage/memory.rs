use super::CacheAdapter;
use crate::error::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// In-memory cache adapter for testing and development
pub struct MemoryCacheAdapter {
    data: Mutex<HashMap<String, CacheEntry>>,
}

impl std::fmt::Debug for MemoryCacheAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCacheAdapter").finish_non_exhaustive()
    }
}

struct CacheEntry {
    value: String,
    expires_at: Option<DateTime<Utc>>,
}

impl CacheEntry {
    fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expiration| expiration > now)
    }
}

impl MemoryCacheAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Mutex::default(),
        }
    }

    fn lock(&self) -> AuthResult<MutexGuard<'_, HashMap<String, CacheEntry>>> {
        self.data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))
    }

    fn cleanup_expired(&self) {
        if let Ok(mut data) = self.data.lock() {
            let now = Utc::now();
            data.retain(|_, entry| entry.is_live(now));
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
        let entry = CacheEntry {
            value: value.to_owned(),
            expires_at: Some(Utc::now() + expires_in),
        };
        _ = self.lock()?.insert(key.to_owned(), entry);
        Ok(())
    }

    async fn set_without_expiry(&self, key: &str, value: &str) -> AuthResult<()> {
        let entry = CacheEntry {
            value: value.to_owned(),
            expires_at: None,
        };
        _ = self.lock()?.insert(key.to_owned(), entry);
        Ok(())
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cleanup_expired();
        let now = Utc::now();
        Ok(self
            .lock()?
            .get(key)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.value.clone()))
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        _ = self.lock()?.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<String>> {
        Ok(self
            .lock()?
            .remove(key)
            .filter(|entry| entry.is_live(Utc::now()))
            .map(|entry| entry.value))
    }

    async fn increment(&self, key: &str, expires_in: std::time::Duration) -> AuthResult<f64> {
        let now = Utc::now();
        let duration = Duration::from_std(expires_in)
            .map_err(|_| AuthError::internal("Cache counter TTL is too large"))?;
        let expires_at = now
            .checked_add_signed(duration)
            .ok_or_else(|| AuthError::internal("Cache counter TTL is too large"))?;
        let mut data = self.lock()?;
        if let Some(entry) = data.get_mut(key).filter(|entry| entry.is_live(now)) {
            let count =
                entry.value.parse::<f64>().map_err(|_| {
                    AuthError::internal("Cache counter contains a non-numeric value")
                })? + 1.0;
            entry.value = count.to_string();
            return Ok(count);
        }
        _ = data.insert(
            key.to_owned(),
            CacheEntry {
                value: "1".to_owned(),
                expires_at: Some(expires_at),
            },
        );
        Ok(1.0)
    }

    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cleanup_expired();
        let now = Utc::now();
        Ok(self
            .lock()?
            .get(key)
            .is_some_and(|entry| entry.is_live(now)))
    }

    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
        if let Some(entry) = self.lock()?.get_mut(key) {
            entry.expires_at = Some(Utc::now() + expires_in);
        }
        Ok(())
    }

    async fn clear(&self) -> AuthResult<()> {
        self.lock()?.clear();
        Ok(())
    }
}
