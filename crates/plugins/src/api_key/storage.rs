use super::{ApiKeyConfig, ApiKeyPlugin};
use alibi_core::store::CacheAdapter;
use alibi_core::{
    ApiKey, AuthContext, AuthError, AuthResult, AuthSchema, CreateApiKey, UpdateApiKey,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// API-key persistence policy. Secondary-only admission is a non-atomic merge;
/// use database fallback for durable, guarded quota and rate-limit admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApiKeyStorageMode {
    #[default]
    Database,
    SecondaryStorage,
}

/// Application-owned serialized API-key storage. `None` TTL means permanent.
/// Implementations must propagate failures; these operations are not atomic admission.
#[async_trait]
pub trait ApiKeyStorage: Send + Sync {
    async fn get(&self, key: &str) -> AuthResult<Option<String>>;
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> AuthResult<()>;
    async fn delete(&self, key: &str) -> AuthResult<()>;
}

struct CacheStorage(Arc<dyn CacheAdapter>);
#[async_trait]
impl ApiKeyStorage for CacheStorage {
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.0.get(key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> AuthResult<()> {
        match ttl {
            Some(ttl) => self.0.set(key, value, ttl).await,
            None => self.0.set_without_expiry(key, value).await,
        }
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.0.delete(key).await
    }
}

impl ApiKeyConfig {
    pub(super) fn secondary(&self) -> Option<Arc<dyn ApiKeyStorage>> {
        self.custom_storage.clone().or_else(|| {
            self.secondary_storage
                .as_ref()
                .map(|cache| Arc::new(CacheStorage(Arc::clone(cache))) as Arc<dyn ApiKeyStorage>)
        })
    }
    pub(super) fn uses_database(&self) -> bool {
        self.storage == ApiKeyStorageMode::Database || self.fallback_to_database
    }
    pub(crate) async fn read_key(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        value: &str,
        by_hash: bool,
    ) -> AuthResult<Option<ApiKey>> {
        if self.storage == ApiKeyStorageMode::SecondaryStorage
            && let Some(storage) = self.secondary()
            && let Some(key) = read_storage(storage.as_ref(), value, by_hash).await?
        {
            return Ok(Some(key));
        }
        if !self.uses_database() {
            return Ok(None);
        }
        let key = if by_hash {
            ctx.database.get_api_key_by_hash(value).await?
        } else {
            ctx.database.get_api_key_by_id(value).await?
        };
        if let Some(key) = &key
            && self.secondary().is_some()
        {
            self.cache_key(key).await?;
        }
        Ok(key)
    }
    pub(super) async fn cache_key(&self, key: &ApiKey) -> AuthResult<()> {
        if self.storage == ApiKeyStorageMode::Database {
            return Ok(());
        }
        let storage = self
            .secondary()
            .ok_or_else(|| AuthError::internal("Secondary storage is required"))?;
        write_storage(storage, key, self.fallback_to_database).await
    }
    pub(super) async fn remove_key(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        key: &ApiKey,
    ) -> AuthResult<()> {
        if self.storage == ApiKeyStorageMode::SecondaryStorage {
            let storage = self
                .secondary()
                .ok_or_else(|| AuthError::internal("Secondary storage is required"))?;
            remove_storage(storage, key, self.fallback_to_database).await?;
        }
        if self.uses_database() {
            ctx.database.delete_api_key(&key.id).await?;
        }
        Ok(())
    }
    pub(super) async fn create_stored_key(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        input: CreateApiKey,
    ) -> AuthResult<ApiKey> {
        let key = if self.uses_database() {
            ctx.database.create_api_key(input).await?
        } else {
            let now = timestamp();
            ApiKey {
                id: uuid::Uuid::new_v4().to_string(),
                name: input.name,
                start: input
                    .start
                    .map(|start| String::from_utf16(start.as_utf16()))
                    .transpose()
                    .map_err(|_| AuthError::internal("Invalid UTF-16 starting characters"))?,
                prefix: input.prefix,
                key_hash: input.key_hash,
                reference_id: input.reference_id,
                config_id: input.config_id,
                refill_interval: input.refill_interval,
                refill_amount: input.refill_amount,
                last_refill_at: None,
                enabled: input.enabled,
                rate_limit_enabled: input.rate_limit_enabled,
                rate_limit_time_window: input.rate_limit_time_window,
                rate_limit_max: input.rate_limit_max,
                request_count: Some(0.0),
                remaining: input.remaining,
                last_request: None,
                expires_at: input.expires_at,
                created_at: now.clone(),
                updated_at: now,
                permissions: input.permissions,
                metadata: input.metadata,
            }
        };
        self.cache_key(&key).await?;
        Ok(key)
    }
    pub(super) async fn update_stored_key(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        id: &str,
        update: UpdateApiKey,
    ) -> AuthResult<ApiKey> {
        let key = if self.uses_database() {
            ctx.database.update_api_key(id, update).await?
        } else {
            let mut key = self
                .read_key(ctx, id, false)
                .await?
                .ok_or_else(|| AuthError::not_found("API Key not found"))?;
            macro_rules! assign { ($($field:ident),*) => { $(if let Some(value) = update.$field { key.$field = Some(value); })* }; }
            assign!(
                name,
                remaining,
                rate_limit_time_window,
                rate_limit_max,
                refill_interval,
                refill_amount,
                permissions,
                metadata,
                request_count
            );
            if let Some(value) = update.enabled {
                key.enabled = value;
            }
            if let Some(value) = update.rate_limit_enabled {
                key.rate_limit_enabled = value;
            }
            if let Some(value) = update.expires_at {
                key.expires_at = value;
            }
            if let Some(value) = update.last_request {
                key.last_request = value;
            }
            if let Some(value) = update.last_refill_at {
                key.last_refill_at = value;
            }
            key.updated_at = timestamp();
            key
        };
        self.cache_key(&key).await?;
        Ok(key)
    }
    pub(super) async fn list_stored_keys(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        reference: &str,
        sort_by: Option<&str>,
        sort_direction: Option<&str>,
    ) -> AuthResult<Vec<ApiKey>> {
        let sorted = |mut keys: Vec<ApiKey>, from_database| {
            if let Some(sort_by) = sort_by {
                super::handlers::sort_keys(&mut keys, sort_by, sort_direction, from_database)?;
            }
            Ok(keys)
        };
        if self.storage == ApiKeyStorageMode::Database {
            return sorted(
                ctx.database.list_api_keys_by_reference(reference).await?,
                true,
            );
        }
        let storage = self.secondary();
        if let Some(storage) = &storage {
            let ids = reference_ids(storage.as_ref(), reference).await?;
            if !ids.is_empty() {
                let storage = Arc::clone(storage);
                let keys = storage_map(ids, move |id| {
                    let storage = Arc::clone(&storage);
                    async move { read_storage(storage.as_ref(), &id, false).await }
                })
                .await?;
                return sorted(keys.into_iter().flatten().collect(), false);
            }
        }
        if !self.fallback_to_database {
            return Ok(Vec::new());
        }
        let keys = sorted(
            ctx.database.list_api_keys_by_reference(reference).await?,
            true,
        )?;
        if let Some(storage) = storage
            && !keys.is_empty()
        {
            let cache = Arc::clone(&storage);
            _ = storage_map(keys.clone(), move |key| {
                let storage = Arc::clone(&cache);
                async move { write_storage(storage, &key, true).await }
            })
            .await?;
            let ids: Vec<_> = keys.iter().map(|key| &key.id).collect();
            storage
                .set(&ref_index(reference), &serde_json::to_string(&ids)?, None)
                .await?;
        }
        Ok(keys)
    }
}

impl ApiKeyPlugin {
    pub(super) async fn list_storage_keys(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        reference: &str,
        sort_by: Option<&str>,
        sort_direction: Option<&str>,
    ) -> AuthResult<Vec<ApiKey>> {
        let mut operations = Vec::new();
        let mut stores = std::collections::HashSet::new();
        for config in &self.configurations {
            let identifier = if config.storage == ApiKeyStorageMode::Database {
                "database".to_owned()
            } else if config.custom_storage.is_some() {
                format!("custom:{}", config.config_id)
            } else {
                format!(
                    "secondary:{:p}:{}",
                    config
                        .secondary_storage
                        .as_ref()
                        .map_or(std::ptr::null::<()>(), |storage| Arc::as_ptr(storage)
                            .cast::<()>()),
                    config.fallback_to_database
                )
            };
            if stores.insert(identifier) {
                let config = config.clone();
                let reference = reference.to_owned();
                let context = AuthContext {
                    config: Arc::clone(&ctx.config),
                    database: Arc::clone(&ctx.database),
                    email_provider: ctx.email_provider.clone(),
                    metadata: ctx.metadata.clone(),
                    extensions: ctx.extensions.clone(),
                };
                let sort_by = sort_by.map(str::to_owned);
                let sort_direction = sort_direction.map(str::to_owned);
                operations.push(start_storage_task(async move {
                    config
                        .list_stored_keys(
                            &context,
                            &reference,
                            sort_by.as_deref(),
                            sort_direction.as_deref(),
                        )
                        .await
                }));
            }
        }
        let groups = storage_results(operations).await?;
        let mut keys = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for group in groups {
            for key in group {
                if seen.insert(key.id.clone()) {
                    keys.push(key);
                }
            }
        }
        Ok(keys)
    }
}

pub(super) fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn hash_index(hash: &str) -> String {
    format!("api-key:{hash}")
}
fn id_index(id: &str) -> String {
    format!("api-key:by-id:{id}")
}
fn ref_index(reference: &str) -> String {
    format!("api-key:by-ref:{reference}")
}
pub(super) async fn read_storage(
    storage: &dyn ApiKeyStorage,
    value: &str,
    by_hash: bool,
) -> AuthResult<Option<ApiKey>> {
    let index = if by_hash {
        hash_index(value)
    } else {
        id_index(value)
    };
    let Some(data) = storage.get(&index).await? else {
        return Ok(None);
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&data) else {
        return Ok(None);
    };
    if let Some(metadata) = value.get_mut("metadata")
        && !metadata.is_null()
    {
        *metadata = serde_json::Value::String(serde_json::to_string(metadata)?);
    }
    Ok(serde_json::from_value(value).ok())
}
pub(super) async fn write_storage(
    storage: Arc<dyn ApiKeyStorage>,
    key: &ApiKey,
    fallback: bool,
) -> AuthResult<()> {
    let ttl = key
        .expires_at
        .as_deref()
        .and_then(|date| chrono::DateTime::parse_from_rfc3339(date).ok())
        .map(|date| date.signed_duration_since(Utc::now()).num_seconds())
        .filter(|seconds| *seconds > 0)
        .map(Duration::seconds);
    let mut value = serde_json::to_value(key)?;
    let fields = value
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Invalid API key"))?;
    _ = fields.insert(
        "metadata".to_owned(),
        key.metadata
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or(serde_json::Value::Null),
    );
    if !fallback && key.permissions.is_none() {
        _ = fields.remove("permissions");
    }
    let data = serde_json::to_string(&value)?;
    let hash = hash_index(&key.key_hash);
    let id = id_index(&key.id);
    let mut operations = vec![
        spawn_set(Arc::clone(&storage), hash, data.clone(), ttl),
        spawn_set(Arc::clone(&storage), id, data, ttl),
    ];
    if fallback {
        operations.push(spawn_delete(
            Arc::clone(&storage),
            ref_index(&key.reference_id),
        ));
    }
    _ = storage_results(operations).await?;
    if fallback {
        Ok(())
    } else {
        modify_reference(storage.as_ref(), &key.reference_id, &key.id, true).await
    }
}

type StorageTask<T> = (
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<AuthResult<T>>,
);
fn start_storage_task<T: Send + 'static>(
    operation: impl std::future::Future<Output = AuthResult<T>> + Send + 'static,
) -> StorageTask<T> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let mut operation = Box::pin(operation);
        let mut sender = Some(sender);
        std::future::poll_fn(|context| {
            let result = operation.as_mut().poll(context);
            if let Some(sender) = sender.take() {
                let _ = sender.send(());
            }
            result
        })
        .await
    });
    (receiver, handle)
}
fn spawn_set(
    storage: Arc<dyn ApiKeyStorage>,
    index: String,
    value: String,
    ttl: Option<Duration>,
) -> StorageTask<()> {
    start_storage_task(async move { storage.set(&index, &value, ttl).await })
}
fn spawn_delete(storage: Arc<dyn ApiKeyStorage>, index: String) -> StorageTask<()> {
    start_storage_task(async move { storage.delete(&index).await })
}
async fn storage_results<T: Send + 'static>(operations: Vec<StorageTask<T>>) -> AuthResult<Vec<T>> {
    use futures_util::StreamExt as _;
    // Source Promise.all starts every IO, then rejects on the first failure;
    // the other initiated operations continue. First-poll acknowledgements
    // preserve initiation, and dropped JoinHandles detach instead of cancel.
    let mut results: Vec<Option<T>> = std::iter::repeat_with(|| None)
        .take(operations.len())
        .collect();
    let pending = futures_util::stream::FuturesUnordered::new();
    for (index, (started, handle)) in operations.into_iter().enumerate() {
        started
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        pending.push(async move {
            handle
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .map(|value| (index, value))
        });
    }
    let mut pending = pending;
    while let Some(result) = pending.next().await {
        let (index, value) = result?;
        *results
            .get_mut(index)
            .ok_or_else(|| AuthError::internal("Invalid storage result index"))? = Some(value);
    }
    Ok(results.into_iter().flatten().collect())
}
async fn storage_map<T, R, F, Fut>(items: Vec<T>, mapper: F) -> AuthResult<Vec<R>>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = AuthResult<R>> + Send + 'static,
{
    use futures_util::StreamExt as _;
    let mut results: Vec<Option<R>> = std::iter::repeat_with(|| None).take(items.len()).collect();
    let mut items = items.into_iter().enumerate();
    let mapper = Arc::new(mapper);
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let launch = |(index, item)| {
        let mapper = Arc::clone(&mapper);
        let failed = Arc::clone(&failed);
        start_storage_task(async move {
            match mapper(item).await {
                Ok(value) => Ok((index, value)),
                Err(error) => {
                    failed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err(error)
                }
            }
        })
    };
    let mut pending = futures_util::stream::FuturesUnordered::new();
    let initial: Vec<_> = items.by_ref().take(10).map(&launch).collect();
    for (started, handle) in initial {
        started
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        pending.push(handle);
    }
    while let Some(result) = pending.next().await {
        let (index, value) = result.map_err(|error| AuthError::internal(error.to_string()))??;
        *results
            .get_mut(index)
            .ok_or_else(|| AuthError::internal("Invalid storage result index"))? = Some(value);
        if !failed.load(std::sync::atomic::Ordering::SeqCst)
            && let Some(item) = items.next()
        {
            let (started, handle) = launch(item);
            started
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            pending.push(handle);
        }
    }
    Ok(results.into_iter().flatten().collect())
}
async fn reference_ids(storage: &dyn ApiKeyStorage, reference: &str) -> AuthResult<Vec<String>> {
    Ok(storage
        .get(&ref_index(reference))
        .await?
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default())
}
async fn modify_reference(
    storage: &dyn ApiKeyStorage,
    reference: &str,
    id: &str,
    add: bool,
) -> AuthResult<()> {
    static LOCKS: OnceLock<
        tokio::sync::Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    > = OnceLock::new();
    let index = ref_index(reference);
    let lock = {
        let mut locks = LOCKS.get_or_init(Default::default).lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&index).and_then(std::sync::Weak::upgrade) {
            lock
        } else {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            _ = locks.insert(index.clone(), Arc::downgrade(&lock));
            lock
        }
    };
    let _guard = lock.lock().await;
    let mut ids = reference_ids(storage, reference).await?;
    if add {
        if !ids.iter().any(|value| value == id) {
            ids.push(id.to_owned());
        }
    } else {
        ids.retain(|value| value != id);
    }
    if ids.is_empty() {
        storage.delete(&index).await
    } else {
        storage
            .set(&index, &serde_json::to_string(&ids)?, None)
            .await
    }
}

pub(super) async fn remove_storage(
    storage: Arc<dyn ApiKeyStorage>,
    key: &ApiKey,
    fallback: bool,
) -> AuthResult<()> {
    let hash = hash_index(&key.key_hash);
    let id = id_index(&key.id);
    let reference = ref_index(&key.reference_id);
    let mut operations = vec![
        spawn_delete(Arc::clone(&storage), hash),
        spawn_delete(Arc::clone(&storage), id),
    ];
    if fallback {
        operations.push(spawn_delete(storage, reference));
    } else {
        let reference = key.reference_id.clone();
        let id = key.id.clone();
        operations.push(start_storage_task(async move {
            modify_reference(storage.as_ref(), &reference, &id, false).await
        }));
    }
    storage_results(operations).await.map(|_| ())
}
