use super::entities::api_key::{ActiveModel, Column, Entity};
use super::entities::api_key_start::ApiKeyStart;
use super::{SeaOrmStore, map_db_err, parse_optional_rfc3339};
use crate::schema::AuthSchema;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};
use better_auth_core::types::{ApiKey, CreateApiKey, UpdateApiKey};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, Iterable, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, Set, SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use uuid::Uuid;

#[async_trait]
impl<S> ApiKeyStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn consume_api_key_usage_from_snapshot(
        &self,
        observed: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        self.consume_usage_phases(observed, global_rate_limit_enabled)
            .await
    }

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let now = Utc::now();
        let start = input
            .start
            .map(|start| ApiKeyStart::prepare(start, self.connection().get_database_backend()))
            .transpose()?;
        let sqlite_cast = start
            .as_ref()
            .is_some_and(ApiKeyStart::requires_sqlite_cast);
        let model = ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(input.name),
            start: Set(start),
            prefix: Set(input.prefix),
            key_hash: Set(input.key_hash),
            reference_id: Set(input.reference_id),
            config_id: Set(input.config_id),
            refill_interval: Set(input.refill_interval),
            refill_amount: Set(input.refill_amount),
            last_refill_at: Set(None),
            enabled: Set(input.enabled),
            rate_limit_enabled: Set(input.rate_limit_enabled),
            rate_limit_time_window: Set(input.rate_limit_time_window),
            rate_limit_max: Set(input.rate_limit_max),
            request_count: Set(Some(0.0)),
            remaining: Set(input.remaining),
            last_request: Set(None),
            expires_at: Set(parse_optional_rfc3339(
                input.expires_at.as_deref(),
                "expires_at",
            )?),
            created_at: Set(now),
            updated_at: Set(now),
            permissions: Set(input.permissions),
            metadata: Set(input.metadata),
        };
        let inserted = if sqlite_cast {
            use sea_orm::sea_query::{Expr, ExprTrait, Query};
            // Keep one bound INSERT with every ordinary model value. Only the
            // invalid-surrogate SQLite start needs a bytes-to-TEXT expression;
            // other engines and valid strings retain the original ORM path.
            let mut insert = Entity::insert(model.clone());
            let mut values = Query::select();
            for column in Column::iter() {
                let value = Expr::val(model.get(column).unwrap());
                let _ = values.expr(if matches!(column, Column::Start) {
                    value.cast_as("text")
                } else {
                    value
                });
            }
            let _ = insert
                .query()
                .select_from(values)
                .map_err(|error| AuthError::internal(error.to_string()))?;
            insert.exec_with_returning(self.connection()).await
        } else {
            model.insert(self.connection()).await
        };
        inserted
            .map(|model| ApiKey::from(&model))
            .map_err(map_db_err)
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| ApiKey::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        Entity::find()
            .filter(Column::KeyHash.eq(hash))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| ApiKey::from(&model)))
            .map_err(map_db_err)
    }

    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        // Explicit ASC order matches TS insertion-order behavior and avoids
        // nondeterministic results across database backends.
        Entity::find()
            .filter(Column::ReferenceId.eq(reference_id))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(ApiKey::from).collect())
            .map_err(map_db_err)
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("API Key not found"));
        };

        let active = apply_update_fields(model.into_active_model(), update)?;
        active
            .update(self.connection())
            .await
            .map(|model_2| ApiKey::from(&model_2))
            .map_err(map_db_err)
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        // SQLite must acquire its write reservation before reading usage counters.
        let transaction = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let txn = &transaction;
        let id = id.to_owned();
        let result = async {
            let Some(model) = Entity::find_by_id(id.clone())
                .lock_exclusive()
                .one(txn)
                .await
                .map_err(map_db_err)?
            else {
                return Err(AuthError::not_found("API Key not found"));
            };

            let now = Utc::now();
            let mut update = UpdateApiKey::default();

            if let Some(remaining) = model.remaining {
                if let (Some(interval), Some(amount)) = (model.refill_interval, model.refill_amount)
                    && interval != 0.0
                    && amount != 0.0
                    && (now.timestamp_millis()
                        - model
                            .last_refill_at
                            .unwrap_or(model.created_at)
                            .timestamp_millis()) as f64
                        > interval
                {
                    update.remaining = Some(amount - 1.0);
                    update.last_refill_at = Some(Some(now.to_rfc3339()));
                } else if remaining > 0.0 {
                    update.remaining = Some(remaining - 1.0);
                } else {
                    return Ok(ConsumeApiKeyResult::UsageExhausted);
                }
            }

            if global_rate_limit_enabled && model.rate_limit_enabled {
                if let (Some(window), Some(max)) =
                    (model.rate_limit_time_window, model.rate_limit_max)
                {
                    let elapsed = model
                        .last_request
                        .map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
                    if let Some(elapsed) = elapsed
                        && elapsed <= window
                        && model.request_count.unwrap_or(0.0) >= max
                    {
                        // TS consumes quota before rejecting a rate-limited request.
                        // A rejection preserves the rate-limit window and updated_at.
                        if update.remaining.is_some() {
                            let updated_at = model.updated_at;
                            let mut active =
                                apply_update_fields(model.into_active_model(), update)?;
                            active.updated_at = Set(updated_at);
                            drop(active.update(txn).await.map_err(map_db_err)?);
                        }
                        return Ok(ConsumeApiKeyResult::RateLimited {
                            try_again_in: (window - elapsed).ceil(),
                        });
                    }

                    update.request_count =
                        Some(if elapsed.is_none_or(|elapsed| elapsed > window) {
                            1.0
                        } else {
                            model.request_count.unwrap_or(0.0) + 1.0
                        });
                    update.last_request = Some(Some(now.to_rfc3339()));
                }
            } else {
                update.last_request = Some(Some(now.to_rfc3339()));
            }

            let active = apply_update_fields(model.into_active_model(), update)?;
            let updated = active.update(txn).await.map_err(map_db_err)?;
            Ok(ConsumeApiKeyResult::Allowed(Box::new(ApiKey::from(
                &updated,
            ))))
        }
        .await;
        if result.is_ok() {
            transaction.commit().await.map_err(map_db_err)?;
        } else {
            transaction.rollback().await.map_err(map_db_err)?;
        }
        result
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        // Single query: DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < NOW()
        // Matches TS: adapter.deleteMany({ where: [{ field: "expiresAt", operator: "lt", value: new Date() }, ...] })
        Entity::delete_many()
            .filter(Column::ExpiresAt.is_not_null())
            .filter(Column::ExpiresAt.lt(Utc::now()))
            .exec(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|result| {
                usize::try_from(result.rows_affected)
                    .map_err(|_error| AuthError::internal("Affected row count exceeds usize"))
            })
    }
}

/// Apply `UpdateApiKey` fields to a `SeaORM` active model.
fn apply_update_fields(mut active: ActiveModel, update: UpdateApiKey) -> AuthResult<ActiveModel> {
    if let Some(name) = update.name {
        active.name = Set(Some(name));
    }
    if let Some(enabled) = update.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(remaining) = update.remaining {
        active.remaining = Set(Some(remaining));
    }
    if let Some(rate_limit_enabled) = update.rate_limit_enabled {
        active.rate_limit_enabled = Set(rate_limit_enabled);
    }
    if let Some(rate_limit_time_window) = update.rate_limit_time_window {
        active.rate_limit_time_window = Set(Some(rate_limit_time_window));
    }
    if let Some(rate_limit_max) = update.rate_limit_max {
        active.rate_limit_max = Set(Some(rate_limit_max));
    }
    if let Some(refill_interval) = update.refill_interval {
        active.refill_interval = Set(Some(refill_interval));
    }
    if let Some(refill_amount) = update.refill_amount {
        active.refill_amount = Set(Some(refill_amount));
    }
    if let Some(permissions) = update.permissions {
        active.permissions = Set(Some(permissions));
    }
    if let Some(metadata) = update.metadata {
        active.metadata = Set(Some(metadata));
    }
    if let Some(expires_at) = update.expires_at {
        active.expires_at = Set(parse_optional_rfc3339(expires_at.as_deref(), "expires_at")?);
    }
    if let Some(last_request) = update.last_request {
        active.last_request = Set(parse_optional_rfc3339(
            last_request.as_deref(),
            "last_request",
        )?);
    }
    if let Some(request_count) = update.request_count {
        active.request_count = Set(Some(request_count));
    }
    if let Some(last_refill_at) = update.last_refill_at {
        active.last_refill_at = Set(parse_optional_rfc3339(
            last_refill_at.as_deref(),
            "last_refill_at",
        )?);
    }
    active.updated_at = Set(Utc::now());
    Ok(active)
}

// LCOV_EXCL_START
#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::AuthConfig;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database};
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tokio::task::JoinSet;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn file_sqlite_connections_consume_quota_without_lock_upgrade_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            std::env::temp_dir().join(format!("better-auth-api-key-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let outcome = async {
            let mut options = ConnectOptions::new(format!(
                "sqlite://{}?mode=rwc",
                directory.join("auth.sqlite").display()
            ));
            let _ignored_max_connections = options.min_connections(8).max_connections(8);
            let database = Database::connect(options).await?;
            let result = async {
                run_migrations(&database).await?;
                let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
                    AuthConfig::new("a-secret-that-is-at-least-32-characters"),
                    database.clone(),
                ));
                let key = store
                    .create_api_key(CreateApiKey {
                        reference_id: "owner".to_owned(),
                        config_id: "default".to_owned(),
                        name: None,
                        prefix: None,
                        key_hash: "concurrent-key-hash".to_owned(),
                        start: None,
                        expires_at: None,
                        remaining: Some(12.5),
                        rate_limit_enabled: true,
                        rate_limit_time_window: Some(86_400_000.0),
                        rate_limit_max: Some(2.5),
                        refill_interval: None,
                        refill_amount: None,
                        permissions: None,
                        metadata: None,
                        enabled: true,
                    })
                    .await?;
                let barrier = Arc::new(Barrier::new(32));
                let mut tasks = JoinSet::new();
                for _ in 0..32 {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    let id = key.id.clone();
                    drop(tasks.spawn(async move {
                        let _ignored_wait = barrier.wait().await;
                        store.consume_api_key_usage(&id, true).await
                    }));
                }
                let mut counts = [0; 3];
                while let Some(result) = tasks.join_next().await {
                    match result?? {
                        ConsumeApiKeyResult::Allowed(_) => counts[0] += 1,
                        ConsumeApiKeyResult::RateLimited { .. } => counts[1] += 1,
                        ConsumeApiKeyResult::UsageExhausted => counts[2] += 1,
                    }
                }
                let observed = store
                    .update_api_key(
                        &key.id,
                        UpdateApiKey {
                            remaining: Some(12.5),
                            request_count: Some(0.0),
                            last_request: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?;
                let barrier_2 = Arc::new(Barrier::new(32));
                let mut tasks_2 = JoinSet::new();
                for _ in 0..32 {
                    let store = Arc::clone(&store);
                    let observed = observed.clone();
                    let barrier_2_3 = Arc::clone(&barrier_2);
                    drop(tasks_2.spawn(async move {
                        let _ignored_wait_2 = barrier_2_3.wait().await;
                        store
                            .consume_api_key_usage_from_snapshot(&observed, true)
                            .await
                    }));
                }
                let mut phased_counts = [0; 3];
                while let Some(result) = tasks_2.join_next().await {
                    match result?? {
                        ConsumeApiKeyResult::Allowed(_) => phased_counts[0] += 1,
                        ConsumeApiKeyResult::RateLimited { .. } => phased_counts[1] += 1,
                        ConsumeApiKeyResult::UsageExhausted => phased_counts[2] += 1,
                    }
                }
                assert_eq!(phased_counts, [3, 10, 19]);
                let persisted = store.get_api_key_by_id(&key.id).await?;
                Ok::<_, Box<dyn std::error::Error>>((counts, persisted))
            }
            .await;
            let closed = database.close().await;
            closed?;
            result
        }
        .await;
        let removed = std::fs::remove_dir_all(&directory);
        removed?;
        let (counts, persisted) = outcome?;
        // Upstream accepts fractional limits and consumes quota before rate-limit rejection.
        assert_eq!(counts, [3, 10, 19]);
        let persisted = persisted.ok_or_else(|| {
            std::io::Error::other("fractional exhausted quota must retain the key")
        })?;
        assert_eq!(persisted.remaining, Some(-0.5));
        assert_eq!(persisted.request_count, Some(3.0));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[expect(
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn independent_connections_reject_final_quota_loser_without_deleting_credential()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            std::env::temp_dir().join(format!("better-auth-final-quota-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let outcome = async {
            let mut options = ConnectOptions::new(format!(
                "sqlite://{}?mode=rwc",
                directory.join("auth.sqlite").display()
            ));
            let _ignored_max_connections = options.min_connections(1).max_connections(1);
            let first = Database::connect(options.clone()).await?;
            let second = Database::connect(options).await?;
            let result = async {
                run_migrations(&first).await?;
                let config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
                let stores = [
                    Arc::new(SeaOrmStore::<BundledSchema>::new(
                        config.clone(),
                        first.clone(),
                    )),
                    Arc::new(SeaOrmStore::<BundledSchema>::new(config, second.clone())),
                ];
                let mut input = CreateApiKey {
                    reference_id: "owner".into(),
                    config_id: "default".into(),
                    name: Some("last-use".into()),
                    prefix: None,
                    key_hash: "last-use-hash".into(),
                    start: None,
                    expires_at: None,
                    remaining: Some(1.0),
                    rate_limit_enabled: false,
                    rate_limit_time_window: None,
                    rate_limit_max: None,
                    refill_interval: None,
                    refill_amount: None,
                    permissions: None,
                    metadata: None,
                    enabled: true,
                };
                let key = stores[0].create_api_key(input.clone()).await?;
                input.reference_id = "foreign-owner".into();
                input.key_hash = "foreign-hash".into();
                let foreign = stores[0].create_api_key(input).await?;
                let barrier = Arc::new(Barrier::new(2));
                let mut tasks = JoinSet::new();
                for store in &stores {
                    let store = Arc::clone(store);
                    let id = key.id.clone();
                    let barrier = Arc::clone(&barrier);
                    drop(tasks.spawn(async move {
                        let _ignored_wait = barrier.wait().await;
                        store.consume_api_key_usage(&id, false).await
                    }));
                }
                let mut allowed = None;
                let mut exhausted = 0;
                while let Some(result) = tasks.join_next().await {
                    match result?? {
                        ConsumeApiKeyResult::Allowed(key_2) => {
                            assert!(allowed.is_none());
                            allowed = Some(*key_2);
                        }
                        ConsumeApiKeyResult::UsageExhausted => exhausted += 1,
                        ConsumeApiKeyResult::RateLimited { .. } => {
                            panic!("disabled rate limit must not deny")
                        }
                    }
                }
                let allowed =
                    allowed.ok_or_else(|| std::io::Error::other("one final use must succeed"))?;
                assert_eq!(exhausted, 1);
                assert_eq!(allowed.remaining, Some(0.0));
                let persisted = stores[1].get_api_key_by_id(&key.id).await?.ok_or_else(|| {
                    std::io::Error::other("quota loser must retain the credential")
                })?;
                assert_eq!(
                    serde_json::to_value(&persisted)?,
                    serde_json::to_value(&allowed)?
                );
                assert!(matches!(
                    stores[0].consume_api_key_usage(&key.id, false).await?,
                    ConsumeApiKeyResult::UsageExhausted
                ));
                assert_eq!(
                    serde_json::to_value(stores[1].get_api_key_by_id(&key.id).await?)?,
                    serde_json::to_value(Some(&persisted))?
                );
                assert_eq!(
                    serde_json::to_value(stores[1].get_api_key_by_id(&foreign.id).await?)?,
                    serde_json::to_value(Some(&foreign))?
                );
                // Application retry can refill the same actual credential; the
                // atomic denial must not destroy the row or replace its ownership.
                let reset = stores[0]
                    .update_api_key(
                        &key.id,
                        UpdateApiKey {
                            remaining: Some(1.0),
                            ..Default::default()
                        },
                    )
                    .await?;
                assert_eq!(reset.id, key.id);
                assert_eq!(reset.reference_id, "owner");
                let retry = stores[1].consume_api_key_usage(&key.id, false).await?;
                let ConsumeApiKeyResult::Allowed(retry) = retry else {
                    panic!("refilled credential must authenticate");
                };
                assert_eq!(retry.id, key.id);
                assert_eq!(retry.remaining, Some(0.0));
                // Eight callers share one overdue refill across separate database
                // connections. Refill replenishes once, then guarded uses exhaust it.
                let due = stores[0]
                    .update_api_key(
                        &key.id,
                        UpdateApiKey {
                            remaining: Some(0.0),
                            refill_amount: Some(3.0),
                            refill_interval: Some(60_000.0),
                            last_refill_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                            ..Default::default()
                        },
                    )
                    .await?;
                let barrier_2 = Arc::new(Barrier::new(8));
                let mut tasks_2 = JoinSet::new();
                for index in 0..8 {
                    let store = Arc::clone(
                        (stores)
                            .get(index % stores.len())
                            .expect("fixture contains the requested index"),
                    );
                    let id = key.id.clone();
                    let barrier_2_3 = Arc::clone(&barrier_2);
                    drop(tasks_2.spawn(async move {
                        let _ignored_wait_3 = barrier_2_3.wait().await;
                        store.consume_api_key_usage(&id, false).await
                    }));
                }
                let mut accepted = 0;
                let mut exhausted_2 = 0;
                while let Some(result) = tasks_2.join_next().await {
                    match result?? {
                        ConsumeApiKeyResult::Allowed(value) => {
                            accepted += 1;
                            assert_eq!(value.id, due.id);
                            assert_eq!(value.reference_id, due.reference_id);
                        }
                        ConsumeApiKeyResult::UsageExhausted => exhausted_2 += 1,
                        ConsumeApiKeyResult::RateLimited { .. } => {
                            panic!("disabled rate limit must not deny refill")
                        }
                    }
                }
                assert_eq!((accepted, exhausted_2), (3, 5));
                let final_row = stores[1]
                    .get_api_key_by_id(&key.id)
                    .await?
                    .ok_or("refill losers must retain row")?;
                assert_eq!(final_row.remaining, Some(0.0));
                assert_ne!(final_row.last_refill_at, due.last_refill_at);
                assert_eq!(final_row.refill_amount, due.refill_amount);
                assert_eq!(final_row.refill_interval, due.refill_interval);
                assert_eq!(final_row.id, due.id);
                assert_eq!(final_row.key_hash, due.key_hash);
                assert_eq!(final_row.reference_id, due.reference_id);
                // The Source-phased operation must enforce the same one-refill
                // budget when every caller starts with the identical genuine row.
                let observed = stores[0]
                    .update_api_key(
                        &key.id,
                        UpdateApiKey {
                            last_refill_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                            ..Default::default()
                        },
                    )
                    .await?;
                let barrier_3 = Arc::new(Barrier::new(8));
                let mut tasks_3 = JoinSet::new();
                for index in 0..8 {
                    let store = Arc::clone(
                        (stores)
                            .get(index % stores.len())
                            .expect("fixture contains the requested index"),
                    );
                    let observed = observed.clone();
                    let barrier_4 = Arc::clone(&barrier_3);
                    drop(tasks_3.spawn(async move {
                        let _ignored_wait_4 = barrier_4.wait().await;
                        store
                            .consume_api_key_usage_from_snapshot(&observed, false)
                            .await
                    }));
                }
                let mut counts = [0, 0];
                while let Some(result) = tasks_3.join_next().await {
                    match result?? {
                        ConsumeApiKeyResult::Allowed(value) => {
                            counts[0] += 1;
                            assert_eq!(value.reference_id, "owner");
                            assert_eq!(value.id, key.id);
                        }
                        ConsumeApiKeyResult::UsageExhausted => counts[1] += 1,
                        ConsumeApiKeyResult::RateLimited { .. } => {
                            panic!("disabled rate limit must not deny phased refill")
                        }
                    }
                }
                assert_eq!(counts, [3, 5]);
                let persisted_2 = stores[1]
                    .get_api_key_by_id(&key.id)
                    .await?
                    .ok_or("phased refill must retain zero row")?;
                assert_eq!(persisted_2.remaining, Some(0.0));
                assert_ne!(persisted_2.last_refill_at, observed.last_refill_at);
                assert_eq!(persisted_2.key_hash, observed.key_hash);
                assert_eq!(persisted_2.reference_id, observed.reference_id);
                assert_eq!(
                    serde_json::to_value(stores[0].get_api_key_by_id(&foreign.id).await?)?,
                    serde_json::to_value(Some(&foreign))?
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            }
            .await;
            first.close().await?;
            second.close().await?;
            result
        }
        .await;
        std::fs::remove_dir_all(&directory)?;
        outcome
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn assert_usage_source_phase(phase: &str) -> Result<(), Box<dyn std::error::Error>> {
        {
            let database = Database::connect("sqlite::memory:").await?;
            run_migrations(&database).await?;
            let store = SeaOrmStore::<BundledSchema>::new(
                AuthConfig::new("phase-source-secret-at-least-32-characters"),
                database.clone(),
            );
            let input = CreateApiKey {
                reference_id: "phase-owner".into(),
                config_id: "default".into(),
                name: Some("phase-target".into()),
                prefix: None,
                key_hash: format!("{phase}-target-hash"),
                start: None,
                expires_at: None,
                remaining: Some(0.0),
                rate_limit_enabled: true,
                rate_limit_time_window: Some(60_000.0),
                rate_limit_max: Some(2.0),
                refill_interval: Some(60_000.0),
                refill_amount: Some(3.0),
                permissions: None,
                metadata: None,
                enabled: true,
            };
            let key = store.create_api_key(input.clone()).await?;
            let mut other = input;
            other.reference_id = "foreign-owner".into();
            other.name = Some("foreign-control".into());
            other.key_hash = format!("{phase}-foreign-hash");
            let foreign = store.create_api_key(other).await?;
            let snapshot = store
                .update_api_key(
                    &key.id,
                    UpdateApiKey {
                        last_refill_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                        ..Default::default()
                    },
                )
                .await?;
            let condition = if phase == "rate" {
                "NEW.request_count<>OLD.request_count"
            } else {
                "NEW.remaining IS OLD.remaining AND NEW.request_count IS OLD.request_count AND NEW.last_request IS OLD.last_request AND NEW.last_refill_at IS OLD.last_refill_at"
            };
            let sql = if phase == "current" {
                "CREATE TRIGGER current_row AFTER UPDATE ON api_keys WHEN OLD.name='phase-target' AND NEW.last_request IS NOT OLD.last_request AND NEW.updated_at IS OLD.updated_at BEGIN UPDATE api_keys SET remaining=77,name='current-row' WHERE id=NEW.id; END".to_owned()
            } else {
                format!(
                    "CREATE TRIGGER phase_veto BEFORE UPDATE ON api_keys WHEN OLD.name='phase-target' AND ({condition}) BEGIN SELECT RAISE(ABORT,'actual phase storage veto'); END"
                )
            };
            let _ignored_execute_raw = database
                .execute_raw(sea_orm::Statement::from_string(
                    sea_orm::DbBackend::Sqlite,
                    sql,
                ))
                .await?;
            let result = store
                .consume_api_key_usage_from_snapshot(&snapshot, true)
                .await;
            if phase != "current" {
                assert!(
                    result.is_err(),
                    "{phase} write must expose the genuine SQL veto"
                );
            }
            let persisted = store
                .get_api_key_by_id(&key.id)
                .await?
                .ok_or("phase error cannot delete key")?;
            assert_eq!(
                persisted.remaining,
                Some(if phase == "current" { 77.0 } else { 2.0 }),
                "{phase} must expose actual current quota"
            );
            assert_ne!(persisted.last_refill_at, snapshot.last_refill_at);
            let mut expected = snapshot.clone();
            expected.remaining = Some(2.0);
            expected.last_refill_at = persisted.last_refill_at.clone();
            if phase == "final" {
                expected.request_count = Some(1.0);
                expected.last_request = persisted.last_request.clone();
                assert!(persisted.last_request.is_some());
            }
            if phase == "current" {
                let ConsumeApiKeyResult::Allowed(returned) = result? else {
                    panic!("genuine current row must be returned")
                };
                assert_eq!(
                    serde_json::to_value(&returned)?,
                    serde_json::to_value(&persisted)?
                );
                expected.remaining = Some(77.0);
                expected.name = Some("current-row".into());
                expected.request_count = Some(1.0);
                expected.last_request = persisted.last_request.clone();
                expected.updated_at = persisted.updated_at.clone();
            }
            assert_eq!(
                serde_json::to_value(&persisted)?,
                serde_json::to_value(&expected)?
            );
            assert_eq!(
                serde_json::to_value(store.get_api_key_by_id(&foreign.id).await?)?,
                serde_json::to_value(Some(&foreign))?
            );
            database.close().await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn rate_sql_failure_retains_successful_refill_consumption()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_usage_source_phase("rate").await
    }
    #[tokio::test]
    async fn final_sql_failure_retains_successful_quota_and_rate_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_usage_source_phase("final").await
    }

    #[tokio::test]
    async fn final_current_row_includes_genuine_after_rate_write_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_usage_source_phase("current").await
    }
}
// LCOV_EXCL_STOP
