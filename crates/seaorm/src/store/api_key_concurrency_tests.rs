use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::AuthConfig;
use sea_orm::{ConnectOptions, ConnectionTrait, Database};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_sqlite_connections_consume_quota_without_lock_upgrade_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!("better-auth-api-key-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let mut options = ConnectOptions::new(format!(
            "sqlite://{}?mode=rwc",
            directory.join("auth.sqlite").display()
        ));
        let _ = options.min_connections(8).max_connections(8);
        let database = Database::connect(options).await?;
        let result = async {
            run_migrations(&database).await?;
            let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
                AuthConfig::new("a-secret-that-is-at-least-32-characters"),
                database.clone(),
            ));
            let key = store
                .create_api_key(CreateApiKey {
                    reference_id: "owner".to_string(),
                    config_id: "default".to_string(),
                    name: None,
                    prefix: None,
                    key_hash: "concurrent-key-hash".to_string(),
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
                let store = store.clone();
                let barrier = barrier.clone();
                let id = key.id.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_api_key_usage(&id, true).await
                });
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
            let barrier = Arc::new(Barrier::new(32));
            let mut tasks = JoinSet::new();
            for _ in 0..32 {
                let store = store.clone();
                let observed = observed.clone();
                let barrier = barrier.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store
                        .consume_api_key_usage_from_snapshot(&observed, true)
                        .await
                });
            }
            let mut phased_counts = [0; 3];
            while let Some(result) = tasks.join_next().await {
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
    let persisted = persisted
        .ok_or_else(|| std::io::Error::other("fractional exhausted quota must retain the key"))?;
    assert_eq!(persisted.remaining, Some(-0.5));
    assert_eq!(persisted.request_count, Some(3.0));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        let _ = options.min_connections(1).max_connections(1);
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
                let store = store.clone();
                let id = key.id.clone();
                let barrier = barrier.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_api_key_usage(&id, false).await
                });
            }
            let mut allowed = None;
            let mut exhausted = 0;
            while let Some(result) = tasks.join_next().await {
                match result?? {
                    ConsumeApiKeyResult::Allowed(key) => {
                        assert!(allowed.is_none());
                        allowed = Some(*key);
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
            let persisted = stores[1]
                .get_api_key_by_id(&key.id)
                .await?
                .ok_or_else(|| std::io::Error::other("quota loser must retain the credential"))?;
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
            let barrier = Arc::new(Barrier::new(8));
            let mut tasks = JoinSet::new();
            for index in 0..8 {
                let store = stores[index % stores.len()].clone();
                let id = key.id.clone();
                let barrier = barrier.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_api_key_usage(&id, false).await
                });
            }
            let mut accepted = 0;
            let mut exhausted = 0;
            while let Some(result) = tasks.join_next().await {
                match result?? {
                    ConsumeApiKeyResult::Allowed(value) => {
                        accepted += 1;
                        assert_eq!(value.id, due.id);
                        assert_eq!(value.reference_id, due.reference_id);
                    }
                    ConsumeApiKeyResult::UsageExhausted => exhausted += 1,
                    ConsumeApiKeyResult::RateLimited { .. } => {
                        panic!("disabled rate limit must not deny refill")
                    }
                }
            }
            assert_eq!((accepted, exhausted), (3, 5));
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
            let barrier = Arc::new(Barrier::new(8));
            let mut tasks = JoinSet::new();
            for index in 0..8 {
                let store = stores[index % stores.len()].clone();
                let observed = observed.clone();
                let barrier = barrier.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store
                        .consume_api_key_usage_from_snapshot(&observed, false)
                        .await
                });
            }
            let mut counts = [0, 0];
            while let Some(result) = tasks.join_next().await {
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
            let persisted = stores[1]
                .get_api_key_by_id(&key.id)
                .await?
                .ok_or("phased refill must retain zero row")?;
            assert_eq!(persisted.remaining, Some(0.0));
            assert_ne!(persisted.last_refill_at, observed.last_refill_at);
            assert_eq!(persisted.key_hash, observed.key_hash);
            assert_eq!(persisted.reference_id, observed.reference_id);
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
        let _ = database
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
