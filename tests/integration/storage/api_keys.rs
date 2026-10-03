//! API key quota consumption across connections and Source-phased writes.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use better_auth::AuthConfig;
use better_auth_core::store::ApiKeyStore;
use better_auth_core::store::SchemaMigrator;
use better_auth_core::{ConsumeApiKeyResult, CreateApiKey, UpdateApiKey};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

backend_tests!(
    file_sqlite_connections_consume_quota_without_lock_upgrade_errors,
    independent_connections_reject_final_quota_loser_without_deleting_credential,
    rate_sql_failure_retains_successful_refill_consumption,
    final_sql_failure_retains_successful_quota_and_rate_writes,
    final_current_row_includes_genuine_after_rate_write_changes,
);
postgres_tests!(
    file_sqlite_connections_consume_quota_without_lock_upgrade_errors,
    independent_connections_reject_final_quota_loser_without_deleting_credential,
);

fn key(reference_id: &str, key_hash: &str) -> CreateApiKey {
    CreateApiKey {
        reference_id: reference_id.to_owned(),
        config_id: "default".to_owned(),
        name: None,
        prefix: None,
        key_hash: key_hash.to_owned(),
        start: None,
        expires_at: None,
        remaining: None,
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
        refill_interval: None,
        refill_amount: None,
        permissions: None,
        metadata: None,
        enabled: true,
    }
}

fn tally(counts: &mut [usize; 3], result: &ConsumeApiKeyResult) {
    match result {
        ConsumeApiKeyResult::Allowed(_) => counts[0] += 1,
        ConsumeApiKeyResult::RateLimited { .. } => counts[1] += 1,
        ConsumeApiKeyResult::UsageExhausted => counts[2] += 1,
    }
}

async fn file_sqlite_connections_consume_quota_without_lock_upgrade_errors<B: Backend>(
    db: Db,
) -> TestResult {
    let connection = B::connect(&db.url, Some(8)).await?;
    let store = Arc::new(B::store(
        Arc::new(AuthConfig::new("a-secret-that-is-at-least-32-characters")),
        &connection,
    ));
    store.migrate().await?;
    let created = store
        .create_api_key(CreateApiKey {
            remaining: Some(12.5),
            rate_limit_enabled: true,
            rate_limit_time_window: Some(86_400_000.0),
            rate_limit_max: Some(2.5),
            ..key("owner", "concurrent-key-hash")
        })
        .await?;
    let barrier = Arc::new(Barrier::new(32));
    let mut tasks = JoinSet::new();
    for _ in 0..32 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let id = created.id.clone();
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store.consume_api_key_usage(&id, true).await
        }));
    }
    let mut counts = [0; 3];
    while let Some(result) = tasks.join_next().await {
        tally(&mut counts, &result??);
    }
    // Upstream accepts fractional limits and consumes quota before rate-limit rejection.
    assert_eq!(counts, [3, 10, 19]);
    let persisted = store
        .get_api_key_by_id(&created.id)
        .await?
        .ok_or("fractional exhausted quota must retain the key")?;
    assert_eq!(persisted.remaining, Some(-0.5));
    assert_eq!(persisted.request_count, Some(3.0));
    let observed = store
        .update_api_key(
            &created.id,
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
        let store = Arc::clone(&store);
        let observed = observed.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store
                .consume_api_key_usage_from_snapshot(&observed, true)
                .await
        }));
    }
    let mut phased_counts = [0; 3];
    while let Some(result) = tasks.join_next().await {
        tally(&mut phased_counts, &result??);
    }
    assert_eq!(phased_counts, [3, 10, 19]);
    drop(store);
    B::close(connection).await
}

async fn independent_connections_reject_final_quota_loser_without_deleting_credential<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let config = Arc::new(AuthConfig::new("a-secret-that-is-at-least-32-characters"));
    let first = B::connect(&db.url, Some(1)).await?;
    let second = B::connect(&db.url, Some(1)).await?;
    let stores = [
        Arc::new(B::store(Arc::clone(&config), &first)),
        Arc::new(B::store(config, &second)),
    ];
    stores[0].migrate().await?;
    let input = CreateApiKey {
        name: Some("last-use".into()),
        remaining: Some(1.0),
        ..key("owner", "last-use-hash")
    };
    let created = stores[0].create_api_key(input.clone()).await?;
    let foreign = stores[0]
        .create_api_key(CreateApiKey {
            reference_id: "foreign-owner".into(),
            key_hash: "foreign-hash".into(),
            ..input
        })
        .await?;
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = JoinSet::new();
    for store in &stores {
        let store = Arc::clone(store);
        let id = created.id.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store.consume_api_key_usage(&id, false).await
        }));
    }
    let mut allowed = None;
    let mut exhausted = 0;
    while let Some(result) = tasks.join_next().await {
        match result?? {
            ConsumeApiKeyResult::Allowed(row) => {
                assert!(allowed.is_none());
                allowed = Some(*row);
            }
            ConsumeApiKeyResult::UsageExhausted => exhausted += 1,
            ConsumeApiKeyResult::RateLimited { .. } => panic!("disabled rate limit must not deny"),
        }
    }
    let allowed = allowed.ok_or("one final use must succeed")?;
    assert_eq!(exhausted, 1);
    assert_eq!(allowed.remaining, Some(0.0));
    let persisted = stores[1]
        .get_api_key_by_id(&created.id)
        .await?
        .ok_or("quota loser must retain the credential")?;
    assert_eq!(
        serde_json::to_value(&persisted)?,
        serde_json::to_value(&allowed)?
    );
    assert!(matches!(
        stores[0].consume_api_key_usage(&created.id, false).await?,
        ConsumeApiKeyResult::UsageExhausted
    ));
    assert_eq!(
        serde_json::to_value(stores[1].get_api_key_by_id(&created.id).await?)?,
        serde_json::to_value(Some(&persisted))?
    );
    assert_eq!(
        serde_json::to_value(stores[1].get_api_key_by_id(&foreign.id).await?)?,
        serde_json::to_value(Some(&foreign))?
    );
    // Application retry can refill the same actual credential; the atomic
    // denial must not destroy the row or replace its ownership.
    let reset = stores[0]
        .update_api_key(
            &created.id,
            UpdateApiKey {
                remaining: Some(1.0),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(reset.id, created.id);
    assert_eq!(reset.reference_id, "owner");
    let ConsumeApiKeyResult::Allowed(retry) =
        stores[1].consume_api_key_usage(&created.id, false).await?
    else {
        panic!("refilled credential must authenticate");
    };
    assert_eq!(retry.id, created.id);
    assert_eq!(retry.remaining, Some(0.0));
    // Eight callers share one overdue refill across separate database
    // connections. Refill replenishes once, then guarded uses exhaust it.
    let due = stores[0]
        .update_api_key(
            &created.id,
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
        let store = Arc::clone(&stores[index % stores.len()]);
        let id = created.id.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store.consume_api_key_usage(&id, false).await
        }));
    }
    let mut counts = [0; 3];
    while let Some(result) = tasks.join_next().await {
        let result = result??;
        if let ConsumeApiKeyResult::Allowed(value) = &result {
            assert_eq!(value.id, due.id);
            assert_eq!(value.reference_id, due.reference_id);
        }
        tally(&mut counts, &result);
    }
    assert_eq!(counts, [3, 0, 5]);
    let final_row = stores[1]
        .get_api_key_by_id(&created.id)
        .await?
        .ok_or("refill losers must retain row")?;
    assert_eq!(final_row.remaining, Some(0.0));
    assert_ne!(final_row.last_refill_at, due.last_refill_at);
    assert_eq!(final_row.refill_amount, due.refill_amount);
    assert_eq!(final_row.refill_interval, due.refill_interval);
    assert_eq!(final_row.id, due.id);
    assert_eq!(final_row.key_hash, due.key_hash);
    assert_eq!(final_row.reference_id, due.reference_id);
    // The Source-phased operation must enforce the same one-refill budget
    // when every caller starts with the identical genuine row.
    let observed = stores[0]
        .update_api_key(
            &created.id,
            UpdateApiKey {
                last_refill_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                ..Default::default()
            },
        )
        .await?;
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for index in 0..8 {
        let store = Arc::clone(&stores[index % stores.len()]);
        let observed = observed.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store
                .consume_api_key_usage_from_snapshot(&observed, false)
                .await
        }));
    }
    let mut counts = [0; 3];
    while let Some(result) = tasks.join_next().await {
        let result = result??;
        if let ConsumeApiKeyResult::Allowed(value) = &result {
            assert_eq!(value.reference_id, "owner");
            assert_eq!(value.id, created.id);
        }
        tally(&mut counts, &result);
    }
    assert_eq!(counts, [3, 0, 5]);
    let persisted = stores[1]
        .get_api_key_by_id(&created.id)
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
    drop(stores);
    B::close(first).await?;
    B::close(second).await
}

async fn assert_usage_source_phase<B: Backend>(db: Db, phase: &str) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("phase-source-secret-at-least-32-characters")
        .await?;
    let input = CreateApiKey {
        name: Some("phase-target".into()),
        remaining: Some(0.0),
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000.0),
        rate_limit_max: Some(2.0),
        refill_interval: Some(60_000.0),
        refill_amount: Some(3.0),
        ..key("phase-owner", &format!("{phase}-target-hash"))
    };
    let created = store.create_api_key(input.clone()).await?;
    let foreign = store
        .create_api_key(CreateApiKey {
            reference_id: "foreign-owner".into(),
            name: Some("foreign-control".into()),
            key_hash: format!("{phase}-foreign-hash"),
            ..input
        })
        .await?;
    let snapshot = store
        .update_api_key(
            &created.id,
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
    _ = db.execute(&sql, &[]).await?;
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
        .get_api_key_by_id(&created.id)
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
    B::close(connection).await
}

async fn rate_sql_failure_retains_successful_refill_consumption<B: Backend>(db: Db) -> TestResult {
    assert_usage_source_phase::<B>(db, "rate").await
}

async fn final_sql_failure_retains_successful_quota_and_rate_writes<B: Backend>(
    db: Db,
) -> TestResult {
    assert_usage_source_phase::<B>(db, "final").await
}

async fn final_current_row_includes_genuine_after_rate_write_changes<B: Backend>(
    db: Db,
) -> TestResult {
    assert_usage_source_phase::<B>(db, "current").await
}
