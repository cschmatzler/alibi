//! Two-factor counters, locks and backup compare-and-swap across connections.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use better_auth::AuthConfig;
use better_auth_core::store::SchemaMigrator;
use better_auth_core::store::TwoFactorStore;
use better_auth_core::{CreateTwoFactor, UpdateTwoFactor};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::{sync::Barrier, task::JoinSet};

backend_tests!(
    independent_factor_connections_increment_nullable_numbers_and_conditionally_reset_or_consume
);
postgres_tests!(
    independent_factor_connections_increment_nullable_numbers_and_conditionally_reset_or_consume,
);

async fn independent_factor_connections_increment_nullable_numbers_and_conditionally_reset_or_consume<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let config = Arc::new(AuthConfig::new(
        "factor-policy-secret-at-least-32-characters",
    ));
    let primary = B::connect(&db.url, Some(1)).await?;
    let store = B::store(Arc::clone(&config), &primary);
    store.migrate().await?;
    _ = db.execute("INSERT INTO users(id,name,email,email_verified,metadata,created_at,updated_at) VALUES('owner','Owner','owner@fixture.test',FALSE,'{}','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')", &[]).await?;
    let factor = store
        .create_two_factor(CreateTwoFactor {
            user_id: "owner".into(),
            secret: "secret".into(),
            backup_codes: "old-backup".into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(factor.failed_verification_count, Some(0.0));
    // Custom schemas can contain multiple generations for one owner.
    _ = db.execute("DROP INDEX idx_two_factor_user_id", &[]).await?;
    let sibling = store
        .create_two_factor(CreateTwoFactor {
            user_id: "owner".into(),
            secret: "other-secret".into(),
            backup_codes: "other-backup".into(),
            ..Default::default()
        })
        .await?;
    let mut connections = Vec::new();
    for _ in 0..8 {
        connections.push(B::connect(&db.url, Some(1)).await?);
    }
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for connection in &connections {
        let worker = B::store(Arc::clone(&config), connection);
        let barrier = Arc::clone(&barrier);
        let id = factor.id.clone();
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            worker.increment_two_factor_failure(&id).await
        }));
    }
    let mut counts = Vec::new();
    while let Some(row) = tasks.join_next().await {
        counts.push(row??.unwrap().failed_verification_count.unwrap());
    }
    counts.sort_by(f64::total_cmp);
    assert_eq!(counts, (1..=8).map(f64::from).collect::<Vec<_>>());
    // SQLite keeps INTEGER affinity for integral counts; PostgreSQL stores
    // the counter as double precision.
    let (sql, expected) = if db.is_postgres() {
        (
            "SELECT CAST(pg_typeof(failed_verification_count) AS TEXT) FROM two_factor WHERE id=$1",
            "double precision",
        )
    } else {
        (
            "SELECT typeof(failed_verification_count) FROM two_factor WHERE id=$1",
            "integer",
        )
    };
    assert_eq!(
        db.text(sql, &[&factor.id]).await?,
        Some(expected.to_owned())
    );
    let now = Utc::now();
    let future = now + Duration::minutes(15);
    assert!(
        store
            .set_two_factor_lock_if_count_at_least(&factor.id, 8.5, future)
            .await?
            .is_none()
    );
    assert!(
        store
            .set_two_factor_lock_if_count_at_least(&factor.id, 7.5, future)
            .await?
            .is_some()
    );
    assert!(
        store
            .clear_expired_two_factor_lock(&factor.id, now)
            .await?
            .is_none()
    );
    let barrier = Arc::new(Barrier::new(8));
    let mut unlocks = JoinSet::new();
    for connection in &connections {
        let worker = B::store(Arc::clone(&config), connection);
        let barrier = Arc::clone(&barrier);
        let id = factor.id.clone();
        drop(unlocks.spawn(async move {
            _ = barrier.wait().await;
            worker.clear_expired_two_factor_lock(&id, future).await
        }));
    }
    let mut winners = Vec::new();
    while let Some(row) = unlocks.join_next().await {
        if let Some(row) = row?? {
            winners.push(row);
        }
    }
    assert_eq!(winners.len(), 1);
    let unlocked = winners.pop().unwrap();
    assert_eq!(unlocked.failed_verification_count, Some(0.0));
    assert_eq!(unlocked.locked_until, None);
    // A stale failure cannot set a lock after a concurrent success reset.
    assert!(
        store
            .set_two_factor_lock_if_count_at_least(&factor.id, 1.0, future)
            .await?
            .is_none()
    );
    _ = db
        .execute(
            "UPDATE two_factor SET failed_verification_count=0.5 WHERE id=$1",
            &[&factor.id],
        )
        .await?;
    let incremented = store
        .increment_two_factor_failure(&factor.id)
        .await?
        .unwrap();
    assert_eq!(incremented.failed_verification_count, Some(1.5));
    let updated = store
        .update_two_factor(
            &factor.id,
            UpdateTwoFactor {
                secret: Some("rotated".into()),
                verified: Some(false),
                ..Default::default()
            },
        )
        .await?
        .unwrap();
    assert_eq!(updated.failed_verification_count, Some(1.5));
    assert_eq!(updated.verified, Some(false));
    assert_eq!(updated.created_at, factor.created_at);
    assert_eq!(updated.updated_at, factor.updated_at);
    let barrier = Arc::new(Barrier::new(8));
    let mut swaps = JoinSet::new();
    for (index, connection) in connections.iter().enumerate() {
        let worker = B::store(Arc::clone(&config), connection);
        let id = factor.id.clone();
        let barrier = Arc::clone(&barrier);
        drop(swaps.spawn(async move {
            _ = barrier.wait().await;
            worker
                .compare_and_swap_two_factor_backup_codes(
                    &id,
                    "old-backup",
                    &format!("winner-{index}"),
                )
                .await
        }));
    }
    let mut swap_winners = 0;
    while let Some(row) = swaps.join_next().await {
        if row?? {
            swap_winners += 1;
        }
    }
    assert_eq!(swap_winners, 1);
    store.reset_two_factor_failures(&factor.id).await?;
    let reset = store
        .update_two_factor(&factor.id, UpdateTwoFactor::default())
        .await?
        .unwrap();
    assert_eq!(reset.failed_verification_count, Some(0.0));
    assert_eq!(reset.locked_until, None);
    assert_eq!(reset.secret, "rotated");
    assert!(reset.backup_codes.starts_with("winner-"));
    let untouched = store
        .update_two_factor(&sibling.id, UpdateTwoFactor::default())
        .await?
        .unwrap();
    assert_eq!(
        serde_json::to_value(untouched)?,
        serde_json::to_value(sibling)?
    );
    assert!(
        store
            .increment_two_factor_failure("missing")
            .await?
            .is_none()
    );
    for connection in connections {
        B::close(connection).await?;
    }
    B::close(primary).await
}
