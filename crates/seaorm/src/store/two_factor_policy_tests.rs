use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::TwoFactorStore;
use better_auth_core::{AuthConfig, CreateTwoFactor, UpdateTwoFactor};
use chrono::{Duration, Utc};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, Statement};
use std::sync::Arc;
use tokio::{sync::Barrier, task::JoinSet};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn installed_factor_policy_upgrade_retains_rows_custom_schema_and_is_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let db = Database::connect("sqlite::memory:").await?;
    let _ignored_execute_unprepared = db.execute_unprepared(
        "CREATE TABLE two_factor (id TEXT PRIMARY KEY, secret TEXT NOT NULL, backup_codes TEXT NOT NULL, user_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, custom TEXT DEFAULT 'kept');
         CREATE INDEX installed_factor_owner ON two_factor(user_id);
         CREATE TABLE factor_audit (value TEXT);
         CREATE TRIGGER installed_factor_trigger AFTER INSERT ON two_factor BEGIN INSERT INTO factor_audit VALUES(NEW.id); END;
         INSERT INTO two_factor(rowid,id,secret,backup_codes,user_id,created_at,updated_at) VALUES(41,'installed','secret-bytes','backup-bytes','owner','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')"
    ).await?;
    run_migrations(&db).await?;
    run_migrations(&db).await?;
    let row = db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,
        "SELECT rowid,id,secret,backup_codes,user_id,created_at,updated_at,custom,verified,failed_verification_count,locked_until FROM two_factor WHERE id='installed'".to_owned())).await?.unwrap();
    assert_eq!(row.try_get::<i64>("", "rowid")?, 41);
    for (column, expected) in [
        ("id", "installed"),
        ("secret", "secret-bytes"),
        ("backup_codes", "backup-bytes"),
        ("user_id", "owner"),
        ("created_at", "2025-01-02T03:04:05Z"),
        ("updated_at", "2025-01-02T03:04:05Z"),
        ("custom", "kept"),
    ] {
        assert_eq!(row.try_get::<String>("", column)?, expected);
    }
    assert!(row.try_get::<bool>("", "verified")?);
    assert_eq!(row.try_get::<i64>("", "failed_verification_count")?, 0);
    assert_eq!(row.try_get::<Option<String>>("", "locked_until")?, None);
    let _ignored_execute_unprepared_2 = db.execute_unprepared("INSERT INTO two_factor(id,secret,backup_codes,user_id,created_at,updated_at,verified,failed_verification_count) VALUES('nullable','s','b','nullable-owner','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z',NULL,NULL)").await?;
    let _ignored_execute_unprepared_3 = db.execute_unprepared("INSERT INTO two_factor(id,secret,backup_codes,user_id,created_at,updated_at) VALUES('defaults','s','b','default-owner','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')").await?;
    let audit = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM factor_audit".to_owned(),
        ))
        .await?
        .unwrap();
    assert_eq!(audit.try_get::<i64>("", "n")?, 3);
    let index = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_schema WHERE type='index' AND name='installed_factor_owner'"
                .to_owned(),
        ))
        .await?;
    assert!(index.is_some());
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("installed-factor-secret-at-least-32-characters"),
        db.clone(),
    );
    let legacy = store.get_two_factor_by_user_id("owner").await?.unwrap();
    assert_eq!(legacy.verified, Some(true));
    assert_eq!(legacy.failed_verification_count, Some(0.0));
    let nullable = store
        .get_two_factor_by_user_id("nullable-owner")
        .await?
        .unwrap();
    assert_eq!(nullable.verified, None);
    assert_eq!(nullable.failed_verification_count, None);
    let incremented_null = store
        .increment_two_factor_failure(&nullable.id)
        .await?
        .unwrap();
    assert_eq!(incremented_null.failed_verification_count, None);
    assert!(
        store
            .set_two_factor_lock_if_count_at_least(&nullable.id, 0.0, Utc::now())
            .await?
            .is_none()
    );
    let _ignored_execute_unprepared_4 = db
        .execute_unprepared(
            "UPDATE two_factor SET failed_verification_count=0.25 WHERE id='defaults'",
        )
        .await?;
    let fraction = store
        .get_two_factor_by_user_id("default-owner")
        .await?
        .unwrap();
    assert_eq!(fraction.failed_verification_count, Some(0.25));
    db.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn independent_factor_connections_increment_nullable_numbers_and_conditionally_reset_or_consume()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!(
        "better-auth-factor-policy-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let url = format!("sqlite://{}?mode=rwc", directory.join("auth.sqlite").display());
        let mut first_options = ConnectOptions::new(url.clone());
        let _ignored_min_connections = first_options.max_connections(1).min_connections(1);
        let db = Database::connect(first_options).await?;
        run_migrations(&db).await?;
        // The factor table's preexisting FK requires an owner on this branch.
        let _ignored_execute_unprepared_5 = db.execute_unprepared("INSERT INTO users(id,name,email,email_verified,metadata,created_at,updated_at) VALUES('owner','Owner','owner@fixture.test',0,'{}','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')").await?;
        let config = AuthConfig::new("factor-policy-secret-at-least-32-characters");
        let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone());
        let factor = store.create_two_factor(CreateTwoFactor { user_id:"owner".into(),secret:"secret".into(),backup_codes:"old-backup".into(),..Default::default() }).await?;
        assert_eq!(factor.failed_verification_count, Some(0.0));
        let _ignored_execute_unprepared_6 = db.execute_unprepared("DROP INDEX idx_two_factor_user_id").await?;
        // Installed/custom schemas can contain multiple generations for one owner.
        let sibling = store.create_two_factor(CreateTwoFactor { user_id:"owner".into(),secret:"other-secret".into(),backup_codes:"other-backup".into(),..Default::default() }).await?;
        let mut connections = Vec::new();
        for _ in 0..8 {
            let mut options = ConnectOptions::new(url.clone());
            let _ignored_min_connections_2 = options.max_connections(1).min_connections(1);
            connections.push(Database::connect(options).await?);
        }
        let result = async {
            let barrier = Arc::new(Barrier::new(8));
            let mut tasks = JoinSet::new();
            for connection in &connections {
                let worker = SeaOrmStore::<BundledSchema>::new(config.clone(), connection.clone());
                let barrier = Arc::clone(&barrier); let id = factor.id.clone();
                drop(tasks.spawn(async move { let _ignored_wait = barrier.wait().await; worker.increment_two_factor_failure(&id).await }));
            }
            let mut counts = Vec::new();
            while let Some(row) = tasks.join_next().await { counts.push(row??.unwrap().failed_verification_count.unwrap()); }
            counts.sort_by(f64::total_cmp);
            assert_eq!(counts, (1..=8).map(f64::from).collect::<Vec<_>>());
            let physical = db.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                "SELECT typeof(failed_verification_count) AS affinity FROM two_factor WHERE id=?", [factor.id.clone().into()])).await?.unwrap();
            assert_eq!(physical.try_get::<String>("", "affinity")?, "integer");
            let now = Utc::now(); let future = now + Duration::minutes(15);
            assert!(store.set_two_factor_lock_if_count_at_least(&factor.id,8.5,future).await?.is_none());
            assert!(store.set_two_factor_lock_if_count_at_least(&factor.id,7.5,future).await?.is_some());
            assert!(store.clear_expired_two_factor_lock(&factor.id,now).await?.is_none());
            let barrier_2 = Arc::new(Barrier::new(8));
            let mut unlocks = JoinSet::new();
            for connection in &connections {
                let worker = SeaOrmStore::<BundledSchema>::new(config.clone(), connection.clone());
                let barrier_2_3 = Arc::clone(&barrier_2); let id = factor.id.clone();
                drop(unlocks.spawn(async move { let _ignored_wait_2 = barrier_2_3.wait().await; worker.clear_expired_two_factor_lock(&id, future).await }));
            }
            let mut winners = Vec::new();
            while let Some(row) = unlocks.join_next().await { if let Some(row) = row?? { winners.push(row); } }
            assert_eq!(winners.len(), 1);
            let unlocked = winners.pop().unwrap();
            assert_eq!(unlocked.failed_verification_count,Some(0.0)); assert_eq!(unlocked.locked_until,None);
            // A stale failure cannot set a lock after a concurrent success reset.
            assert!(store.set_two_factor_lock_if_count_at_least(&factor.id,1.0,future).await?.is_none());
            let _ignored_into = db.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                "UPDATE two_factor SET failed_verification_count=0.5 WHERE id=?", [factor.id.clone().into()])).await?;
            let incremented = store.increment_two_factor_failure(&factor.id).await?.unwrap();
            assert_eq!(incremented.failed_verification_count,Some(1.5));
            let updated = store.update_two_factor(&factor.id,UpdateTwoFactor {secret:Some("rotated".into()),verified:Some(false),..Default::default()}).await?.unwrap();
            assert_eq!(updated.failed_verification_count,Some(1.5)); assert_eq!(updated.verified,Some(false));
            assert_eq!(updated.created_at,factor.created_at); assert_eq!(updated.updated_at,factor.updated_at);
            let barrier_3 = Arc::new(Barrier::new(8)); let mut swaps = JoinSet::new();
            for (index,connection) in connections.iter().enumerate() {
                let worker = SeaOrmStore::<BundledSchema>::new(config.clone(),connection.clone()); let id=factor.id.clone(); let barrier_4=Arc::clone(&barrier_3);
                drop(swaps.spawn(async move { let _ignored_wait_3 = barrier_4.wait().await; worker.compare_and_swap_two_factor_backup_codes(&id,"old-backup",&format!("winner-{index}")).await }));
            }
            let mut winners_2=0; while let Some(row)=swaps.join_next().await { if row?? { winners_2+=1; } } assert_eq!(winners_2,1);
            store.reset_two_factor_failures(&factor.id).await?;
            let reset = store.update_two_factor(&factor.id,UpdateTwoFactor::default()).await?.unwrap();
            assert_eq!(reset.failed_verification_count,Some(0.0)); assert_eq!(reset.locked_until,None);
            assert_eq!(reset.secret,"rotated"); assert!(reset.backup_codes.starts_with("winner-"));
            let untouched = store.update_two_factor(&sibling.id,UpdateTwoFactor::default()).await?.unwrap();
            assert_eq!(serde_json::to_value(untouched)?,serde_json::to_value(sibling)?);
            assert!(store.increment_two_factor_failure("missing").await?.is_none());
            Ok::<_,Box<dyn std::error::Error>>(())
        }.await;
        for connection in connections { connection.close().await?; }
        db.close().await?;
        result
    }.await;
    std::fs::remove_dir_all(directory)?;
    outcome
}
