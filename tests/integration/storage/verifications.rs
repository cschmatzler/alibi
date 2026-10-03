//! Verification generations, lifecycle hooks and compare-and-swap winners.

use super::{Backend, Db, Raw, TestResult, backend_tests, postgres_tests};
use async_trait::async_trait;
use better_auth::{AuthConfig, AuthSchema};
use better_auth_core::store::SchemaMigrator;
use better_auth_core::store::{
    BoxedTransactionValue, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl,
    TransactionStore, VerificationStore,
};
use better_auth_core::{
    AuthAccount, AuthError, AuthResult, AuthSession, AuthUser, AuthVerification, CreateAccount,
    CreateSession, CreateUser, CreateVerification,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Barrier, Mutex};
use tokio::task::JoinSet;

backend_tests!(
    transactional_verification_creation_rolls_back_with_signup_work,
    expired_latest_generation_is_visible_then_invalidates_live_siblings,
    value_mismatch_preserves_latest_and_success_prevents_replay,
    expiration_cleanup_can_veto_the_whole_batch_and_after_hooks_keep_deleted_snapshots,
    identifier_invalidation_uses_one_hook_snapshot_for_all_siblings,
    consume_lifecycle_hooks_cancel_or_run_once_after_commit,
    compare_and_swap_updates_only_the_expected_generation,
    independent_sqlite_stores_have_one_consume_reserve_and_update_winner,
    native_uuid_verification_schema_reserves_and_consumes_deterministically,
);
postgres_tests!(
    transactional_verification_creation_rolls_back_with_signup_work,
    expired_latest_generation_is_visible_then_invalidates_live_siblings,
    value_mismatch_preserves_latest_and_success_prevents_replay,
    expiration_cleanup_can_veto_the_whole_batch_and_after_hooks_keep_deleted_snapshots,
    identifier_invalidation_uses_one_hook_snapshot_for_all_siblings,
    consume_lifecycle_hooks_cancel_or_run_once_after_commit,
    independent_sqlite_stores_have_one_consume_reserve_and_update_winner,
    native_uuid_verification_schema_reserves_and_consumes_deterministically,
);

const SECRET: &str = "verification-test-local-secret-at-least-32-chars";

fn token(identifier: &str, value: &str, expiry: DateTime<Utc>) -> CreateVerification {
    CreateVerification {
        identifier: identifier.to_owned(),
        value: value.to_owned(),
        expires_at: expiry,
    }
}

async fn count(raw: &Raw, sql: &str, args: &[&str]) -> AuthResult<i64> {
    raw.count_where(sql, args)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))
}

async fn set_created_at(db: &Db, id: &str, created_at: DateTime<Utc>) -> TestResult {
    db.set_timestamp("verifications", "created_at", ("id", id), created_at)
        .await
}

struct RejectAfterVerificationCreation;

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for RejectAfterVerificationCreation {
    async fn after_create_verification(
        &self,
        _row: &S::Verification,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        Err(AuthError::bad_request("after callback rejected"))
    }
}

struct TransactionCreationHooks {
    raw: Raw,
    events: Arc<Mutex<Vec<String>>>,
}

impl TransactionCreationHooks {
    async fn observe<B: HookBackend>(
        &self,
        event: String,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(
            context.tx.is_none(),
            "after hooks must run after the transaction commits"
        );
        for table in ["users", "accounts", "verifications", "sessions"] {
            assert_eq!(
                count(&self.raw, &format!("SELECT COUNT(*) FROM {table}"), &[]).await?,
                1,
                "all signup writes must be visible before any after hook"
            );
        }
        self.events.lock().await.push(event);
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for TransactionCreationHooks {
    async fn after_create_user(
        &self,
        row: &S::User,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        self.observe(format!("user:{}", row.email().unwrap_or_default()), context)
            .await
    }
    async fn after_create_account(
        &self,
        row: &S::Account,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        self.observe(format!("account:{}", row.account_id()), context)
            .await
    }
    async fn after_create_verification(
        &self,
        row: &S::Verification,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        self.observe(
            format!("verification:{}:{}", row.identifier(), row.value()),
            context,
        )
        .await
    }
    async fn after_create_session(
        &self,
        row: &S::Session,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        self.observe(format!("session:{}", row.token()), context)
            .await
    }
}

/// Counts delete hooks; `transactional` asserts consume runs before-hooks in
/// its transaction while invalidation snapshots outside one.
struct DeleteHooks {
    raw: Raw,
    cancel: bool,
    transactional: Option<bool>,
    before: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
}

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for DeleteHooks {
    async fn before_delete_verification(
        &self,
        _row: &S::Verification,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        if let Some(transactional) = self.transactional {
            assert_eq!(context.tx.is_some(), transactional);
        }
        _ = self.before.fetch_add(1, Ordering::SeqCst);
        Ok(if self.cancel {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }

    async fn after_delete_verification(
        &self,
        row: &S::Verification,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        assert_eq!(
            count(
                &self.raw,
                "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
                &[row.identifier()]
            )
            .await?,
            0
        );
        _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ExpirationHooks {
    raw: Raw,
    cancel_second: bool,
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for ExpirationHooks {
    async fn before_delete_verification(
        &self,
        row: &S::Verification,
        _context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        self.events
            .lock()
            .await
            .push(format!("before:{}:{}", row.identifier(), row.value()));
        Ok(if self.cancel_second && row.identifier() == "expired-b" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_delete_verification(
        &self,
        row: &S::Verification,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        assert_eq!(
            count(
                &self.raw,
                "SELECT COUNT(*) FROM verifications WHERE id=$1",
                &[row.id().as_ref()]
            )
            .await?,
            0
        );
        assert_eq!(
            count(&self.raw, "SELECT COUNT(*) FROM verifications", &[]).await?,
            1
        );
        self.events
            .lock()
            .await
            .push(format!("after:{}:{}", row.identifier(), row.value()));
        Ok(())
    }
}

struct UpdateSnapshotHook {
    observed: Arc<Mutex<Vec<(String, String)>>>,
}

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for UpdateSnapshotHook {
    async fn after_update_verification(
        &self,
        row: &S::Verification,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        self.observed
            .lock()
            .await
            .push((row.id().into_owned(), row.value().to_owned()));
        Ok(())
    }
}

async fn transactional_verification_creation_rolls_back_with_signup_work<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = B::hook(
        store,
        TransactionCreationHooks {
            raw: db.raw.clone(),
            events: Arc::clone(&events),
        },
    );
    let expires = Utc::now() + chrono::Duration::minutes(5);
    for (identifier, commit) in [("signup-rolled-back", false), ("signup-committed", true)] {
        let work_events = Arc::clone(&events);
        let outcome = store
            .transaction_boxed(Box::new(move |tx| {
                Box::pin(async move {
                    let user = tx
                        .create_user(
                            CreateUser::new().with_email(format!("{identifier}@example.com")),
                        )
                        .await?;
                    drop(
                        tx.create_account(CreateAccount {
                            additional_fields: Default::default(),
                            user_id: user.id().into_owned(),
                            account_id: identifier.to_owned(),
                            provider_id: "credential".to_owned(),
                            access_token: None,
                            refresh_token: None,
                            id_token: None,
                            access_token_expires_at: None,
                            refresh_token_expires_at: None,
                            scope: None,
                            password: Some("stored-password".to_owned()),
                        })
                        .await?,
                    );
                    let verification = tx
                        .create_verification(token(identifier, "654321:0", expires))
                        .await?;
                    drop(
                        tx.create_session(CreateSession {
                            additional_fields: better_auth_core::field_policy::FieldValues::default(
                            ),
                            token: Some(identifier.to_owned()),
                            user_id: user.id().into_owned(),
                            expires_at: expires,
                            ip_address: None,
                            user_agent: None,
                            impersonated_by: None,
                            active_organization_id: None,
                            active_team_id: None,
                        })
                        .await?,
                    );
                    work_events
                        .lock()
                        .await
                        .push(format!("inside:{identifier}"));
                    if !commit {
                        return Err(AuthError::bad_request("email sender rejected signup"));
                    }
                    Ok::<BoxedTransactionValue, AuthError>(Box::new(verification.id().into_owned()))
                })
            }))
            .await;
        if commit {
            drop(outcome?);
        } else {
            assert!(
                matches!(outcome, Err(AuthError::BadRequest(message)) if message == "email sender rejected signup")
            );
            assert_eq!(*events.lock().await, vec!["inside:signup-rolled-back"]);
            for table in ["users", "accounts", "verifications", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        }
    }
    assert_eq!(
        *events.lock().await,
        vec![
            "inside:signup-rolled-back",
            "inside:signup-committed",
            "user:signup-committed@example.com",
            "account:signup-committed",
            "verification:signup-committed:654321:0",
            "session:signup-committed",
        ]
    );
    assert_eq!(
        store
            .get_latest_verification_by_identifier("signup-committed")
            .await?
            .map(|row| row.value().to_owned()),
        Some("654321:0".to_owned())
    );
    B::close(connection).await?;

    let db = db.fresh().await?;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let callback_failure = B::hook(store, RejectAfterVerificationCreation);
    let outcome = callback_failure
        .transaction_boxed(Box::new(move |tx| {
            Box::pin(async move {
                drop(
                    tx.create_verification(token("after-hook-error", "already-committed", expires))
                        .await?,
                );
                Ok::<BoxedTransactionValue, AuthError>(Box::new(()))
            })
        }))
        .await;
    assert!(
        matches!(outcome, Err(AuthError::BadRequest(message)) if message == "after callback rejected")
    );
    assert_eq!(
        callback_failure
            .get_latest_verification_by_identifier("after-hook-error")
            .await?
            .map(|row| row.value().to_owned()),
        Some("already-committed".to_owned()),
        "an after callback failure must not roll back committed writes"
    );
    B::close(connection).await
}

// Upstream 1.7.6 internal-adapter consumeVerificationValue invalidates every
// generation, including a live older row when the newest generation expired.
async fn expired_latest_generation_is_visible_then_invalidates_live_siblings<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let now = Utc::now();
    let older = store
        .create_verification(token(
            "generation",
            "older-live",
            now + chrono::Duration::hours(1),
        ))
        .await?;
    set_created_at(&db, older.id().as_ref(), now - chrono::Duration::minutes(2)).await?;
    let newest = store
        .create_verification(token(
            "generation",
            "newest-expired",
            now - chrono::Duration::minutes(1),
        ))
        .await?;
    set_created_at(
        &db,
        newest.id().as_ref(),
        now - chrono::Duration::minutes(1),
    )
    .await?;
    assert_eq!(
        store
            .get_latest_verification_by_identifier("generation")
            .await?
            .map(|row| row.value().to_owned()),
        Some("newest-expired".to_owned())
    );
    assert_eq!(db.count("verifications").await?, 2);
    assert!(
        store
            .consume_verification_by_identifier("generation")
            .await?
            .is_none()
    );
    assert!(
        store
            .consume_verification("generation", "older-live")
            .await?
            .is_none()
    );
    assert!(
        store
            .get_latest_verification_by_identifier("generation")
            .await?
            .is_none()
    );
    assert_eq!(db.count("verifications").await?, 0);
    B::close(connection).await
}

async fn value_mismatch_preserves_latest_and_success_prevents_replay<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let now = Utc::now();
    let older = store
        .create_verification(token(
            "single-use",
            "old-token",
            now + chrono::Duration::minutes(10),
        ))
        .await?;
    set_created_at(&db, older.id().as_ref(), now - chrono::Duration::minutes(1)).await?;
    let newest = store
        .create_verification(token(
            "single-use",
            "new-token",
            now + chrono::Duration::minutes(10),
        ))
        .await?;
    let newest_id = newest.id().into_owned();
    assert!(
        store
            .consume_verification("single-use", "old-token")
            .await?
            .is_none()
    );
    assert!(
        store
            .consume_verification("single-use", "incorrect")
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_latest_verification_by_identifier("single-use")
            .await?
            .map(|row| row.id().into_owned()),
        Some(newest_id.clone())
    );
    assert_eq!(
        store
            .consume_verification("single-use", "new-token")
            .await?
            .map(|row| row.id().into_owned()),
        Some(newest_id)
    );
    assert!(
        store
            .consume_verification_by_identifier("single-use")
            .await?
            .is_none()
    );
    assert_eq!(db.count("verifications").await?, 0);
    B::close(connection).await
}

async fn expiration_cleanup_can_veto_the_whole_batch_and_after_hooks_keep_deleted_snapshots<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let connection = B::connect(&db.url, None).await?;
    let mut config = AuthConfig::new(SECRET);
    config.advanced.database.default_find_many_limit = 2;
    let config = Arc::new(config);
    let store = B::store(Arc::clone(&config), &connection);
    store.migrate().await?;
    let now = Utc::now();
    for (identifier, value, expires) in [
        ("expired-a", "first", now - chrono::Duration::minutes(2)),
        ("expired-b", "second", now - chrono::Duration::minutes(1)),
        (
            "expired-c",
            "outside-hook-snapshot",
            now - chrono::Duration::minutes(1),
        ),
        ("live", "retained", now + chrono::Duration::minutes(5)),
    ] {
        drop(
            store
                .create_verification(token(identifier, value, expires))
                .await?,
        );
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let cancelled = B::hook(
        B::store(Arc::clone(&config), &connection),
        ExpirationHooks {
            raw: db.raw.clone(),
            cancel_second: true,
            events: Arc::clone(&events),
        },
    );
    assert_eq!(cancelled.delete_expired_verifications().await?, 0);
    assert_eq!(db.count("verifications").await?, 4);
    assert_eq!(
        *events.lock().await,
        vec!["before:expired-a:first", "before:expired-b:second"]
    );
    events.lock().await.clear();
    let active = B::hook(
        B::store(Arc::clone(&config), &connection),
        ExpirationHooks {
            raw: db.raw.clone(),
            cancel_second: false,
            events: Arc::clone(&events),
        },
    );
    // The adapter's findMany limit bounds hook snapshots, while the delete
    // predicate removes every expired record, including the unsnapshotted row.
    assert_eq!(active.delete_expired_verifications().await?, 3);
    assert_eq!(
        *events.lock().await,
        vec![
            "before:expired-a:first",
            "before:expired-b:second",
            "after:expired-a:first",
            "after:expired-b:second",
        ]
    );
    let live = store
        .get_latest_verification_by_identifier("live")
        .await?
        .ok_or("Cleanup removed a live proof")?;
    assert_eq!(live.value(), "retained");
    assert_eq!(active.delete_expired_verifications().await?, 0);
    assert_eq!(
        events.lock().await.len(),
        4,
        "an empty cleanup must not invoke hooks"
    );
    B::close(connection).await
}

async fn identifier_invalidation_uses_one_hook_snapshot_for_all_siblings<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let expiry = Utc::now() + chrono::Duration::minutes(10);
    for value in ["first", "second"] {
        drop(
            store
                .create_verification(token("invalidate", value, expiry))
                .await?,
        );
    }
    let hooked = |cancel| {
        B::hook(
            B::store(Arc::new(AuthConfig::new(SECRET)), &connection),
            DeleteHooks {
                raw: db.raw.clone(),
                cancel,
                transactional: None,
                before: Arc::clone(&before),
                after: Arc::clone(&after),
            },
        )
    };
    hooked(true)
        .delete_verifications_by_identifier("invalidate")
        .await?;
    assert_eq!(db.count("verifications").await?, 2);
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 0);
    let active = hooked(false);
    active
        .delete_verifications_by_identifier("invalidate")
        .await?;
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(before.load(Ordering::SeqCst), 2);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    active
        .delete_verifications_by_identifier("invalidate")
        .await?;
    assert_eq!(before.load(Ordering::SeqCst), 2);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    B::close(connection).await
}

async fn consume_lifecycle_hooks_cancel_or_run_once_after_commit<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    drop(
        store
            .create_verification(token(
                "hooked",
                "secret",
                Utc::now() + chrono::Duration::minutes(10),
            ))
            .await?,
    );
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let hooked = |cancel| {
        B::hook(
            B::store(Arc::new(AuthConfig::new(SECRET)), &connection),
            DeleteHooks {
                raw: db.raw.clone(),
                cancel,
                transactional: Some(true),
                before: Arc::clone(&before),
                after: Arc::clone(&after),
            },
        )
    };
    assert!(
        hooked(true)
            .consume_verification_by_identifier("hooked")
            .await?
            .is_none()
    );
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 0);
    assert!(
        store
            .get_latest_verification_by_identifier("hooked")
            .await?
            .is_some()
    );
    let active = hooked(false);
    assert!(
        active
            .consume_verification_by_identifier("hooked")
            .await?
            .is_some()
    );
    assert!(
        active
            .consume_verification_by_identifier("hooked")
            .await?
            .is_none()
    );
    assert_eq!(before.load(Ordering::SeqCst), 2);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    B::close(connection).await
}

async fn compare_and_swap_updates_only_the_expected_generation<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let expiry = Utc::now() + chrono::Duration::minutes(10);
    let row = store
        .create_verification(token("attempts", "123456:0", expiry))
        .await?;
    let id = row.id().into_owned();
    let next_expiry = expiry + chrono::Duration::minutes(1);
    assert!(
        !store
            .compare_and_swap_verification(&id, "wrong-snapshot", "123456:1", next_expiry)
            .await?
    );
    assert!(
        store
            .compare_and_swap_verification(&id, "123456:0", "123456:1", next_expiry)
            .await?
    );
    assert!(
        !store
            .compare_and_swap_verification(&id, "123456:0", "123456:2", expiry)
            .await?
    );
    let updated = store
        .get_latest_verification_by_identifier("attempts")
        .await?
        .ok_or("updated generation disappeared")?;
    assert_eq!(updated.value(), "123456:1");
    assert_eq!(updated.expires_at(), next_expiry);
    assert!(updated.updated_at() >= row.updated_at());
    store.delete_verifications_by_identifier("attempts").await?;
    assert!(
        !store
            .compare_and_swap_verification(&id, "123456:1", "123456:2", expiry)
            .await?
    );
    assert!(
        store
            .get_latest_verification_by_identifier("attempts")
            .await?
            .is_none()
    );

    // A real database trigger can consume the updated row before a second
    // SELECT. The pinned adapter returns the winning UPDATE snapshot even
    // then, so its after callback must still receive that value exactly once.
    let disappearing = store
        .create_verification(token("callback-delete", "before", expiry))
        .await?;
    let disappearing = disappearing.id().into_owned();
    _ = db.execute("CREATE TRIGGER remove_after_update AFTER UPDATE ON verifications WHEN NEW.identifier = 'callback-delete' BEGIN DELETE FROM verifications WHERE id = NEW.id; END", &[]).await?;
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    let hooked = B::hook(
        B::store(Arc::new(AuthConfig::new(SECRET)), &connection),
        UpdateSnapshotHook {
            observed: Arc::clone(&snapshots),
        },
    );
    assert!(
        hooked
            .compare_and_swap_verification(&disappearing, "before", "winning", next_expiry)
            .await?
    );
    assert!(
        store
            .get_latest_verification_by_identifier("callback-delete")
            .await?
            .is_none()
    );
    assert_eq!(
        *snapshots.lock().await,
        vec![(disappearing, "winning".to_owned())]
    );
    B::close(connection).await
}

// Separate pools and stores prove that SQL, rather than a local mutex,
// enforces one consume/reserve/update winner under concurrent requests.
async fn independent_sqlite_stores_have_one_consume_reserve_and_update_winner<B: Backend>(
    db: Db,
) -> TestResult {
    let config = Arc::new(AuthConfig::new(
        "independent-pool-verification-secret-at-least-32",
    ));
    let observed_updates = Arc::new(Mutex::new(Vec::new()));
    let mut connections = Vec::new();
    let mut stores = Vec::new();
    for index in 0..8 {
        let connection = B::connect(&db.url, Some(1)).await?;
        let store = B::store(Arc::clone(&config), &connection);
        if index == 0 {
            store.migrate().await?;
        }
        stores.push(Arc::new(B::hook(
            store,
            UpdateSnapshotHook {
                observed: Arc::clone(&observed_updates),
            },
        )));
        connections.push(connection);
    }
    let primary = Arc::clone(&stores[0]);
    let expiry = Utc::now() + chrono::Duration::minutes(10);
    let old = primary
        .create_verification(token("racing", "old", expiry))
        .await?;
    set_created_at(
        &db,
        old.id().as_ref(),
        Utc::now() - chrono::Duration::minutes(1),
    )
    .await?;
    let newest = primary
        .create_verification(token("racing", "newest", expiry))
        .await?;
    let barrier = Arc::new(Barrier::new(8));
    let mut consumers = JoinSet::new();
    for store in &stores {
        let store = Arc::clone(store);
        let barrier = Arc::clone(&barrier);
        drop(consumers.spawn(async move {
            _ = barrier.wait().await;
            store.consume_verification_by_identifier("racing").await
        }));
    }
    let mut consumed = Vec::new();
    while let Some(result) = consumers.join_next().await {
        if let Some(row) = result?? {
            consumed.push(row.id().into_owned());
        }
    }
    assert_eq!(consumed, vec![newest.id().into_owned()]);
    assert_eq!(db.count("verifications").await?, 0);

    let barrier = Arc::new(Barrier::new(8));
    let mut reservations = JoinSet::new();
    for (index, store) in stores.iter().enumerate() {
        let store = Arc::clone(store);
        let barrier = Arc::clone(&barrier);
        drop(reservations.spawn(async move {
            _ = barrier.wait().await;
            store
                .reserve_verification(token("claim", &format!("claimant-{index}"), expiry))
                .await
        }));
    }
    let mut reservation_winners = 0;
    while let Some(result) = reservations.join_next().await {
        if result?? {
            reservation_winners += 1;
        }
    }
    assert_eq!(reservation_winners, 1);
    assert_eq!(db.count("verifications").await?, 1);
    let reserved = primary
        .get_latest_verification_by_identifier("claim")
        .await?
        .ok_or("missing reservation")?;
    let (reserved_id, reserved_value) = (reserved.id().into_owned(), reserved.value().to_owned());
    let barrier = Arc::new(Barrier::new(8));
    let mut updates = JoinSet::new();
    for (index, store) in stores.iter().enumerate() {
        let store = Arc::clone(store);
        let barrier = Arc::clone(&barrier);
        let (id, value) = (reserved_id.clone(), reserved_value.clone());
        drop(updates.spawn(async move {
            _ = barrier.wait().await;
            store
                .compare_and_swap_verification(&id, &value, &format!("updated-{index}"), expiry)
                .await
        }));
    }
    let mut update_winners = 0;
    while let Some(result) = updates.join_next().await {
        if result?? {
            update_winners += 1;
        }
    }
    assert_eq!(update_winners, 1);
    assert_eq!(observed_updates.lock().await.len(), 1);
    assert!(
        primary
            .consume_verification_by_identifier("claim")
            .await?
            .is_some()
    );
    assert!(
        primary
            .reserve_verification(token("claim", "reclaimed", expiry))
            .await?
    );

    observed_updates.lock().await.clear();
    let mut expected_snapshots = Vec::new();
    let barrier = Arc::new(Barrier::new(64));
    let mut snapshot_races = JoinSet::new();
    for attempt in 0..64 {
        let identifier = format!("snapshot-race-{attempt}");
        let row = primary
            .create_verification(token(&identifier, "before-update", expiry))
            .await?;
        let row_id = row.id().into_owned();
        let updating_store = Arc::clone(&primary);
        let consuming_store = Arc::clone(&stores[4 + attempt % 4]);
        let barrier = Arc::clone(&barrier);
        expected_snapshots.push((row_id.clone(), "winning-snapshot".to_owned()));
        drop(snapshot_races.spawn(async move {
            _ = barrier.wait().await;
            let update = updating_store.compare_and_swap_verification(
                &row_id,
                "before-update",
                "winning-snapshot",
                expiry,
            );
            let consume = async {
                // Observe the real SQL update through a separate pool, then
                // race consumption against its after callback.
                loop {
                    if consuming_store
                        .get_latest_verification_by_identifier(&identifier)
                        .await?
                        .is_some_and(|row| row.value() == "winning-snapshot")
                    {
                        return consuming_store
                            .consume_verification_by_identifier(&identifier)
                            .await;
                    }
                    tokio::task::yield_now().await;
                }
            };
            let (update_outcome, consumed) = tokio::join!(update, consume);
            assert!(update_outcome?);
            let consumed = consumed?
                .ok_or_else(|| AuthError::internal("Concurrent consume lost the updated row"))?;
            assert_eq!(consumed.id().as_ref(), row_id);
            assert_eq!(consumed.value(), "winning-snapshot");
            Ok::<_, AuthError>(())
        }));
    }
    while let Some(result) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        snapshot_races.join_next(),
    )
    .await?
    {
        result??;
    }
    let observed = observed_updates.lock().await;
    assert_eq!(
        observed.len(),
        expected_snapshots.len(),
        "every successful CAS must notify once even after concurrent consumption"
    );
    for snapshot in expected_snapshots {
        assert_eq!(
            observed.iter().filter(|event| **event == snapshot).count(),
            1,
            "the after hook must receive the winning updated snapshot exactly once"
        );
    }
    drop(observed);
    drop(primary);
    drop(stores);
    for connection in connections {
        B::close(connection).await?;
    }
    Ok(())
}

async fn native_uuid_verification_schema_reserves_and_consumes_deterministically<B: Backend>(
    db: Db,
) -> TestResult {
    _ = db
        .execute(
            if db.is_postgres() {
                "CREATE TABLE uuid_verifications (id UUID NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)"
            } else {
                "CREATE TABLE uuid_verifications (id BLOB NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
            },
            &[],
        )
        .await?;
    let connection = B::connect(&db.url, None).await?;
    let store = B::uuid_store(
        Arc::new(AuthConfig::new(
            "uuid-verification-schema-local-secret-32-chars",
        )),
        &connection,
    );
    let expiry = Utc::now() + chrono::Duration::minutes(10);
    assert!(
        store
            .reserve_verification(token("uuid-claim", "first", expiry))
            .await?
    );
    assert!(
        !store
            .reserve_verification(token("uuid-claim", "other", expiry))
            .await?
    );
    let reserved = store
        .get_latest_verification_by_identifier("uuid-claim")
        .await?
        .ok_or("missing UUID reservation")?;
    assert_eq!(reserved.value(), "first");
    let reserved_id = reserved.id().into_owned();
    assert!(uuid::Uuid::parse_str(&reserved_id).is_ok());
    assert!(
        store
            .compare_and_swap_verification(&reserved_id, "first", "updated", expiry)
            .await?
    );
    let consumed = store
        .consume_verification_by_identifier("uuid-claim")
        .await?
        .ok_or("missing UUID consumption")?;
    assert_eq!(consumed.id().as_ref(), reserved_id);
    assert_eq!(consumed.value(), "updated");
    assert!(
        store
            .consume_verification_by_identifier("uuid-claim")
            .await?
            .is_none()
    );
    assert!(
        store
            .reserve_verification(token("uuid-claim", "reused", expiry))
            .await?
    );
    assert_eq!(
        store
            .get_latest_verification_by_identifier("uuid-claim")
            .await?
            .map(|row| row.id().into_owned()),
        Some(reserved_id)
    );
    if !db.is_postgres() {
        assert_eq!(
            db.text("SELECT typeof(id) FROM uuid_verifications", &[])
                .await?,
            Some("blob".to_owned())
        );
    }
    B::close(connection).await
}

#[expect(
    unreachable_pub,
    reason = "SeaORM's derive emits public entity associated types"
)]
pub(crate) mod seaorm_uuid {
    use better_auth::AuthSchema;
    use better_auth_core::entity::AuthVerification;
    use better_auth_core::{AuthError, AuthResult, CreateVerification};
    use better_auth_seaorm::SeaOrmVerificationModel;
    use better_auth_seaorm::sea_orm::{self, Set, entity::prelude::*};
    use better_auth_seaorm::store::entities::{account, session, user};
    use chrono::{DateTime, Utc};
    use std::borrow::Cow;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "uuid_verifications")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}

    impl AuthVerification for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn identifier(&self) -> &str {
            &self.identifier
        }
        fn value(&self) -> &str {
            &self.value
        }
        fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    impl SeaOrmVerificationModel for Model {
        type Id = Uuid;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;
        fn id_column() -> Self::Column {
            Column::Id
        }
        fn identifier_column() -> Self::Column {
            Column::Identifier
        }
        fn value_column() -> Self::Column {
            Column::Value
        }
        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn updated_at_column() -> Option<Self::Column> {
            Some(Column::UpdatedAt)
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_error| AuthError::bad_request("invalid UUID verification id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            verification: CreateVerification,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            ActiveModel {
                id: Set(id.unwrap_or_else(Uuid::new_v4)),
                identifier: Set(verification.identifier),
                value: Set(verification.value),
                expires_at: Set(verification.expires_at),
                created_at: Set(now),
                updated_at: Set(now),
            }
        }
    }

    pub(crate) struct Schema;

    impl AuthSchema for Schema {
        type User = user::Model;
        type Session = session::Model;
        type Account = account::Model;
        type Verification = Model;
    }
}

pub(crate) mod sqlx_uuid {
    use better_auth::AuthSchema;
    use better_auth_core::entity::AuthVerification;
    use better_auth_core::{AuthError, AuthResult, CreateVerification};
    use better_auth_sqlx::sqlx::{self, Row, postgres::PgRow, sqlite::SqliteRow};
    use better_auth_sqlx::store::entities::{account, session, user};
    use better_auth_sqlx::{
        ActiveRow, ColumnDef, SqlValue, SqlxModel, SqlxValue, SqlxVerificationModel,
    };
    use chrono::{DateTime, Utc};
    use std::borrow::Cow;
    use uuid::Uuid;

    #[derive(Clone, Debug, serde::Serialize)]
    pub(crate) struct Model {
        pub(crate) id: Uuid,
        pub(crate) identifier: String,
        pub(crate) value: String,
        pub(crate) expires_at: DateTime<Utc>,
        pub(crate) created_at: DateTime<Utc>,
        pub(crate) updated_at: DateTime<Utc>,
    }

    macro_rules! from_row {
        ($row:ty) => {
            impl<'r> sqlx::FromRow<'r, $row> for Model {
                fn from_row(row: &'r $row) -> Result<Self, sqlx::Error> {
                    Ok(Self {
                        id: row.try_get("id")?,
                        identifier: row.try_get("identifier")?,
                        value: row.try_get("value")?,
                        expires_at: row.try_get("expires_at")?,
                        created_at: row.try_get("created_at")?,
                        updated_at: row.try_get("updated_at")?,
                    })
                }
            }
        };
    }
    from_row!(SqliteRow);
    from_row!(PgRow);

    const COLUMNS: [&str; 6] = [
        "id",
        "identifier",
        "value",
        "expires_at",
        "created_at",
        "updated_at",
    ];

    impl SqlxModel for Model {
        const TABLE: &'static str = "uuid_verifications";
        const COLUMNS: &'static [ColumnDef] = &[
            ColumnDef {
                name: "id",
                kind: <Uuid as SqlxValue>::KIND,
            },
            ColumnDef {
                name: "identifier",
                kind: <String as SqlxValue>::KIND,
            },
            ColumnDef {
                name: "value",
                kind: <String as SqlxValue>::KIND,
            },
            ColumnDef {
                name: "expires_at",
                kind: <DateTime<Utc> as SqlxValue>::KIND,
            },
            ColumnDef {
                name: "created_at",
                kind: <DateTime<Utc> as SqlxValue>::KIND,
            },
            ColumnDef {
                name: "updated_at",
                kind: <DateTime<Utc> as SqlxValue>::KIND,
            },
        ];
        const PRIMARY_KEY: &'static str = "id";

        fn into_active(self) -> ActiveRow {
            let mut active = ActiveRow::new();
            active.unchanged("id", self.id);
            active.unchanged("identifier", self.identifier);
            active.unchanged("value", self.value);
            active.unchanged("expires_at", self.expires_at);
            active.unchanged("created_at", self.created_at);
            active.unchanged("updated_at", self.updated_at);
            active
        }

        fn from_active(mut active: ActiveRow) -> AuthResult<Self> {
            fn field<T: SqlxValue>(active: &mut ActiveRow, column: &str) -> AuthResult<T> {
                T::from_sql_value(active.take(column).into_value().unwrap_or_else(T::null))
                    .map_err(|_error| AuthError::internal(format!("{column} is NotSet")))
            }
            let [id, identifier, value, expires_at, created_at, updated_at] = COLUMNS;
            Ok(Self {
                id: field(&mut active, id)?,
                identifier: field(&mut active, identifier)?,
                value: field(&mut active, value)?,
                expires_at: field(&mut active, expires_at)?,
                created_at: field(&mut active, created_at)?,
                updated_at: field(&mut active, updated_at)?,
            })
        }
    }

    impl AuthVerification for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn identifier(&self) -> &str {
            &self.identifier
        }
        fn value(&self) -> &str {
            &self.value
        }
        fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    impl SqlxVerificationModel for Model {
        fn id_column() -> &'static str {
            "id"
        }
        fn identifier_column() -> &'static str {
            "identifier"
        }
        fn value_column() -> &'static str {
            "value"
        }
        fn expires_at_column() -> &'static str {
            "expires_at"
        }
        fn created_at_column() -> &'static str {
            "created_at"
        }
        fn updated_at_column() -> Option<&'static str> {
            Some("updated_at")
        }
        fn parse_id(id: &str) -> AuthResult<SqlValue> {
            id.parse::<Uuid>()
                .map(SqlxValue::into_sql_value)
                .map_err(|_error| AuthError::bad_request("invalid UUID verification id"))
        }
        fn new_active(
            id: Option<SqlValue>,
            verification: CreateVerification,
            now: DateTime<Utc>,
        ) -> ActiveRow {
            let mut active = ActiveRow::new();
            active.set("id", id.unwrap_or_else(|| Uuid::new_v4().into_sql_value()));
            active.set("identifier", verification.identifier);
            active.set("value", verification.value);
            active.set("expires_at", verification.expires_at);
            active.set("created_at", now);
            active.set("updated_at", now);
            active
        }
    }

    pub(crate) struct Schema;

    impl AuthSchema for Schema {
        type User = user::Model;
        type Session = session::Model;
        type Account = account::Model;
        type Verification = Model;
    }
}
