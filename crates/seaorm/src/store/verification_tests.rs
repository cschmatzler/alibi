#[expect(
    unreachable_pub,
    reason = "SeaORM's derive emits public entity associated types"
)]
mod uuid_verification {
    use super::*;
    use chrono::DateTime;
    use sea_orm::Set;
    use sea_orm::entity::prelude::*;
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
}

use super::*;
use crate::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use crate::store::{
    bundled_schema::BundledSchema, entities::verification, migrator::run_migrations,
};
use better_auth_core::AuthConfig;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, PaginatorTrait};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Barrier;
use tokio::task::JoinSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct RejectAfterVerificationCreation;

#[async_trait]
impl SeaOrmHooks<BundledSchema> for RejectAfterVerificationCreation {
    async fn after_create_verification(
        &self,
        _row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        Err(AuthError::bad_request("after callback rejected"))
    }
}

struct TransactionCreationHooks {
    events: Arc<tokio::sync::Mutex<Vec<String>>>,
}

impl TransactionCreationHooks {
    async fn observe(&self, event: String, context: &SeaOrmHookContext<'_>) -> AuthResult<()> {
        use crate::store::entities::{account, session, user};
        assert!(
            context.tx.is_none(),
            "after hooks must run after the transaction commits"
        );
        for count in [
            user::Entity::find()
                .count(context.db)
                .await
                .map_err(map_db_err)?,
            account::Entity::find()
                .count(context.db)
                .await
                .map_err(map_db_err)?,
            verification::Entity::find()
                .count(context.db)
                .await
                .map_err(map_db_err)?,
            session::Entity::find()
                .count(context.db)
                .await
                .map_err(map_db_err)?,
        ] {
            assert_eq!(
                count, 1,
                "all signup writes must be visible before any after hook"
            );
        }
        self.events.lock().await.push(event);
        Ok(())
    }
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for TransactionCreationHooks {
    async fn after_create_user(
        &self,
        row: &crate::store::entities::user::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.observe(
            format!("user:{}", row.email.as_deref().unwrap_or_default()),
            context,
        )
        .await
    }
    async fn after_create_account(
        &self,
        row: &crate::store::entities::account::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.observe(format!("account:{}", row.account_id), context)
            .await
    }
    async fn after_create_verification(
        &self,
        row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.observe(
            format!("verification:{}:{}", row.identifier, row.value),
            context,
        )
        .await
    }
    async fn after_create_session(
        &self,
        row: &crate::store::entities::session::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.observe(format!("session:{}", row.token), context)
            .await
    }
}

struct ConsumeHooks {
    cancel: bool,
    before: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
}

struct InvalidationHooks {
    cancel: bool,
    before: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
}

struct ExpirationHooks {
    cancel_second: bool,
    events: Arc<tokio::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for ExpirationHooks {
    async fn before_delete_verification(
        &self,
        row: &verification::Model,
        _context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.events
            .lock()
            .await
            .push(format!("before:{}:{}", row.identifier, row.value));
        Ok(if self.cancel_second && row.identifier == "expired-b" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    async fn after_delete_verification(
        &self,
        row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        assert!(
            verification::Entity::find_by_id(row.id.clone())
                .one(context.db)
                .await
                .map_err(map_db_err)?
                .is_none()
        );
        assert_eq!(
            verification::Entity::find()
                .count(context.db)
                .await
                .map_err(map_db_err)?,
            1
        );
        self.events
            .lock()
            .await
            .push(format!("after:{}:{}", row.identifier, row.value));
        Ok(())
    }
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for InvalidationHooks {
    async fn before_delete_verification(
        &self,
        _row: &verification::Model,
        _context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let _ = self.before.fetch_add(1, Ordering::SeqCst);
        Ok(if self.cancel {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }

    async fn after_delete_verification(
        &self,
        row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert_eq!(
            verification::Entity::find()
                .filter(verification::Column::Identifier.eq(&row.identifier))
                .count(context.db)
                .await
                .map_err(map_db_err)?,
            0
        );
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for ConsumeHooks {
    async fn before_delete_verification(
        &self,
        _row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        assert!(context.tx.is_some());
        let _ = self.before.fetch_add(1, Ordering::SeqCst);
        Ok(if self.cancel {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }

    async fn after_delete_verification(
        &self,
        row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        assert_eq!(
            verification::Entity::find()
                .filter(verification::Column::Identifier.eq(&row.identifier))
                .count(context.db)
                .await
                .map_err(map_db_err)?,
            0
        );
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// Separate pools and stores prove that SQL, rather than a local mutex,
// enforces one consume/reserve/update winner under concurrent requests.
struct UpdateSnapshotHook {
    observed: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for UpdateSnapshotHook {
    async fn after_update_verification(
        &self,
        row: &verification::Model,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        assert!(context.tx.is_none());
        self.observed
            .lock()
            .await
            .push((row.id.clone(), row.value.clone()));
        Ok(())
    }
}

struct UuidVerificationSchema;

impl AuthSchema for UuidVerificationSchema {
    type User = super::super::entities::user::Model;
    type Session = super::super::entities::session::Model;
    type Account = super::super::entities::account::Model;
    type Verification = uuid_verification::Model;
}

async fn memory_store() -> Result<SeaOrmStore<BundledSchema>, Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    Ok(SeaOrmStore::new(
        AuthConfig::new("verification-test-local-secret-at-least-32-chars"),
        database,
    ))
}

fn token(identifier: &str, value: &str, expiry: DateTime<Utc>) -> CreateVerification {
    CreateVerification {
        identifier: identifier.to_owned(),
        value: value.to_owned(),
        expires_at: expiry,
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn transactional_verification_creation_rolls_back_with_signup_work() -> TestResult {
    use crate::store::entities::{account, session, user};
    use better_auth_core::store::TransactionStore;
    use better_auth_core::{CreateAccount, CreateSession, CreateUser};
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let store = memory_store().await?.hook(TransactionCreationHooks {
        events: Arc::clone(&events),
    });
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
                            user_id: user.id.clone(),
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
                            user_id: user.id,
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
                    Ok::<better_auth_core::store::BoxedTransactionValue, AuthError>(Box::new(
                        verification.id,
                    ))
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
            for count in [
                user::Entity::find().count(store.connection()).await?,
                account::Entity::find().count(store.connection()).await?,
                verification::Entity::find()
                    .count(store.connection())
                    .await?,
                session::Entity::find().count(store.connection()).await?,
            ] {
                assert_eq!(count, 0);
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
            .map(|row| row.value),
        Some("654321:0".to_owned())
    );
    let callback_failure = memory_store().await?.hook(RejectAfterVerificationCreation);
    let outcome = callback_failure
        .transaction_boxed(Box::new(move |tx| {
            Box::pin(async move {
                drop(
                    tx.create_verification(token("after-hook-error", "already-committed", expires))
                        .await?,
                );
                Ok::<better_auth_core::store::BoxedTransactionValue, AuthError>(Box::new(()))
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
            .map(|row| row.value),
        Some("already-committed".to_owned()),
        "an after callback failure must not roll back committed writes"
    );
    Ok(())
}

async fn set_created_at(
    database: &DatabaseConnection,
    id: &str,
    created_at: DateTime<Utc>,
) -> AuthResult<()> {
    let _ignored_map_err = verification::Entity::update_many()
        .filter(verification::Column::Id.eq(id))
        .col_expr(
            verification::Column::CreatedAt,
            sea_orm::sea_query::Expr::value(created_at),
        )
        .exec(database)
        .await
        .map_err(map_db_err)?;
    Ok(())
}

// Upstream 1.7.6 internal-adapter consumeVerificationValue invalidates every
// generation, including a live older row when the newest generation expired.
#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn expired_latest_generation_is_visible_then_invalidates_live_siblings() -> TestResult {
    let store = memory_store().await?;
    let now = Utc::now();
    let older = store
        .create_verification(token(
            "generation",
            "older-live",
            now + chrono::Duration::hours(1),
        ))
        .await?;
    set_created_at(
        store.connection(),
        &older.id,
        now - chrono::Duration::minutes(2),
    )
    .await?;
    let newest = store
        .create_verification(token(
            "generation",
            "newest-expired",
            now - chrono::Duration::minutes(1),
        ))
        .await?;
    set_created_at(
        store.connection(),
        &newest.id,
        now - chrono::Duration::minutes(1),
    )
    .await?;
    let latest = store
        .get_latest_verification_by_identifier("generation")
        .await?;
    assert_eq!(
        latest.as_ref().map(|row| row.value.as_str()),
        Some("newest-expired")
    );
    assert_eq!(
        verification::Entity::find()
            .count(store.connection())
            .await?,
        2
    );
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
    assert_eq!(
        verification::Entity::find()
            .count(store.connection())
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn value_mismatch_preserves_latest_and_success_prevents_replay() -> TestResult {
    let store = memory_store().await?;
    let now = Utc::now();
    let older = store
        .create_verification(token(
            "single-use",
            "old-token",
            now + chrono::Duration::minutes(10),
        ))
        .await?;
    set_created_at(
        store.connection(),
        &older.id,
        now - chrono::Duration::minutes(1),
    )
    .await?;
    let newest = store
        .create_verification(token(
            "single-use",
            "new-token",
            now + chrono::Duration::minutes(10),
        ))
        .await?;
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
            .as_ref()
            .map(|row| row.id.as_str()),
        Some(newest.id.as_str())
    );
    assert_eq!(
        store
            .consume_verification("single-use", "new-token")
            .await?
            .as_ref()
            .map(|row| row.id.as_str()),
        Some(newest.id.as_str())
    );
    assert!(
        store
            .consume_verification_by_identifier("single-use")
            .await?
            .is_none()
    );
    assert_eq!(
        verification::Entity::find()
            .count(store.connection())
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn expiration_cleanup_can_veto_the_whole_batch_and_after_hooks_keep_deleted_snapshots()
-> TestResult {
    let store = memory_store().await?;
    let mut config = store.config().as_ref().clone();
    config.advanced.database.default_find_many_limit = 2;
    let store = SeaOrmStore::<BundledSchema>::new(config, store.connection().clone());
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
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let cancelled =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(ExpirationHooks {
                cancel_second: true,
                events: Arc::clone(&events),
            });
    assert_eq!(cancelled.delete_expired_verifications().await?, 0);
    assert_eq!(
        verification::Entity::find()
            .count(store.connection())
            .await?,
        4
    );
    assert_eq!(
        *events.lock().await,
        vec!["before:expired-a:first", "before:expired-b:second"]
    );
    events.lock().await.clear();
    let active =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(ExpirationHooks {
                cancel_second: false,
                events: Arc::clone(&events),
            });
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
        .ok_or_else(|| std::io::Error::other("Cleanup removed a live proof"))?;
    assert_eq!(live.value, "retained");
    assert_eq!(active.delete_expired_verifications().await?, 0);
    assert_eq!(
        events.lock().await.len(),
        4,
        "an empty cleanup must not invoke hooks"
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn identifier_invalidation_uses_one_hook_snapshot_for_all_siblings() -> TestResult {
    let store = memory_store().await?;
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let expiry = Utc::now() + chrono::Duration::minutes(10);
    drop(
        store
            .create_verification(token("invalidate", "first", expiry))
            .await?,
    );
    drop(
        store
            .create_verification(token("invalidate", "second", expiry))
            .await?,
    );
    let cancelled =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(InvalidationHooks {
                cancel: true,
                before: Arc::clone(&before),
                after: Arc::clone(&after),
            });
    cancelled
        .delete_verifications_by_identifier("invalidate")
        .await?;
    assert_eq!(
        verification::Entity::find()
            .count(store.connection())
            .await?,
        2
    );
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 0);
    let active =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(InvalidationHooks {
                cancel: false,
                before: Arc::clone(&before),
                after: Arc::clone(&after),
            });
    active
        .delete_verifications_by_identifier("invalidate")
        .await?;
    assert_eq!(
        verification::Entity::find()
            .count(store.connection())
            .await?,
        0
    );
    assert_eq!(before.load(Ordering::SeqCst), 2);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    active
        .delete_verifications_by_identifier("invalidate")
        .await?;
    assert_eq!(before.load(Ordering::SeqCst), 2);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn consume_lifecycle_hooks_cancel_or_run_once_after_commit() -> TestResult {
    let store = memory_store().await?;
    let now = Utc::now();
    drop(
        store
            .create_verification(token(
                "hooked",
                "secret",
                now + chrono::Duration::minutes(10),
            ))
            .await?,
    );
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let cancelled =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(ConsumeHooks {
                cancel: true,
                before: Arc::clone(&before),
                after: Arc::clone(&after),
            });
    assert!(
        cancelled
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
    let active =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(ConsumeHooks {
                cancel: false,
                before: Arc::clone(&before),
                after: Arc::clone(&after),
            });
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
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn compare_and_swap_updates_only_the_expected_generation() -> TestResult {
    let store = memory_store().await?;
    let expiry = Utc::now() + chrono::Duration::minutes(10);
    let row = store
        .create_verification(token("attempts", "123456:0", expiry))
        .await?;
    let next_expiry = expiry + chrono::Duration::minutes(1);
    assert!(
        !store
            .compare_and_swap_verification(&row.id, "wrong-snapshot", "123456:1", next_expiry)
            .await?
    );
    assert!(
        store
            .compare_and_swap_verification(&row.id, "123456:0", "123456:1", next_expiry)
            .await?
    );
    assert!(
        !store
            .compare_and_swap_verification(&row.id, "123456:0", "123456:2", expiry)
            .await?
    );
    let updated = store
        .get_latest_verification_by_identifier("attempts")
        .await?
        .ok_or_else(|| std::io::Error::other("updated generation disappeared"))?;
    assert_eq!(updated.value, "123456:1");
    assert_eq!(updated.expires_at, next_expiry);
    assert!(updated.updated_at >= row.updated_at);
    store.delete_verifications_by_identifier("attempts").await?;
    assert!(
        !store
            .compare_and_swap_verification(&row.id, "123456:1", "123456:2", expiry)
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
    let _ignored_execute_raw = store.connection().execute_raw(sea_orm::Statement::from_string(
        sea_orm::DbBackend::Sqlite,
        "CREATE TRIGGER remove_after_update AFTER UPDATE ON verifications WHEN NEW.identifier = 'callback-delete' BEGIN DELETE FROM verifications WHERE id = NEW.id; END",
    )).await?;
    let snapshots = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let hooked =
        SeaOrmStore::<BundledSchema>::new(Arc::clone(store.config()), store.connection().clone())
            .hook(UpdateSnapshotHook {
                observed: Arc::clone(&snapshots),
            });
    assert!(
        hooked
            .compare_and_swap_verification(&disappearing.id, "before", "winning", next_expiry)
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
        vec![(disappearing.id, "winning".to_owned())]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn independent_sqlite_stores_have_one_consume_reserve_and_update_winner() -> TestResult {
    let directory =
        std::env::temp_dir().join(format!("better-auth-verification-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.join("auth.sqlite").display()
        );
        let mut databases = Vec::new();
        let mut stores = Vec::new();
        let observed_updates = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        for index in 0..8 {
            let mut options = ConnectOptions::new(url.clone());
            let _ignored_max_connections = options.min_connections(1).max_connections(1);
            let database = Database::connect(options).await?;
            if index == 0 {
                run_migrations(&database).await?;
            }
            stores.push(Arc::new(
                SeaOrmStore::<BundledSchema>::new(
                    AuthConfig::new("independent-pool-verification-secret-at-least-32"),
                    database.clone(),
                )
                .hook(UpdateSnapshotHook {
                    observed: Arc::clone(&observed_updates),
                }),
            ));
            databases.push(database);
        }
        let primary = stores
            .first()
            .ok_or_else(|| std::io::Error::other("missing primary store"))?;
        let expiry = Utc::now() + chrono::Duration::minutes(10);
        let old = primary
            .create_verification(token("racing", "old", expiry))
            .await?;
        set_created_at(
            primary.connection(),
            &old.id,
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
                let _ignored_wait = barrier.wait().await;
                store.consume_verification_by_identifier("racing").await
            }));
        }
        let mut consumed = Vec::new();
        while let Some(result) = consumers.join_next().await {
            if let Some(row) = result?? {
                consumed.push(row);
            }
        }
        assert_eq!(consumed.len(), 1);
        assert_eq!(
            consumed.first().map(|row| row.id.as_str()),
            Some(newest.id.as_str())
        );
        assert_eq!(
            verification::Entity::find()
                .count(primary.connection())
                .await?,
            0
        );

        let barrier_2 = Arc::new(Barrier::new(8));
        let mut reservations = JoinSet::new();
        for (index, store) in stores.iter().enumerate() {
            let store = Arc::clone(store);
            let barrier_2_3 = Arc::clone(&barrier_2);
            drop(reservations.spawn(async move {
                let _ignored_wait_2 = barrier_2_3.wait().await;
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
        assert_eq!(
            verification::Entity::find()
                .count(primary.connection())
                .await?,
            1
        );
        let reserved = primary
            .get_latest_verification_by_identifier("claim")
            .await?
            .ok_or_else(|| std::io::Error::other("missing reservation"))?;
        let barrier_3 = Arc::new(Barrier::new(8));
        let mut updates = JoinSet::new();
        for (index, store) in stores.iter().enumerate() {
            let store = Arc::clone(store);
            let barrier_4_5 = Arc::clone(&barrier_3);
            let row = reserved.clone();
            drop(updates.spawn(async move {
                let _ignored_wait_3 = barrier_4_5.wait().await;
                store
                    .compare_and_swap_verification(
                        &row.id,
                        &row.value,
                        &format!("updated-{index}"),
                        expiry,
                    )
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
        let barrier_4 = Arc::new(Barrier::new(64));
        let mut snapshot_races = JoinSet::new();
        for attempt in 0..64 {
            let identifier = format!("snapshot-race-{attempt}");
            let row = primary
                .create_verification(token(&identifier, "before-update", expiry))
                .await?;
            let updating_store = Arc::clone(primary);
            let consuming_store = Arc::clone(
                stores
                    .get(4 + attempt % 4)
                    .ok_or_else(|| std::io::Error::other("missing consumer store"))?,
            );
            let barrier_6 = Arc::clone(&barrier_4);
            expected_snapshots.push((row.id.clone(), "winning-snapshot".to_owned()));
            drop(snapshot_races.spawn(async move {
                let _ignored_wait_4 = barrier_6.wait().await;
                let update = updating_store.compare_and_swap_verification(
                    &row.id,
                    "before-update",
                    "winning-snapshot",
                    expiry,
                );
                let consume = async {
                    // Observe the real SQL update through a separate pool,
                    // then race consumption against its after callback.
                    loop {
                        if consuming_store
                            .get_latest_verification_by_identifier(&identifier)
                            .await?
                            .is_some_and(|row_2| row_2.value == "winning-snapshot")
                        {
                            return consuming_store
                                .consume_verification_by_identifier(&identifier)
                                .await;
                        }
                        tokio::task::yield_now().await;
                    }
                };
                let (update_outcome, consumed_2) = tokio::join!(update, consume);
                assert!(update_outcome?);
                let consumed_2_3 = consumed_2?.ok_or_else(|| {
                    AuthError::internal("Concurrent consume lost the updated row")
                })?;
                assert_eq!(consumed_2_3.id, row.id);
                assert_eq!(consumed_2_3.value, "winning-snapshot");
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
        drop(stores);
        for database in databases {
            database.close().await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    std::fs::remove_dir_all(&directory)?;
    outcome
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn native_uuid_verification_schema_reserves_and_consumes_deterministically() -> TestResult {
    use sea_orm::{ConnectionTrait, Schema};
    let database = Database::connect("sqlite::memory:").await?;
    let _ignored_create_table_from_entity = database
        .execute(
            &Schema::new(database.get_database_backend())
                .create_table_from_entity(uuid_verification::Entity),
        )
        .await?;
    let store = SeaOrmStore::<UuidVerificationSchema>::new(
        AuthConfig::new("uuid-verification-schema-local-secret-32-chars"),
        database,
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
        .ok_or_else(|| std::io::Error::other("missing UUID reservation"))?;
    assert_eq!(reserved.value, "first");
    assert!(
        store
            .compare_and_swap_verification(reserved.id().as_ref(), "first", "updated", expiry)
            .await?
    );
    let consumed = store
        .consume_verification_by_identifier("uuid-claim")
        .await?
        .ok_or_else(|| std::io::Error::other("missing UUID consumption"))?;
    assert_eq!(consumed.id, reserved.id);
    assert_eq!(consumed.value, "updated");
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
            .map(|row| row.id),
        Some(reserved.id)
    );
    Ok(())
}
