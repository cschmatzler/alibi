//! Initialized verification policy across physical and secondary storage.
use super::*;
use alibi_core::store::{
    CacheAdapter, DatabaseHookContext, DatabaseHooks, HookBackend, MemoryCacheAdapter,
};
use alibi_core::verification::VerificationSnapshot;
use chrono::Duration;
use std::sync::atomic::AtomicUsize;

struct PublicationCache {
    inner: MemoryCacheAdapter,
    fail: AtomicBool,
}
#[async_trait]
impl CacheAdapter for PublicationCache {
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> AuthResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuthError::internal(
                "application cache rejected publication",
            ));
        }
        self.inner.set(key, value, ttl).await
    }
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.inner.get(key).await
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<String>> {
        self.inner.get_and_delete(key).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.inner.exists(key).await
    }
    async fn expire(&self, key: &str, ttl: Duration) -> AuthResult<()> {
        self.inner.expire(key, ttl).await
    }
    async fn clear(&self) -> AuthResult<()> {
        self.inner.clear().await
    }
}
struct PublicationHook {
    cache: Arc<PublicationCache>,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for PublicationHook {
    async fn after_create_verification_record(
        &self,
        snapshot: &VerificationSnapshot,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        let identifier = snapshot.data().get("identifier").unwrap().as_str().unwrap();
        let published = self
            .cache
            .get(&format!("verification:{identifier}"))
            .await?
            .unwrap();
        let published: Value = serde_json::from_str(&published).unwrap();
        assert_eq!(
            published["value"].as_str(),
            snapshot.data().get("value").unwrap().as_str()
        );
        let _ = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

pub(super) async fn exercise<B: Backend>(db: &Db) -> TestResult {
    for physical in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let cache = Arc::new(PublicationCache {
            inner: MemoryCacheAdapter::new(),
            fail: AtomicBool::new(false),
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let mut config = AuthConfig::new(SECRET);
        config.verification.secondary_storage = Some(cache.clone());
        config.verification.store_in_database = physical;
        config.verification.store_identifier.default = VerificationIdentifierStrategy::Custom(
            Arc::new(IdentifierHasher(Arc::new(AtomicBool::new(false)))),
        );
        let auth = Arc::new(
            AuthBuilder::new(config.clone())
                .store(B::hook(
                    B::store(Arc::new(config), &connection),
                    PublicationHook {
                        cache: cache.clone(),
                        calls: calls.clone(),
                    },
                ))
                .build()
                .await?,
        );
        let service = auth.context().verifications();
        let proof = |identifier: &str| CreateVerification {
            identifier: identifier.into(),
            value: "initial-proof".into(),
            expires_at: chrono::Utc::now() + Duration::minutes(5),
        };
        let created = service.create(proof("delivery")).await?.unwrap();
        assert_eq!(created.data().get("id").is_some(), physical);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(db.count("verifications").await?, i64::from(physical));
        let _ = service
            .update(
                "delivery",
                UpdateVerification {
                    value: Some("updated-proof".into()),
                    ..Default::default()
                },
            )
            .await?;
        let cached = cache
            .get("verification:application:delivery")
            .await?
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&cached)?["value"],
            "updated-proof"
        );
        // Legacy alias must be invalidated together with the transformed key.
        cache
            .set("verification:delivery", &cached, Duration::minutes(5))
            .await?;
        let consumed = service.consume("delivery").await?.unwrap();
        assert_eq!(
            consumed.data().get("value").unwrap().as_str(),
            Some("updated-proof")
        );
        assert!(cache.get("verification:delivery").await?.is_none());
        assert!(
            cache
                .get("verification:application:delivery")
                .await?
                .is_none()
        );
        assert_eq!(db.count("verifications").await?, 0);
        let _ = service.create(proof("atomic")).await?;
        let (left, right) = tokio::join!(service.consume("atomic"), service.consume("atomic"));
        let consumed = left?.into_iter().chain(right?).collect::<Vec<_>>();
        assert_eq!(consumed.len(), 1);
        assert_eq!(
            consumed[0].data().get("value").unwrap().as_str(),
            Some("initial-proof")
        );
        assert_eq!(db.count("verifications").await?, 0);
        // Cache-only mode must not borrow an unrelated persisted proof when its
        // configured authority has no value; dual mode must fall back to SQL.
        let _ = auth
            .store()
            .create_verification(proof("application:sql-only"))
            .await?;
        assert_eq!(service.find("sql-only").await?.is_some(), physical);
        assert_eq!(service.consume("sql-only").await?.is_some(), physical);
        assert_eq!(db.count("verifications").await?, i64::from(!physical));
        auth.store()
            .delete_verifications_by_identifier("application:sql-only")
            .await?;
        let reservation = service.reserve(proof("reservation")).await;
        if physical {
            assert!(reservation?);
            assert!(
                cache
                    .get("verification:application:reservation")
                    .await?
                    .is_some()
            );
            service.delete("reservation").await?;
        } else {
            assert!(reservation.is_err());
            assert!(
                cache
                    .get("verification:application:reservation")
                    .await?
                    .is_none()
            );
        }
        assert_eq!(db.count("verifications").await?, 0);
        // Update with no cache entry must not manufacture a redeemable proof.
        let updated = service
            .update(
                "missing",
                UpdateVerification {
                    value: Some("unissued".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.is_some(), !physical);
        assert!(service.consume("missing").await?.is_none());
        let before_calls = calls.load(Ordering::SeqCst);
        cache.fail.store(true, Ordering::SeqCst);
        assert!(service.create(proof("failed-outside")).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), before_calls);
        assert_eq!(db.count("verifications").await?, i64::from(physical));
        assert!(
            cache
                .get("verification:application:failed-outside")
                .await?
                .is_none()
        );
        auth.store()
            .delete_verifications_by_identifier("application:failed-outside")
            .await?;
        let transactional = auth.clone();
        let candidate = proof("failed-transaction");
        let outcome = auth
            .store()
            .transaction_boxed(Box::new(move |tx| {
                Box::pin(async move {
                    let _ = transactional
                        .context()
                        .verifications()
                        .create_in_transaction(tx, candidate)
                        .await?;
                    Ok(Box::new(()) as Box<dyn std::any::Any + Send>)
                })
            }))
            .await;
        assert!(outcome.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), before_calls);
        assert_eq!(db.count("verifications").await?, 0);
        assert!(
            cache
                .get("verification:application:failed-transaction")
                .await?
                .is_none()
        );
        B::close(connection).await?;
    }
    Ok(())
}
