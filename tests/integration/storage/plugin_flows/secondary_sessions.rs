//! Secondary-storage-only sessions are unindexed and evicted when their owner signs out.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use super::*;
use alibi_core::store::{CacheAdapter, MemoryCacheAdapter};

backend_tests!(sign_out_evicts_the_cached_session_and_its_owner_index);
postgres_tests!(sign_out_evicts_the_cached_session_and_its_owner_index);

async fn sign_out_evicts_the_cached_session_and_its_owner_index<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.secondary_storage = Some(cache.clone());
    config.session.store_in_database = false;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let first = signup(&auth, "first@example.test").await;
    let token = body(&first)["token"].as_str().unwrap().to_owned();
    let user_id = body(&first)["user"]["id"].as_str().unwrap().to_owned();
    let second = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"first@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let other = body(&second)["token"].as_str().unwrap().to_owned();
    assert_eq!(db.count("sessions").await?, 0);
    let index = format!("active-sessions-{user_id}");
    let listed = cache.get(&index).await?.unwrap();
    assert!(listed.contains(&token) && listed.contains(&other));

    let _ = call(
        &auth,
        request("/sign-out", Some(json!({})), &cookies(&first)),
        200,
    )
    .await;
    assert_eq!(cache.get(&token).await?, None);
    let listed = cache.get(&index).await?.unwrap();
    assert!(!listed.contains(&token) && listed.contains(&other));
    assert!(cache.get(&other).await?.is_some());
    Ok(())
}
