use super::*;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn atomic_cache_consumption_has_one_winner_and_rejects_expired_values() -> AuthResult<()> {
    let cache = Arc::new(MemoryCacheAdapter::new());
    cache
        .set("token", "single-use", Duration::minutes(1))
        .await?;
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            let _ignored_wait = barrier.wait().await;
            cache.get_and_delete("token").await
        }));
    }
    let mut winners = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(value) = result.map_err(|error| AuthError::internal(error.to_string()))?? {
            winners.push(value);
        }
    }
    assert_eq!(winners, ["single-use"]);
    assert!(cache.get_and_delete("token").await?.is_none());
    cache
        .set("expired", "expired-value", Duration::seconds(-1))
        .await?;
    assert!(cache.get_and_delete("expired").await?.is_none());
    assert!(!cache.exists("expired").await?);
    Ok(())
}
