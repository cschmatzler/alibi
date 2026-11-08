use super::*;

backend_tests!(
    creation_sync_undefined_updated_at_matches_driver_failure,
    creation_async_undefined_updated_at_matches_driver_failure,
    refresh_sync_undefined_updated_at_matches_driver_failure,
    refresh_async_undefined_updated_at_matches_driver_failure
);
postgres_tests!(
    creation_sync_undefined_updated_at_matches_driver_failure,
    creation_async_undefined_updated_at_matches_driver_failure,
    refresh_sync_undefined_updated_at_matches_driver_failure,
    refresh_async_undefined_updated_at_matches_driver_failure
);

async fn creation_sync_undefined_updated_at_matches_driver_failure<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, "create", true).await
}
async fn creation_async_undefined_updated_at_matches_driver_failure<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "create", true).await
}
async fn refresh_sync_undefined_updated_at_matches_driver_failure<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, "update", true).await
}
async fn refresh_async_undefined_updated_at_matches_driver_failure<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "update", true).await
}
