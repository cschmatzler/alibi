use super::*;

backend_tests!(
    creation_sync_replaced_descriptor_keeps_input_policy,
    creation_async_replaced_descriptor_keeps_input_policy,
    refresh_sync_replaced_descriptor_has_no_implicit_factory,
    refresh_async_replaced_descriptor_has_no_implicit_factory
);
postgres_tests!(
    creation_sync_replaced_descriptor_keeps_input_policy,
    creation_async_replaced_descriptor_keeps_input_policy,
    refresh_sync_replaced_descriptor_has_no_implicit_factory,
    refresh_async_replaced_descriptor_has_no_implicit_factory
);

async fn creation_sync_replaced_descriptor_keeps_input_policy<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "create", Policy::NoUpdateFactory).await
}

async fn creation_async_replaced_descriptor_keeps_input_policy<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "create", Policy::NoUpdateFactory).await
}

async fn refresh_sync_replaced_descriptor_has_no_implicit_factory<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, "update", Policy::NoUpdateFactory).await
}

async fn refresh_async_replaced_descriptor_has_no_implicit_factory<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "update", Policy::NoUpdateFactory).await
}
