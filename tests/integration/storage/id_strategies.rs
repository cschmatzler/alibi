//! Persistent sequence allocation across adapter instances and deleted rows.
use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::{AuthConfig, config::DatabaseIdStrategy};
use alibi_core::{
    AuthUser, CreateUser,
    store::{SchemaMigrator, UserStore},
};
use std::{collections::BTreeSet, sync::Arc};

backend_tests!(serial_ids_survive_overlapping_instances_and_deletion);
postgres_tests!(serial_ids_survive_overlapping_instances_and_deletion);

async fn serial_ids_survive_overlapping_instances_and_deletion<B: Backend>(db: Db) -> TestResult {
    let connection = B::connect(&db.url, None).await?;
    let mut config = AuthConfig::new("serial-id-persistence-contract-secret");
    config.advanced.database.generate_id = Some(DatabaseIdStrategy::Serial);
    let config = Arc::new(config);
    let first = B::store(config.clone(), &connection);
    first.migrate().await?;
    let initial = first
        .create_user(CreateUser::new().with_email("initial@example.test"))
        .await?;
    assert_eq!(initial.id(), "1");
    first.delete_user("1").await?;
    let second_connection = B::connect(&db.url, None).await?;
    let second = B::store(config.clone(), &second_connection);
    let (left, right) = tokio::join!(
        first.create_user(CreateUser::new().with_email("left@example.test")),
        second.create_user(CreateUser::new().with_email("right@example.test")),
    );
    let ids = BTreeSet::from([left?.id().into_owned(), right?.id().into_owned()]);
    assert_eq!(ids, BTreeSet::from(["2".to_owned(), "3".to_owned()]));
    drop(first);
    drop(second);
    B::close(connection).await?;
    B::close(second_connection).await?;
    let reopened = B::connect(&db.url, None).await?;
    let store = B::store(config, &reopened);
    let user = store
        .create_user(CreateUser::new().with_email("reopened@example.test"))
        .await?;
    assert_eq!(user.id(), "4");
    assert_eq!(db.count("users").await?, 3);
    B::close(reopened).await
}
