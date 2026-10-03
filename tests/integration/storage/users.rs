//! Nullable plugin flags on the bundled user table.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use better_auth_core::{AuthUser, CreateUser, UpdateUser, store::UserStore};

backend_tests!(
    disabled_plugin_creation_preserves_sql_null,
    explicit_flags_persist_without_initializing_unrelated_updates,
);
postgres_tests!(
    disabled_plugin_creation_preserves_sql_null,
    explicit_flags_persist_without_initializing_unrelated_updates,
);

async fn disabled_plugin_creation_preserves_sql_null<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("nullable-plugin-fields-local-test-secret-32")
        .await?;
    let user = store
        .create_user(CreateUser::new().with_email("disabled-plugin@example.com"))
        .await?;
    assert!(!user.two_factor_enabled());
    assert!(!user.banned());
    assert_eq!(user.two_factor_enabled_value(), None);
    assert_eq!(user.banned_value(), None);
    assert_eq!(
        db.text(
            "SELECT CASE WHEN two_factor_enabled IS NULL AND banned IS NULL THEN 'null,null' END FROM users WHERE id = $1",
            &[user.id().as_ref()]
        )
        .await?,
        Some("null,null".to_owned())
    );
    B::close(connection).await
}

async fn explicit_flags_persist_without_initializing_unrelated_updates<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("nullable-plugin-flags-explicit-local-secret-32")
        .await?;
    let unset = store
        .create_user(CreateUser::new().with_email("unset-fields@example.com"))
        .await?;
    let renamed = store
        .update_user(
            unset.id().as_ref(),
            UpdateUser {
                name: Some("Unrelated update".to_owned()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(renamed.two_factor_enabled_value(), None);
    assert_eq!(renamed.banned_value(), None);
    let configured = store
        .create_user(CreateUser {
            email: Some("explicit-fields@example.com".to_owned()),
            two_factor_enabled: Some(true),
            banned: Some(true),
            ..Default::default()
        })
        .await?;
    let persisted = store
        .get_user_by_id(configured.id().as_ref())
        .await?
        .ok_or("created configured user disappeared")?;
    assert!(persisted.two_factor_enabled());
    assert!(persisted.banned());
    assert_eq!(persisted.two_factor_enabled_value(), Some(true));
    assert_eq!(persisted.banned_value(), Some(true));
    let disabled = store
        .update_user(
            configured.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                banned: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(disabled.two_factor_enabled_value(), Some(false));
    assert_eq!(disabled.banned_value(), Some(false));
    let initialized = store
        .update_user(
            unset.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                banned: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(initialized.two_factor_enabled_value(), Some(false));
    assert_eq!(initialized.banned_value(), Some(false));
    B::close(connection).await
}
