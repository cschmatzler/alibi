use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::{
    AuthConfig, CreateAccount, CreateSession, CreateUser, UpdateUser,
    entity::AuthUser,
    store::{AccountStore, SessionStore, UserStore},
};
use chrono::{Duration, Utc};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, Statement};
use sea_orm_migration::{MigrationTrait, MigratorTrait, SchemaManager};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn disabled_plugin_creation_preserves_sql_null() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("nullable-plugin-fields-local-test-secret-32"),
        database,
    );
    let user = store
        .create_user(CreateUser::new().with_email("disabled-plugin@example.com"))
        .await?;
    assert!(!user.two_factor_enabled());
    assert!(!user.banned());
    assert_eq!(user.two_factor_enabled_value(), None);
    assert_eq!(user.banned_value(), None);
    let row = store
        .connection()
        .query_one_raw(Statement::from_sql_and_values(
            store.connection().get_database_backend(),
            "SELECT two_factor_enabled, banned FROM users WHERE id = ?",
            vec![user.id.into()],
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("created user disappeared"))?;
    assert_eq!(row.try_get::<Option<bool>>("", "two_factor_enabled")?, None);
    assert_eq!(row.try_get::<Option<bool>>("", "banned")?, None);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn explicit_flags_persist_without_initializing_unrelated_updates()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("nullable-plugin-flags-explicit-local-secret-32"),
        database,
    );
    let unset = store
        .create_user(CreateUser::new().with_email("unset-fields@example.com"))
        .await?;
    let renamed = store
        .update_user(
            &unset.id,
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
        .get_user_by_id(&configured.id)
        .await?
        .ok_or_else(|| std::io::Error::other("created configured user disappeared"))?;
    assert!(persisted.two_factor_enabled());
    assert!(persisted.banned());
    assert_eq!(persisted.two_factor_enabled_value(), Some(true));
    assert_eq!(persisted.banned_value(), Some(true));
    let disabled = store
        .update_user(
            &configured.id,
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
            &unset.id,
            UpdateUser {
                two_factor_enabled: Some(false),
                banned: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(initialized.two_factor_enabled_value(), Some(false));
    assert_eq!(initialized.banned_value(), Some(false));
    Ok(())
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
async fn upgrades_populated_users_preserving_custom_schema_and_foreign_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    // An installed user table predating nullable fields, extended by its
    // application. The migration must retain the entire table definition.
    let _ignored_execute_unprepared = database.execute_unprepared(
        "CREATE TABLE users (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT, email TEXT UNIQUE, email_verified BOOLEAN NOT NULL DEFAULT FALSE,
            image TEXT, username TEXT UNIQUE, display_username TEXT,
            two_factor_enabled BOOLEAN CONSTRAINT two_factor_required NOT NULL DEFAULT (FALSE) CHECK(two_factor_enabled IN (0, 1)),
            role TEXT, banned BOOLEAN NOT NULL CONSTRAINT banned_default DEFAULT FALSE,
            ban_reason TEXT, ban_expires TEXT, metadata JSON NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            \"profile,notes\" TEXT NOT NULL DEFAULT 'retained,custom',
            display_label TEXT GENERATED ALWAYS AS (coalesce(name, 'unknown, user')) VIRTUAL
        )",
    ).await?;
    super::migrator::AuthMigrator::up(&database, Some(5)).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("nullable-plugin-upgrade-local-test-secret-32"),
        database.clone(),
    );
    let existing = store
        .create_user(CreateUser {
            id: Some("existing-upgrade-user".to_owned()),
            email: Some("existing-upgrade@example.com".to_owned()),
            name: Some("Existing user".to_owned()),
            two_factor_enabled: Some(true),
            banned: Some(false),
            ..Default::default()
        })
        .await?;
    let opposite = store
        .create_user(CreateUser {
            id: Some("opposite-upgrade-user".to_owned()),
            email: Some("opposite-upgrade@example.com".to_owned()),
            two_factor_enabled: Some(false),
            banned: Some(true),
            ..Default::default()
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: existing.id.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let account = store
        .create_account(CreateAccount {
            account_id: existing.id.clone(),
            provider_id: "credential".to_owned(),
            user_id: existing.id.clone(),
            password: Some("local-test-password-hash".to_owned()),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await?;
    let _ignored_execute_unprepared_2 = database.execute_unprepared(
        "CREATE TABLE custom_user_links (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE)",
    ).await?;
    let _ignored_execute_unprepared_3 = database
        .execute_unprepared(
            "INSERT INTO custom_user_links VALUES ('retained-link', 'existing-upgrade-user')",
        )
        .await?;
    let _ignored_execute_unprepared_4 = database
        .execute_unprepared(
            "CREATE UNIQUE INDEX idx_users_custom_email ON users(lower(email)) WHERE banned = 0",
        )
        .await?;
    let _ignored_execute_unprepared_5 = database
        .execute_unprepared("CREATE TABLE custom_user_events (user_id TEXT, observed_name TEXT)")
        .await?;
    let _ignored_execute_unprepared_6 = database.execute_unprepared(
        "CREATE TRIGGER custom_user_updated AFTER UPDATE OF name ON users BEGIN INSERT INTO custom_user_events VALUES (new.id, new.name); END",
    ).await?;
    let _ignored_execute_unprepared_7 = database
        .execute_unprepared(
            "CREATE VIEW visible_users AS SELECT id, banned, display_label FROM users",
        )
        .await?;
    run_migrations(&database).await?;
    run_migrations(&database).await?;
    let retained = store
        .get_user_by_id(&existing.id)
        .await?
        .ok_or_else(|| std::io::Error::other("upgrade lost existing user"))?;
    assert_eq!(retained.two_factor_enabled_value(), Some(true));
    assert_eq!(retained.banned_value(), Some(false));
    let other = store
        .get_user_by_id(&opposite.id)
        .await?
        .ok_or_else(|| std::io::Error::other("upgrade lost opposite user"))?;
    assert_eq!(other.two_factor_enabled_value(), Some(false));
    assert_eq!(other.banned_value(), Some(true));
    assert_eq!(
        store.get_session(&session.token).await?.map(|row| row.id),
        Some(session.id.clone())
    );
    assert_eq!(
        store
            .get_account("credential", &existing.id)
            .await?
            .map(|row| row.id),
        Some(account.id.clone())
    );
    let fields = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT \"profile,notes\", display_label FROM users WHERE id = 'existing-upgrade-user'"
                .to_owned(),
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("missing retained custom fields"))?;
    assert_eq!(
        fields.try_get::<String>("", "profile,notes")?,
        "retained,custom"
    );
    assert_eq!(
        fields.try_get::<String>("", "display_label")?,
        "Existing user"
    );
    let visible = database.query_one_raw(Statement::from_string(
        database.get_database_backend(),
        "SELECT id, banned, display_label FROM visible_users WHERE id = 'existing-upgrade-user'".to_owned(),
    )).await?.ok_or_else(|| std::io::Error::other("upgrade lost dependent view"))?;
    assert_eq!(visible.try_get::<String>("", "id")?, existing.id);
    assert!(!visible.try_get::<bool>("", "banned")?);
    let null_user = store
        .create_user(CreateUser::new().with_email("new-null-user@example.com"))
        .await?;
    assert_eq!(null_user.two_factor_enabled_value(), None);
    assert_eq!(null_user.banned_value(), None);
    drop(
        store
            .update_user(
                &existing.id,
                UpdateUser {
                    name: Some("Trigger still works".to_owned()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let event = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT user_id, observed_name FROM custom_user_events".to_owned(),
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("upgrade lost custom trigger"))?;
    assert_eq!(event.try_get::<String>("", "user_id")?, existing.id);
    assert_eq!(
        event.try_get::<String>("", "observed_name")?,
        "Trigger still works"
    );
    let unique_index = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT sql FROM sqlite_schema WHERE name = 'idx_users_custom_email'".to_owned(),
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("upgrade lost custom index"))?;
    assert!(
        unique_index
            .try_get::<String>("", "sql")?
            .contains("WHERE banned = 0")
    );
    assert!(
        database
            .execute_unprepared(
                "INSERT INTO custom_user_links VALUES ('invalid-link', 'missing-user')"
            )
            .await
            .is_err()
    );
    store.delete_user(&existing.id).await?;
    assert!(store.get_session(&session.token).await?.is_none());
    assert!(
        store
            .get_account("credential", &existing.id)
            .await?
            .is_none()
    );
    assert!(
        database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT id FROM custom_user_links WHERE id = 'retained-link'".to_owned(),
            ))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn rejected_rebuild_rolls_back_and_restores_foreign_key_enforcement()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    for sql in [
        "CREATE TABLE users (id TEXT PRIMARY KEY, two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE, banned BOOLEAN NOT NULL DEFAULT FALSE, profile TEXT)",
        "INSERT INTO users VALUES ('retained', 1, 0, 'custom preserved')",
        "CREATE TABLE custom_user_links (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id))",
        "PRAGMA foreign_keys = OFF",
        "INSERT INTO custom_user_links VALUES ('preexisting-invalid-link', 'missing-user')",
        "PRAGMA foreign_keys = ON",
    ] {
        let _ignored_execute_unprepared_8 = database.execute_unprepared(sql).await?;
    }
    let error = super::nullable_user_flags::NullableUserPluginFlags
        .up(&SchemaManager::new(&database))
        .await
        .expect_err("the existing invalid relationship must stop this rebuild");
    assert!(
        error
            .to_string()
            .contains("invalid foreign-key relationships")
    );
    let row = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT two_factor_enabled, banned, profile FROM users WHERE id = 'retained'"
                .to_owned(),
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("rollback lost the user"))?;
    assert!(row.try_get::<bool>("", "two_factor_enabled")?);
    assert!(!row.try_get::<bool>("", "banned")?);
    assert_eq!(row.try_get::<String>("", "profile")?, "custom preserved");
    assert!(
        database
            .execute_unprepared(
                "INSERT INTO custom_user_links VALUES ('new-invalid-link', 'missing-user')"
            )
            .await
            .is_err()
    );
    let flags = database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            "PRAGMA table_info(users)".to_owned(),
        ))
        .await?;
    for row_3 in flags.iter().filter(|row_2| {
        row_2
            .try_get::<String>("", "name")
            .is_ok_and(|name| name == "two_factor_enabled" || name == "banned")
    }) {
        assert_eq!(row_3.try_get::<i64>("", "notnull")?, 1);
        assert!(row_3.try_get::<Option<String>>("", "dflt_value")?.is_some());
    }
    assert!(
        !SchemaManager::new(&database)
            .has_table("users__nullable_plugin_flags")
            .await?
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn canceled_rebuild_preserves_rows_and_does_not_reuse_a_connection_with_foreign_keys_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let directory = std::env::temp_dir().join(format!(
        "better-auth-nullable-cancel-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory)?;
    let outcome = async {
        let enabled = Arc::new(AtomicBool::new(false));
        let (started, observed) = tokio::sync::oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started)));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let mut options = ConnectOptions::new(format!("sqlite://{}?mode=rwc", directory.join("auth.sqlite").display()));
        let _ignored_cmp = options.max_connections(1).map_sqlx_sqlite_opts({
            let enabled = Arc::clone(&enabled);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            move |options_2| {
                let enabled = Arc::clone(&enabled);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                options_2.collation("nullable_copy_observer", move |left, right| {
                    if enabled.swap(false, Ordering::SeqCst) {
                        let sender = started.lock().unwrap().take();
                        if let Some(sender) = sender {
                            let _ignored_send = sender.send(());
                        }
                        let (lock, condition) = &*release;
                        let mut released = lock.lock().unwrap();
                        while !*released {
                            released = condition.wait(released).unwrap();
                        }
 drop(released);

                    }
                    left.cmp(right)
                })
            }
        });
        let database = Database::connect(options).await?;
        for sql in [
            "CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT COLLATE nullable_copy_observer UNIQUE, two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE, banned BOOLEAN NOT NULL DEFAULT FALSE, profile TEXT)",
            "INSERT INTO users VALUES ('first', 'first@example.com', 1, 0, 'first preserved')",
            "INSERT INTO users VALUES ('second', 'second@example.com', 0, 1, 'second preserved')",
            "CREATE TABLE custom_user_links (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id))",
            "INSERT INTO custom_user_links VALUES ('retained-link', 'first')",
        ] {
            let _ignored_execute_unprepared_9 = database.execute_unprepared(sql).await?;
        }
        enabled.store(true, Ordering::SeqCst);
        let work = {
            let database = database.clone();
            tokio::spawn(async move {
                super::nullable_user_flags::NullableUserPluginFlags.up(&SchemaManager::new(&database)).await
            })
        };
        // The database's real collation runs while copying the second row:
        // the rebuild is inside its transaction and foreign keys are off.
        tokio::time::timeout(std::time::Duration::from_secs(5), observed).await??;
        work.abort();
        assert!(work.await.unwrap_err().is_cancelled());
        {
            let (lock, condition) = &*release;
            *lock.lock().unwrap() = true;
            condition.notify_all();
        }
        let rows = tokio::time::timeout(std::time::Duration::from_secs(10), database.query_all_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT id, profile, two_factor_enabled, banned FROM users ORDER BY id".to_owned(),
        ))).await??;
        assert_eq!(rows.len(), 2);
        assert_eq!((*(rows).first().expect("fixture contains the requested index")).try_get::<String>("", "profile")?, "first preserved");
        assert_eq!((*(rows).get(1).expect("fixture contains the requested index")).try_get::<String>("", "profile")?, "second preserved");
        assert!((*(rows).first().expect("fixture contains the requested index")).try_get::<bool>("", "two_factor_enabled")?);
        assert!((*(rows).get(1).expect("fixture contains the requested index")).try_get::<bool>("", "banned")?);
        assert!(database.execute_unprepared(
            "INSERT INTO custom_user_links VALUES ('new-invalid-link', 'missing-user')"
        ).await.is_err());
        assert!(database.execute_unprepared(
            "INSERT INTO users (id, email, two_factor_enabled, banned) VALUES ('invalid-null-user', 'invalid-null@example.com', NULL, NULL)"
        ).await.is_err());
        assert!(!SchemaManager::new(&database).has_table("users__nullable_plugin_flags").await?);
        database.close().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }.await;
    std::fs::remove_dir_all(&directory)?;
    outcome
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn nullable_upgrade_preserves_numeric_id_sequence_and_hidden_row_identity()
-> Result<(), Box<dyn std::error::Error>> {
    for (id_type, extra_key, retained_rowid, auto_increment) in [
        ("INTEGER PRIMARY KEY AUTOINCREMENT", "", 10, true),
        ("TEXT PRIMARY KEY", "", 40, false),
        ("INTEGER PRIMARY KEY DESC", "", 40, false),
        ("INTEGER", ", PRIMARY KEY(id, tenant)", 40, false),
    ] {
        let database = Database::connect("sqlite::memory:").await?;
        let _ignored_execute_unprepared_10 = database.execute_unprepared(&format!(
            "CREATE TABLE users (id {id_type}, tenant TEXT NOT NULL DEFAULT 'local', two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE, banned BOOLEAN NOT NULL DEFAULT FALSE{extra_key})"
        )).await?;
        for sql in [
            format!("INSERT INTO users (rowid, id) VALUES ({retained_rowid}, 10)"),
            format!(
                "INSERT INTO users (rowid, id) VALUES ({}, 20)",
                if auto_increment { 20 } else { 80 }
            ),
            "DELETE FROM users WHERE id = 20".to_owned(),
        ] {
            let _ignored_execute_unprepared_11 = database.execute_unprepared(&sql).await?;
        }
        super::nullable_user_flags::NullableUserPluginFlags
            .up(&SchemaManager::new(&database))
            .await?;
        let retained = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT rowid AS retained_row FROM users WHERE id = 10".to_owned(),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("upgrade lost ID"))?;
        assert_eq!(
            retained.try_get::<i64>("", "retained_row")?,
            retained_rowid,
            "{id_type}"
        );
        if auto_increment {
            let _ignored_execute_unprepared_12 = database
                .execute_unprepared(
                    "INSERT INTO users (two_factor_enabled, banned) VALUES (NULL, NULL)",
                )
                .await?;
            let generated = database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT id FROM users WHERE id != 10".to_owned(),
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("numeric ID was not generated"))?;
            assert_eq!(generated.try_get::<i64>("", "id")?, 21);
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn installed_without_rowid_tables_and_unary_defaults_preserve_custom_values()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    for sql in [
        "CREATE TABLE users(id TEXT PRIMARY KEY, two_factor_enabled BOOLEAN NOT /* retained */ NULL DEFAULT+0, banned BOOLEAN NOT NULL DEFAULT-0, \"profile,notes\" TEXT DEFAULT 'value,retained') WITHOUT ROWID",
        "INSERT INTO users(id) VALUES('old')",
    ] {
        let _ignored_execute_unprepared_13 = database.execute_unprepared(sql).await?;
    }
    super::nullable_user_flags::NullableUserPluginFlags
        .up(&SchemaManager::new(&database))
        .await?;
    let _ignored_execute_unprepared_14 = database
        .execute_unprepared("INSERT INTO users(id) VALUES('new')")
        .await?;
    let rows = database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT id, two_factor_enabled, banned, \"profile,notes\" FROM users ORDER BY id"
                .to_owned(),
        ))
        .await?;
    let new = rows
        .first()
        .ok_or_else(|| std::io::Error::other("missing new user"))?;
    assert_eq!(new.try_get::<String>("", "id")?, "new");
    assert_eq!(new.try_get::<Option<bool>>("", "two_factor_enabled")?, None);
    assert_eq!(new.try_get::<Option<bool>>("", "banned")?, None);
    assert_eq!(
        new.try_get::<String>("", "profile,notes")?,
        "value,retained"
    );
    let old = rows
        .get(1)
        .ok_or_else(|| std::io::Error::other("missing old user"))?;
    assert_eq!(old.try_get::<String>("", "id")?, "old");
    assert_eq!(
        old.try_get::<Option<bool>>("", "two_factor_enabled")?,
        Some(false)
    );
    assert_eq!(old.try_get::<Option<bool>>("", "banned")?, Some(false));
    assert!(
        database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT rowid FROM users".to_owned()
            ))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn upgrades_named_not_null_conflict_rules_without_dropping_checks()
-> Result<(), Box<dyn std::error::Error>> {
    for conflict in ["ABORT", "FAIL", "IGNORE", "REPLACE", "ROLLBACK"] {
        let database = Database::connect("sqlite::memory:").await?;
        let _ignored_execute_unprepared_15 = database.execute_unprepared(&format!(
            "CREATE TABLE users(id TEXT PRIMARY KEY, two_factor_enabled BOOLEAN NOT NULL ON CONFLICT {conflict} DEFAULT FALSE, banned BOOLEAN CONSTRAINT ban_required NOT NULL ON CONFLICT {conflict} DEFAULT FALSE CHECK(banned IN (0,1)))"
        )).await?;
        let _ignored_execute_unprepared_16 = database
            .execute_unprepared("INSERT INTO users(id) VALUES('old')")
            .await?;
        super::nullable_user_flags::NullableUserPluginFlags
            .up(&SchemaManager::new(&database))
            .await?;
        let _ignored_execute_unprepared_17 = database
            .execute_unprepared("INSERT INTO users(id) VALUES('new')")
            .await?;
        let rows = database
            .query_all_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT id, two_factor_enabled, banned FROM users ORDER BY id".to_owned(),
            ))
            .await?;
        let new = rows
            .first()
            .ok_or_else(|| std::io::Error::other("missing new user"))?;
        assert_eq!(new.try_get::<Option<bool>>("", "two_factor_enabled")?, None);
        assert_eq!(new.try_get::<Option<bool>>("", "banned")?, None);
        let old = rows
            .get(1)
            .ok_or_else(|| std::io::Error::other("missing old user"))?;
        assert_eq!(
            old.try_get::<Option<bool>>("", "two_factor_enabled")?,
            Some(false)
        );
        assert_eq!(old.try_get::<Option<bool>>("", "banned")?, Some(false));
        assert!(
            database
                .execute_unprepared("UPDATE users SET banned = 2 WHERE id = 'new'")
                .await
                .is_err()
        );
    }
    Ok(())
}
