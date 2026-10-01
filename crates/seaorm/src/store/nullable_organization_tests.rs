use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::{
    AuthConfig, CreateOrganization, UpdateOrganization, store::OrganizationStore,
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use serde_json::{Value, json};

async fn raw_metadata(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let row = database
        .query_one_raw(Statement::from_sql_and_values(
            database.get_database_backend(),
            "SELECT metadata FROM organization WHERE id = ?",
            [id.into()],
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("organization disappeared"))?;
    Ok(row.try_get("", "metadata")?)
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn public_store_distinguishes_omitted_and_literal_null_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("nullable-organization-metadata-public-store-secret"),
        database.clone(),
    );
    let absent = store
        .create_organization(CreateOrganization::new("Absent", "absent"))
        .await?;
    assert_eq!(absent.metadata, None);
    assert_eq!(raw_metadata(&database, &absent.id).await?, None);
    let literal = store
        .create_organization(
            CreateOrganization::new("Literal", "literal").with_metadata(Value::Null),
        )
        .await?;
    assert_eq!(literal.metadata, Some(Value::Null));
    assert_eq!(
        raw_metadata(&database, &literal.id).await?,
        Some("null".into())
    );
    for organization in [&absent, &literal] {
        let renamed = store
            .update_organization(
                &organization.id,
                UpdateOrganization {
                    name: Some("Renamed".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(renamed.metadata, organization.metadata);
        assert_eq!(renamed.slug, organization.slug);
        assert_eq!(renamed.created_at, organization.created_at);
    }
    for value in [
        json!({}),
        json!({"guard": [null, true, "kept"]}),
        Value::Null,
    ] {
        let updated = store
            .update_organization(
                &absent.id,
                UpdateOrganization {
                    metadata: Some(value.clone()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.metadata, Some(value.clone()));
        assert_eq!(
            raw_metadata(&database, &absent.id).await?,
            Some(better_auth_core::utils::json::to_string(&value)?)
        );
        let read = store
            .get_organization_by_id(&absent.id)
            .await?
            .ok_or_else(|| std::io::Error::other("organization disappeared"))?;
        assert_eq!(read.metadata, Some(value));
    }
    assert_eq!(
        store
            .get_organization_by_slug("literal")
            .await?
            .map(|row| row.metadata),
        Some(Some(Value::Null))
    );
    let rows = store
        .list_organizations_by_ids(&[absent.id, literal.id])
        .await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.metadata == Some(Value::Null)));
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn installed_organization_upgrade_preserves_bytes_custom_schema_and_references()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    for sql in [
        "CREATE TABLE organization (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, logo TEXT, metadata JSON CONSTRAINT metadata_required NOT NULL ON CONFLICT FAIL CONSTRAINT metadata_default DEFAULT ('{}') CHECK(json_valid(metadata)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, \"app,notes\" TEXT NOT NULL DEFAULT 'kept,bytes', display_label TEXT GENERATED ALWAYS AS (name || ', generated') VIRTUAL)",
        "INSERT INTO organization (rowid,id,name,slug,metadata,created_at,updated_at) VALUES (97,'legacy-literal','Legacy','legacy','null','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),(103,'legacy-object','Object','object','{ \"guard\" : [null,true] }','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        "CREATE TABLE custom_organization_links (id TEXT PRIMARY KEY, organization_id TEXT REFERENCES organization(id) ON DELETE CASCADE)",
        "INSERT INTO custom_organization_links VALUES ('kept-link','legacy-literal')",
        "CREATE UNIQUE INDEX idx_organization_app ON organization(\"app,notes\",slug) WHERE metadata IS NOT NULL",
        "CREATE VIEW visible_organizations AS SELECT id,metadata,display_label FROM organization",
        "CREATE TABLE organization_events (id TEXT, name TEXT)",
        "CREATE TRIGGER organization_name_event AFTER UPDATE OF name ON organization BEGIN INSERT INTO organization_events VALUES (NEW.id,NEW.name); END",
    ] {
        let _ignored_execute_unprepared = database.execute_unprepared(sql).await?;
    }
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("nullable-organization-metadata-installed-store-secret"),
        database.clone(),
    );
    assert_eq!(
        raw_metadata(&database, "legacy-literal").await?,
        Some("null".into())
    );
    assert_eq!(
        raw_metadata(&database, "legacy-object").await?,
        Some("{ \"guard\" : [null,true] }".into())
    );
    let retained = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT rowid, \"app,notes\",display_label FROM organization WHERE id='legacy-literal'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost legacy row"))?;
    assert_eq!(retained.try_get::<i64>("", "rowid")?, 97);
    assert_eq!(retained.try_get::<String>("", "app,notes")?, "kept,bytes");
    assert_eq!(
        retained.try_get::<String>("", "display_label")?,
        "Legacy, generated"
    );
    let ddl = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='organization'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost organization schema"))?
        .try_get::<String>("", "sql")?;
    assert!(ddl.contains("CONSTRAINT metadata_default DEFAULT ('{}') CHECK(json_valid(metadata))"));
    assert!(!ddl.contains("metadata_required"));
    let new = store
        .create_organization(CreateOrganization::new("New Absent", "new-absent"))
        .await?;
    assert_eq!(new.metadata, None);
    assert_eq!(raw_metadata(&database, &new.id).await?, None);
    let literal = store
        .get_organization_by_id("legacy-literal")
        .await?
        .ok_or_else(|| std::io::Error::other("lost legacy model"))?;
    assert_eq!(literal.metadata, Some(Value::Null));
    let updated = store
        .update_organization(
            "legacy-literal",
            UpdateOrganization {
                name: Some("Changed".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.metadata, Some(Value::Null));
    let view = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT metadata, display_label FROM visible_organizations WHERE id='legacy-literal'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost dependent view"))?;
    assert_eq!(view.try_get::<String>("", "metadata")?, "null");
    assert_eq!(
        view.try_get::<String>("", "display_label")?,
        "Changed, generated"
    );
    let event = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT id,name FROM organization_events",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost update trigger"))?;
    assert_eq!(event.try_get::<String>("", "id")?, "legacy-literal");
    assert_eq!(event.try_get::<String>("", "name")?, "Changed");
    let index = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT sql FROM sqlite_schema WHERE name='idx_organization_app'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost index"))?;
    assert!(
        index
            .try_get::<String>("", "sql")?
            .contains("WHERE metadata IS NOT NULL")
    );
    assert!(
        database
            .execute_unprepared("INSERT INTO custom_organization_links VALUES ('denied','missing')")
            .await
            .is_err()
    );
    store.delete_organization("legacy-literal").await?;
    assert!(
        database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT id FROM custom_organization_links WHERE id='kept-link'"
            ))
            .await?
            .is_none()
    );
    assert_eq!(
        raw_metadata(&database, "legacy-object").await?,
        Some("{ \"guard\" : [null,true] }".into())
    );
    run_migrations(&database).await?;
    assert_eq!(raw_metadata(&database, &new.id).await?, None);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn invalid_installed_reference_rolls_back_metadata_upgrade_and_restores_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    // Establish the prior schema and migration ledger before installing a
    // legacy constrained organization table with an already-invalid child.
    run_migrations(&database).await?;
    for sql in [
        "DROP TABLE organization",
        "CREATE TABLE organization (id TEXT PRIMARY KEY, metadata JSON NOT NULL, app TEXT)",
        "INSERT INTO organization VALUES ('kept','null','retained')",
        "CREATE TABLE custom_organization_links (id TEXT PRIMARY KEY, organization_id TEXT REFERENCES organization(id))",
        "PRAGMA foreign_keys=OFF",
        "INSERT INTO custom_organization_links VALUES ('invalid','missing')",
        "PRAGMA foreign_keys=ON",
        "DELETE FROM better_auth_migrations WHERE version='m20260930_000013_nullable_organization_metadata'",
    ] {
        let _ignored_execute_unprepared_2 = database.execute_unprepared(sql).await?;
    }
    let error = run_migrations(&database).await.err().ok_or_else(|| {
        std::io::Error::other("invalid foreign key did not reject the actual table rebuild")
    })?;
    assert!(error.to_string().contains("foreign-key"));
    let row = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT metadata,app FROM organization WHERE id='kept'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("rollback lost row"))?;
    assert_eq!(row.try_get::<String>("", "metadata")?, "null");
    assert_eq!(row.try_get::<String>("", "app")?, "retained");
    assert!(
        database
            .execute_unprepared("INSERT INTO organization VALUES ('null-rejected',NULL,'no')")
            .await
            .is_err()
    );
    assert!(
        database
            .execute_unprepared(
                "INSERT INTO custom_organization_links VALUES ('still-denied','missing')"
            )
            .await
            .is_err()
    );
    for (pragma, expected) in [
        ("PRAGMA foreign_keys", 1_i64),
        ("PRAGMA legacy_alter_table", 0),
    ] {
        let row_2 = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                pragma,
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("missing setting"))?;
        assert_eq!(row_2.try_get_by_index::<i64>(0)?, expected);
    }
    assert!(
        database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT name FROM sqlite_schema WHERE name='organization__nullable_metadata'"
            ))
            .await?
            .is_none()
    );
    assert!(database.query_one_raw(Statement::from_string(database.get_database_backend(),"SELECT version FROM better_auth_migrations WHERE version='m20260930_000013_nullable_organization_metadata'")).await?.is_none());
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn optional_organization_update_distinguishes_absence_from_database_write_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("optional-organization-update-public-store-secret"),
        database.clone(),
    );
    let target = store
        .create_organization(CreateOrganization::new("Original", "optional-target"))
        .await?;
    let foreign = store
        .create_organization(
            CreateOrganization::new("Unrelated", "optional-foreign")
                .with_metadata(json!({"private":"retained"})),
        )
        .await?;
    let updated = store
        .update_organization_if_present(
            &target.id,
            UpdateOrganization {
                name: Some("Updated".into()),
                ..Default::default()
            },
        )
        .await?
        .ok_or_else(|| std::io::Error::other("existing update must return its actual row"))?;
    assert_eq!(updated.name, "Updated");
    assert_eq!(updated.id, target.id);
    assert_eq!(updated.created_at, target.created_at);
    assert_eq!(updated.logo, target.logo);
    assert_eq!(updated.metadata, target.metadata);
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    let _ignored_execute_unprepared_3 = database.execute_unprepared("CREATE TRIGGER veto_optional_organization BEFORE UPDATE ON organization WHEN OLD.slug='optional-target' BEGIN SELECT RAISE(ABORT,'optional organization storage veto'); END").await?;
    let veto = store
        .update_organization_if_present(
            &target.id,
            UpdateOrganization {
                name: Some("Must Not Persist".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(veto.is_err(), "database veto is not a missing-row success");
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    let _ignored_execute_unprepared_4 = database
        .execute_unprepared("DROP TRIGGER veto_optional_organization")
        .await?;
    let _ignored_execute_unprepared_5 = database.execute_unprepared("CREATE TRIGGER ignore_optional_organization BEFORE UPDATE ON organization WHEN OLD.slug='optional-target' BEGIN SELECT RAISE(IGNORE); END").await?;
    assert!(
        store
            .update_organization_if_present(
                &target.id,
                UpdateOrganization {
                    name: Some("Ignored By Adapter".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none(),
        "a real zero-row UPDATE is absence, not a database failure"
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    store.delete_organization(&target.id).await?;
    assert!(
        store
            .update_organization_if_present(
                &target.id,
                UpdateOrganization {
                    name: Some("Deleted".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none()
    );
    assert!(
        store
            .update_organization(&target.id, UpdateOrganization::default())
            .await
            .is_err(),
        "original public update retains its missing-row error contract"
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&foreign.id).await?)?,
        serde_json::to_value(Some(&foreign))?
    );
    Ok(())
}
