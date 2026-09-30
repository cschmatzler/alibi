//! Pinned user deletion retains plugin-owned two-factor records.
use sea_orm_migration::prelude::*;
pub(super) struct TwoFactorUserReference;
impl MigrationName for TwoFactorUserReference {
    fn name(&self) -> &str {
        "m20260930_000007_two_factor_user_reference"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for TwoFactorUserReference {
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        super::user_reference::remove_user_reference(
            manager,
            super::user_reference::UserReference::TwoFactor,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
    use better_auth_core::{
        AuthConfig, CreateUser,
        store::{TwoFactorStore, UserStore},
    };
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    #[tokio::test]
    async fn installed_factor_upgrade_retains_enrollment_and_application_schema_after_user_deletion()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        AuthMigrator::up(&database, None).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            std::sync::Arc::new(AuthConfig::new(
                "factor-upgrade-secret-at-least-32-characters",
            )),
            database.clone(),
        );
        let _ = store
            .create_user(CreateUser {
                id: Some("factor-owner".to_owned()),
                email: Some("owner@factor.fixture.test".to_owned()),
                ..CreateUser::default()
            })
            .await?;
        for statement in [
            "DROP TABLE two_factor",
            "CREATE TABLE two_factor (id TEXT PRIMARY KEY NOT NULL, secret TEXT NOT NULL, backup_codes TEXT NOT NULL, user_id TEXT NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, app_note TEXT NOT NULL DEFAULT 'installed', CONSTRAINT fk_two_factor_user_id FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)",
            "CREATE UNIQUE INDEX idx_two_factor_user_id ON two_factor(user_id)",
            "CREATE TABLE factor_link (factor_id TEXT REFERENCES two_factor(id))",
            "CREATE VIEW factor_app_view AS SELECT id, app_note FROM two_factor",
            "DELETE FROM better_auth_migrations WHERE version IN ('m20260930_000007_two_factor_user_reference', 'm20260930_000012_two_factor_verification_policy')",
        ] {
            let _ = database.execute_unprepared(statement).await?;
        }
        let factor_id = "installed-factor";
        let _ = database
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO two_factor (id, secret, backup_codes, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                [
                    factor_id.into(),
                    "encrypted-secret".into(),
                    "encrypted-codes".into(),
                    "factor-owner".into(),
                ],
            ))
            .await?;
        let _ = database
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO factor_link VALUES (?)",
                [factor_id.into()],
            ))
            .await?;
        AuthMigrator::up(&database, None).await?;
        store.delete_user("factor-owner").await?;
        assert!(store.get_user_by_id("factor-owner").await?.is_none());
        let retained = store
            .get_two_factor_by_user_id("factor-owner")
            .await?
            .ok_or("enrolled factor was cascaded")?;
        assert_eq!(retained.id, factor_id);
        assert_eq!(retained.verified, Some(true));
        assert_eq!(retained.failed_verification_count, Some(0.0));
        assert_eq!(retained.locked_until, None);
        assert_eq!(retained.secret, "encrypted-secret");
        let row = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT app_note FROM factor_app_view WHERE id=(SELECT factor_id FROM factor_link)"
                    .to_owned(),
            ))
            .await?
            .ok_or("application enrollment reference was lost")?;
        assert_eq!(row.try_get::<String>("", "app_note")?, "installed");
        let constraints = database
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA foreign_key_list('two_factor')".to_owned(),
            ))
            .await?;
        assert!(constraints.is_empty());
        Ok(())
    }
}
