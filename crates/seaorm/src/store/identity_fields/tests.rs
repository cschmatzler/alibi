use super::*;

use crate::store::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};

use better_auth_core::entity::{AuthSession, AuthUser};

use better_auth_core::store::{SessionStore, UserStore};

use better_auth_core::{AuthConfig, CreateSession, CreateUser, UpdateUser};

use chrono::Utc;

use sea_orm::{ConnectionTrait, Database, Statement};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn upgrades_installed_schema_without_losing_users_and_round_trips_nullable_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    // These are the three migration entries present before this slice.
    AuthMigrator::up(&database, Some(3)).await?;
    let manager = SchemaManager::new(&database);
    assert!(!manager.has_column("users", "phone_number").await?);
    let now = Utc::now();
    let _ignored_into = database.execute_raw(Statement::from_sql_and_values(
            database.get_database_backend(),
            "INSERT INTO users (id, name, email, email_verified, two_factor_enabled, banned, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec!["existing".into(), "Existing".into(), "existing@example.com".into(), false.into(), false.into(), false.into(), serde_json::json!({}).into(), now.into(), now.into()],
        )).await?;
    AuthMigrator::up(&database, None).await?;
    AuthMigrator::up(&database, None).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("identity-fields-migration-local-secret-32-chars"),
        database,
    );
    let existing = store
        .get_user_by_id("existing")
        .await?
        .ok_or_else(|| std::io::Error::other("migration lost existing user"))?;
    assert_eq!(existing.name(), Some("Existing"));
    assert_eq!(existing.phone_number(), None);
    assert_eq!(existing.phone_number_verified(), None);
    assert_eq!(existing.is_anonymous(), None);
    let other = store
        .create_user(CreateUser::new().with_email("other@example.com"))
        .await?;
    assert_eq!(other.phone_number(), None);
    let configured = store
        .update_user(
            "existing",
            UpdateUser {
                phone_number: Some(Some("+15550000001".to_owned())),
                phone_number_verified: Some(false),
                is_anonymous: Some(false),
                last_login_method: Some(Some("phone-number".to_owned())),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(configured.phone_number(), Some("+15550000001"));
    assert_eq!(configured.phone_number_verified(), Some(false));
    assert_eq!(configured.is_anonymous(), Some(false));
    assert_eq!(configured.last_login_method(), Some("phone-number"));
    assert_eq!(
        store
            .get_user_by_phone_number("+15550000001")
            .await?
            .map(|row| row.id),
        Some("existing".to_owned())
    );
    assert!(
        store
            .update_user(
                other.id().as_ref(),
                UpdateUser {
                    phone_number: Some(Some("+15550000001".to_owned())),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    let cleared = store
        .update_user(
            "existing",
            UpdateUser {
                phone_number: Some(None),
                last_login_method: Some(None),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(cleared.phone_number(), None);
    assert_eq!(cleared.last_login_method(), None);
    assert!(
        store
            .get_user_by_phone_number("+15550000001")
            .await?
            .is_none()
    );
    let reused = store
        .update_user(
            other.id().as_ref(),
            UpdateUser {
                phone_number: Some(Some("+15550000001".to_owned())),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(reused.phone_number(), Some("+15550000001"));
    let session = store
        .create_session(CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: "existing".to_owned(),
            expires_at: now + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: Some("team-a".to_owned()),
        })
        .await?;
    assert_eq!(session.active_team_id(), Some("team-a"));
    let changed = store
        .update_session_active_team(session.token(), Some("team-b"))
        .await?;
    assert_eq!(changed.active_team_id(), Some("team-b"));
    let cleared_2 = store
        .update_session_active_team(session.token(), None)
        .await?;
    assert_eq!(cleared_2.active_team_id(), None);
    Ok(())
}
