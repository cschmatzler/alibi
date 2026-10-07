//! The CLI's generated schemas compile and serve as working store schemas.
//!
//! `tests/fixtures/cli` holds `alibi generate --plugins all` output
//! for each backend; the CLI's own tests keep the fixtures current. Core-only
//! fixtures exercise deletion without any optional plugin tables.

#[cfg(feature = "sqlx")]
mod sqlx_schema {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "generated schema items are public for the application crate, which uses every row type"
    )]
    include!("../../../fixtures/cli/sqlx_all.rs");

    #[tokio::test]
    async fn generated_sqlx_schema_migrates_and_serves_the_store() -> super::TestResult {
        all_tables(crate::storage::Db::sqlite().await?).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn generated_sqlx_schema_migrates_and_serves_postgres() -> super::TestResult {
        all_tables(crate::storage::Db::postgres().await?).await
    }
    async fn all_tables(db: crate::storage::Db) -> super::TestResult {
        let pool = SqlxPool::connect(&db.url).await?;
        run_app_migrations(&pool).await?;
        // Migrations are idempotent.
        run_app_migrations(&pool).await?;
        let store = alibi::sqlx::SqlxStore::<AppAuthSchema>::new(
            alibi::AuthConfig::new("generated-sqlx-schema-secret-32-chars"),
            pool,
        );
        super::exercise(&store).await
    }
}

#[cfg(feature = "seaorm")]
mod seaorm_schema {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "generated schema items are public for the application crate, which uses every row type"
    )]
    include!("../../../fixtures/cli/seaorm_all.rs");

    #[tokio::test]
    async fn generated_seaorm_schema_migrates_and_serves_the_store() -> super::TestResult {
        all_tables(crate::storage::Db::sqlite().await?).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn generated_seaorm_schema_migrates_and_serves_postgres() -> super::TestResult {
        all_tables(crate::storage::Db::postgres().await?).await
    }
    async fn all_tables(db: crate::storage::Db) -> super::TestResult {
        let database = alibi::seaorm::Database::connect(&db.url).await?;
        run_app_migrations(&database).await?;
        run_app_migrations(&database).await?;
        let store = alibi::seaorm::SeaOrmStore::<AppAuthSchema>::new(
            alibi::AuthConfig::new("generated-seaorm-schema-secret-32-chars"),
            database,
        );
        super::exercise(&store).await
    }
}

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Round-trip every core role through the generated models.
#[cfg(any(feature = "sqlx", feature = "seaorm"))]
async fn exercise<S: alibi::AuthSchema>(store: &dyn alibi::store::AuthStore<S>) -> TestResult {
    use alibi::prelude::{AuthSession, AuthUser, AuthVerification};
    use alibi_core::{CreateAccount, CreateSession, CreateUser, CreateVerification};
    let user = store
        .create_user(CreateUser::new().with_email("generated@fixture.test"))
        .await?;
    let user_id = user.id().into_owned();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    let session = store
        .create_session(CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user_id.clone(),
            expires_at,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    drop(
        store
            .create_account(CreateAccount {
                additional_fields: Default::default(),
                user_id: user_id.clone(),
                provider_id: "credential".into(),
                account_id: user_id.clone(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some("stored".into()),
            })
            .await?,
    );
    drop(
        store
            .create_verification(CreateVerification {
                identifier: "generated".into(),
                value: "proof".into(),
                expires_at,
            })
            .await?,
    );
    assert_eq!(
        store
            .get_user_by_email("generated@fixture.test")
            .await?
            .map(|user| user.id().into_owned()),
        Some(user_id.clone())
    );
    assert_eq!(
        store
            .get_session(session.token())
            .await?
            .map(|session| session.user_id().into_owned()),
        Some(user_id.clone())
    );
    assert_eq!(store.get_user_accounts(&user_id).await?.len(), 1);
    assert_eq!(
        store
            .get_latest_verification_by_identifier("generated")
            .await?
            .map(|row| row.value().to_owned()),
        Some("proof".to_owned())
    );
    Ok(())
}

// Core-only output is generated with no --plugins; admin authority is configured
// by ID so this workflow needs no admin columns either.
#[cfg(feature = "sqlx")]
mod sqlx_core {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "application schema fixture exports"
    )]
    include!("../../../fixtures/cli/sqlx_core.rs");

    #[tokio::test]
    async fn generated_core_self_deletion() -> super::TestResult {
        deletion(crate::storage::Db::sqlite().await?, false).await
    }
    #[tokio::test]
    async fn generated_core_admin_deletion() -> super::TestResult {
        deletion(crate::storage::Db::sqlite().await?, true).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn generated_core_deletion_postgres() -> super::TestResult {
        for admin in [false, true] {
            deletion(crate::storage::Db::postgres().await?, admin).await?;
        }
        Ok(())
    }
    async fn deletion(db: crate::storage::Db, admin: bool) -> super::TestResult {
        let pool = SqlxPool::connect(&db.url).await?;
        run_app_migrations(&pool).await?;
        super::assert_core_only(&db).await?;
        let store = alibi::sqlx::SqlxStore::<AppAuthSchema>::new(
            crate::storage::users::deletion_config(),
            pool,
        );
        Box::pin(crate::storage::users::public_user_deletion(
            std::sync::Arc::new(store),
            admin,
            None,
        ))
        .await?;
        for table in ["users", "accounts", "sessions"] {
            assert_eq!(
                db.count(table).await?,
                1,
                "{table}: only the administrator survives"
            );
        }
        Ok(())
    }
}

#[cfg(feature = "seaorm")]
mod seaorm_core {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "application schema fixture exports"
    )]
    include!("../../../fixtures/cli/seaorm_core.rs");

    #[tokio::test]
    async fn generated_core_self_deletion() -> super::TestResult {
        deletion(crate::storage::Db::sqlite().await?, false).await
    }
    #[tokio::test]
    async fn generated_core_admin_deletion() -> super::TestResult {
        deletion(crate::storage::Db::sqlite().await?, true).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn generated_core_deletion_postgres() -> super::TestResult {
        for admin in [false, true] {
            deletion(crate::storage::Db::postgres().await?, admin).await?;
        }
        Ok(())
    }
    async fn deletion(db: crate::storage::Db, admin: bool) -> super::TestResult {
        let database = alibi::seaorm::Database::connect(&db.url).await?;
        run_app_migrations(&database).await?;
        super::assert_core_only(&db).await?;
        let store = alibi::seaorm::SeaOrmStore::<AppAuthSchema>::new(
            crate::storage::users::deletion_config(),
            database,
        );
        Box::pin(crate::storage::users::public_user_deletion(
            std::sync::Arc::new(store),
            admin,
            None,
        ))
        .await?;
        for table in ["users", "accounts", "sessions"] {
            assert_eq!(
                db.count(table).await?,
                1,
                "{table}: only the administrator survives"
            );
        }
        Ok(())
    }
}

async fn assert_core_only(db: &crate::storage::Db) -> TestResult {
    let query = if db.raw.is_postgres() {
        "SELECT COUNT(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename = 'api_keys'"
    } else {
        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'api_keys'"
    };
    assert_eq!(db.count_where(query, &[]).await?, 0);
    Ok(())
}
