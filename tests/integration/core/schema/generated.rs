//! The CLI's generated schemas compile and serve as working store schemas.
//!
//! `tests/fixtures/cli` holds `better-auth-rs generate --plugins all` output
//! for each backend; the CLI's own tests keep the fixtures current.

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
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        run_app_migrations(&pool).await?;
        // Migrations are idempotent.
        run_app_migrations(&pool).await?;
        let store = better_auth::sqlx::SqlxStore::<AppAuthSchema>::new(
            better_auth::AuthConfig::new("generated-sqlx-schema-secret-32-chars"),
            pool,
        );
        super::exercise(&store).await
    }
}

#[cfg(feature = "seaorm2")]
mod seaorm_schema {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "generated schema items are public for the application crate, which uses every row type"
    )]
    include!("../../../fixtures/cli/seaorm_all.rs");

    #[tokio::test]
    async fn generated_seaorm_schema_migrates_and_serves_the_store() -> super::TestResult {
        let database = better_auth::seaorm::Database::connect("sqlite::memory:").await?;
        run_app_migrations(&database).await?;
        run_app_migrations(&database).await?;
        let store = better_auth::seaorm::SeaOrmStore::<AppAuthSchema>::new(
            better_auth::AuthConfig::new("generated-seaorm-schema-secret-32-chars"),
            database,
        );
        super::exercise(&store).await
    }
}

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Round-trip every core role through the generated models.
#[cfg(any(feature = "sqlx", feature = "seaorm2"))]
async fn exercise<S: better_auth::AuthSchema>(
    store: &dyn better_auth::store::AuthStore<S>,
) -> TestResult {
    use better_auth::prelude::{AuthSession, AuthUser, AuthVerification};
    use better_auth_core::{CreateAccount, CreateSession, CreateUser, CreateVerification};
    let user = store
        .create_user(CreateUser::new().with_email("generated@fixture.test"))
        .await?;
    let user_id = user.id().into_owned();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    let session = store
        .create_session(CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
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
