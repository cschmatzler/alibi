//! Application-owned UTC wall-clock schemas must preserve PostgreSQL wire types.
//! The same store lifecycle also runs over aware models and SQLite.

#![allow(
    unreachable_pub,
    reason = "SeaORM derives public entity associated types inside private test fixtures"
)]

use super::{Db, Raw, TestResult, on_raw};
use alibi::{AuthConfig, AuthSchema};
use alibi_core::store::AuthStore;
use alibi_core::{
    AuthAccount, AuthSession, AuthUser, AuthVerification, CreateAccount, CreateSession, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};
use chrono::{DateTime, Duration, NaiveDateTime, SubsecRound, Utc};

// One application schema contract, derived independently by each adapter.
macro_rules! auth_model {
    (sqlx, $module:ident, $role:literal, $table:literal, {$($fields:tt)*}) => {
        pub mod $module {
            use super::*;
            #[derive(alibi::sqlx::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
            #[auth(role = $role, table = $table)]
            pub struct Model {
                pub id: String,
                $($fields)*
            }
        }
    };
    (seaorm, $module:ident, $role:literal, $table:literal, {$($fields:tt)*}) => {
        pub mod $module {
            use super::*;
            use alibi::seaorm::sea_orm::{self, entity::prelude::*};
            #[derive(alibi::seaorm::AuthEntity, Clone, Debug, serde::Serialize, DeriveEntityModel)]
            #[auth(role = $role)]
            #[sea_orm(table_name = $table)]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                $($fields)*
            }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

macro_rules! auth_models {
    ($backend:ident, $date:ty) => {
        auth_model!($backend, user, "user", "users", {
            pub email: Option<String>,
            pub name: Option<String>,
            pub email_verified: bool,
            pub image: Option<String>,
            pub banned: Option<bool>,
            pub ban_reason: Option<String>,
            pub ban_expires: Option<$date>,
            pub created_at: $date,
            pub updated_at: $date,
        });
        auth_model!($backend, session, "session", "sessions", {
            pub user_id: String,
            pub token: String,
            pub expires_at: $date,
            pub created_at: $date,
            pub updated_at: $date,
            pub ip_address: Option<String>,
            pub user_agent: Option<String>,
            pub active: bool,
        });
        auth_model!($backend, account, "account", "accounts", {
            pub account_id: String,
            pub provider_id: String,
            pub user_id: String,
            pub access_token: Option<String>,
            pub refresh_token: Option<String>,
            pub id_token: Option<String>,
            pub access_token_expires_at: Option<$date>,
            pub refresh_token_expires_at: Option<$date>,
            pub scope: Option<String>,
            pub password: Option<String>,
            pub created_at: $date,
            pub updated_at: $date,
        });
        auth_model!($backend, verification, "verification", "verifications", {
            pub identifier: String,
            pub value: String,
            pub expires_at: $date,
            pub created_at: $date,
            pub updated_at: $date,
        });
        struct Schema;
        impl AuthSchema for Schema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }
    };
}

macro_rules! sqlx_case {
    ($module:ident, $date:ty, $naive:literal) => {
        mod $module {
            use super::*;
            auth_models!(sqlx, $date);
            async fn run(db: Db, timezone: &str) -> TestResult {
                install(&db, $naive).await?;
                let connection = super::super::Sqlx::connect(&db.url, Some(1)).await?;
                if let Some(pool) = connection.as_postgres() {
                    _ = sqlx::query("SELECT set_config('TimeZone', $1, false)")
                        .bind(timezone)
                        .execute(pool)
                        .await?;
                    let actual: String = sqlx::query_scalar("SELECT current_setting('TimeZone')")
                        .fetch_one(pool)
                        .await?;
                    assert_eq!(actual, timezone);
                }
                let store = alibi::sqlx::SqlxStore::<Schema>::new(
                    AuthConfig::new("timestamp-regression-local-secret-32-chars"),
                    connection,
                );
                exercise(&db.raw, &store, $naive).await
            }
            timestamp_tests!();
        }
    };
}
macro_rules! seaorm_case {
    ($module:ident, $date:ty, $naive:literal) => {
        mod $module {
            use super::*;
            auth_models!(seaorm, $date);
            async fn run(db: Db, timezone: &str) -> TestResult {
                install(&db, $naive).await?;
                let connection = super::super::SeaOrm::connect(&db.url, Some(1)).await?;
                if db.is_postgres() {
                    use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
                    _ = connection
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Postgres,
                            "SELECT set_config('TimeZone', $1, false)",
                            [timezone.into()],
                        ))
                        .await?;
                    let row = connection
                        .query_one_raw(Statement::from_string(
                            DbBackend::Postgres,
                            "SELECT current_setting('TimeZone') AS timezone".to_owned(),
                        ))
                        .await?
                        .unwrap();
                    let actual: String = row.try_get("", "timezone")?;
                    assert_eq!(actual, timezone);
                }
                let store = alibi::seaorm::SeaOrmStore::<Schema>::new(
                    AuthConfig::new("timestamp-regression-local-secret-32-chars"),
                    connection,
                );
                exercise(&db.raw, &store, $naive).await
            }
            timestamp_tests!();
        }
    };
}
macro_rules! timestamp_tests {
    () => {
        #[tokio::test]
        async fn sqlite_timestamp_lifecycle() -> TestResult {
            run(Db::sqlite().await?, "UTC").await
        }
        #[tokio::test]
        #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
        async fn postgres_timestamp_lifecycle() -> TestResult {
            for timezone in ["UTC", "Europe/Berlin"] {
                run(Db::postgres().await?, timezone).await?;
                eprintln!("{}: {timezone} timestamp lifecycle passed", module_path!());
            }
            Ok(())
        }
    };
}
use super::Backend;
sqlx_case!(sqlx_naive, NaiveDateTime, true);
sqlx_case!(sqlx_aware, DateTime<Utc>, false);
seaorm_case!(seaorm_naive, NaiveDateTime, true);
// SeaORM's normal aware field alias, also exercising shared accessor conversion.
use alibi::seaorm::sea_orm::prelude::DateTimeUtc;
seaorm_case!(seaorm_aware, DateTimeUtc, false);

async fn install(db: &Db, naive: bool) -> TestResult {
    let date = if naive { "TIMESTAMP" } else { "TIMESTAMPTZ" };
    // Deliberately application-owned DDL; no store migrator or timezone casts.
    for statement in [
        format!(
            "CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, name TEXT, email_verified BOOLEAN NOT NULL, image TEXT, banned BOOLEAN, ban_reason TEXT, ban_expires {date}, created_at {date} NOT NULL, updated_at {date} NOT NULL)"
        ),
        format!(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT NOT NULL, expires_at {date} NOT NULL, created_at {date} NOT NULL, updated_at {date} NOT NULL, ip_address TEXT, user_agent TEXT, active BOOLEAN NOT NULL)"
        ),
        format!(
            "CREATE TABLE accounts (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, provider_id TEXT NOT NULL, user_id TEXT NOT NULL, access_token TEXT, refresh_token TEXT, id_token TEXT, access_token_expires_at {date}, refresh_token_expires_at {date}, scope TEXT, password TEXT, created_at {date} NOT NULL, updated_at {date} NOT NULL)"
        ),
        format!(
            "CREATE TABLE verifications (id TEXT PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expires_at {date} NOT NULL, created_at {date} NOT NULL, updated_at {date} NOT NULL)"
        ),
    ] {
        _ = db.raw.execute(&statement, &[]).await?;
    }
    Ok(())
}

async fn stored_date(
    raw: &Raw,
    table: &str,
    column: &str,
    id: &str,
    naive: bool,
) -> TestResult<Option<DateTime<Utc>>> {
    let statement = sqlx::AssertSqlSafe(format!("SELECT {column} FROM {table} WHERE id = $1"));
    if naive {
        let date: Option<NaiveDateTime> = on_raw!(raw, |pool| {
            sqlx::query_scalar(statement)
                .bind(id)
                .fetch_one(pool)
                .await?
        });
        Ok(date.map(|date| date.and_utc()))
    } else {
        Ok(on_raw!(raw, |pool| {
            sqlx::query_scalar(statement)
                .bind(id)
                .fetch_one(pool)
                .await?
        }))
    }
}

async fn exercise<S: AuthSchema>(raw: &Raw, store: &dyn AuthStore<S>, naive: bool) -> TestResult {
    let now = Utc::now().trunc_subsecs(6);
    let expires = now + Duration::minutes(30);
    let historical: DateTime<Utc> = "2026-10-04T12:00:00Z".parse()?;
    let mut input = CreateUser::new().with_email("synthetic@timestamps.test");
    input.created_at = Some(historical);
    input.updated_at = Some(historical);
    let user = store.create_user(input).await?;
    let user_id = user.id().into_owned();
    assert_eq!(user.created_at(), historical);
    assert_eq!(user.updated_at(), historical);
    assert_eq!(
        stored_date(raw, "users", "created_at", &user_id, naive).await?,
        Some(historical)
    );
    assert_eq!(
        stored_date(raw, "users", "ban_expires", &user_id, naive).await?,
        None
    );
    let user = store
        .update_user(
            &user_id,
            UpdateUser {
                banned: Some(true),
                ban_expires: Some(Some(expires)),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(user.ban_expires(), Some(expires));
    assert_eq!(
        stored_date(raw, "users", "ban_expires", &user_id, naive).await?,
        Some(expires)
    );
    assert!(user.updated_at() >= now);
    let user = store
        .update_user(
            &user_id,
            UpdateUser {
                banned: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(user.ban_expires(), None);
    assert_eq!(
        stored_date(raw, "users", "ban_expires", &user_id, naive).await?,
        None
    );

    let account = store
        .create_account(CreateAccount {
            additional_fields: Default::default(),
            user_id: user_id.clone(),
            account_id: "synthetic".into(),
            provider_id: "synthetic".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: Some(expires),
            scope: None,
            password: None,
        })
        .await?;
    let account_id = account.id().into_owned();
    assert_eq!(account.access_token_expires_at(), None);
    assert_eq!(account.refresh_token_expires_at(), Some(expires));
    assert_eq!(
        stored_date(
            raw,
            "accounts",
            "access_token_expires_at",
            &account_id,
            naive
        )
        .await?,
        None
    );
    let account = store
        .update_account(
            &account_id,
            UpdateAccount {
                access_token_expires_at: Some(expires),
                refresh_token_expires_at: Some(expires + Duration::minutes(5)),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(account.access_token_expires_at(), Some(expires));
    assert_eq!(
        account.refresh_token_expires_at(),
        Some(expires + Duration::minutes(5))
    );
    assert_eq!(
        stored_date(
            raw,
            "accounts",
            "refresh_token_expires_at",
            &account_id,
            naive
        )
        .await?,
        account.refresh_token_expires_at()
    );
    assert!(account.created_at() >= now && account.updated_at() >= now);

    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id,
            token: Some("synthetic-session".into()),
            expires_at: expires,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let session_id = session.id().into_owned();
    assert_eq!(session.expires_at(), expires);
    assert!(session.created_at() >= now && session.updated_at() >= now);
    assert_eq!(
        stored_date(raw, "sessions", "expires_at", &session_id, naive).await?,
        Some(expires)
    );
    let session = store
        .refresh_session("synthetic-session", expires + Duration::minutes(5))
        .await?
        .unwrap();
    assert_eq!(session.expires_at(), expires + Duration::minutes(5));
    assert_eq!(
        store
            .get_session("synthetic-session")
            .await?
            .unwrap()
            .expires_at(),
        session.expires_at()
    );
    assert_eq!(store.delete_expired_sessions().await?, 0);
    store.end_session_preserving("synthetic-session").await?;
    let ended = stored_date(raw, "sessions", "expires_at", &session_id, naive)
        .await?
        .unwrap();
    assert!(ended >= now && ended <= Utc::now());
    assert_eq!(store.delete_expired_sessions().await?, 1);
    let second = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: user.id().into_owned(),
            token: Some("synthetic-second".into()),
            expires_at: expires,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    store
        .end_user_sessions_preserving(user.id().as_ref())
        .await?;
    let ended = stored_date(raw, "sessions", "expires_at", second.id().as_ref(), naive)
        .await?
        .unwrap();
    assert!(ended >= now && ended <= Utc::now());
    assert_eq!(store.delete_expired_sessions().await?, 1);

    // Replay the issue's exact wall-clock expiration with the custom row.
    let original = store
        .create_verification(CreateVerification {
            identifier: "original-repro".into(),
            value: "synthetic-proof".into(),
            expires_at: historical,
        })
        .await?;
    assert_eq!(original.expires_at(), historical);
    let stored = stored_date(
        raw,
        "verifications",
        "expires_at",
        original.id().as_ref(),
        naive,
    )
    .await?;
    assert_eq!(stored, Some(historical));
    eprintln!("custom model original reproduction: stored_expires_at={stored:?}");
    store.delete_verification(original.id().as_ref()).await?;

    let verification = store
        .create_verification(CreateVerification {
            identifier: "synthetic-verification".into(),
            value: "synthetic-proof".into(),
            expires_at: expires,
        })
        .await?;
    let verification_id = verification.id().into_owned();
    assert_eq!(verification.expires_at(), expires);
    assert!(verification.created_at() >= now && verification.updated_at() >= now);
    assert_eq!(
        stored_date(raw, "verifications", "expires_at", &verification_id, naive).await?,
        Some(expires)
    );
    assert!(
        store
            .get_verification("synthetic-verification", "synthetic-proof")
            .await?
            .is_some()
    );
    assert_eq!(store.delete_expired_verifications().await?, 0);
    let _updated = store
        .update_verification_by_identifier(
            "synthetic-verification",
            alibi_core::UpdateVerification {
                value: Some("updated-proof".into()),
                expires_at: Some(now - Duration::minutes(30)),
            },
        )
        .await?;
    assert_eq!(
        stored_date(raw, "verifications", "expires_at", &verification_id, naive).await?,
        Some(now - Duration::minutes(30))
    );
    let updated = store
        .get_latest_verification_by_identifier("synthetic-verification")
        .await?
        .unwrap();
    assert_eq!(updated.expires_at(), now - Duration::minutes(30));
    assert!(updated.updated_at() >= now);
    assert!(
        store
            .get_verification("synthetic-verification", "updated-proof")
            .await?
            .is_none()
    );
    assert_eq!(store.delete_expired_verifications().await?, 1);
    // Adapter record creation has a separate direct updated_at write.
    let snapshot = store
        .create_verification_record(
            alibi_core::verification::VerificationCreation {
                id: Some("synthetic-record".into()),
                identifier: "record".into(),
                value: "record-proof".into(),
                expires_at: expires,
                created_at: historical,
                updated_at: historical + Duration::seconds(1),
            },
            alibi_core::verification::VerificationPublication {
                store_in_database: true,
                secondary_storage: None,
                cache_key: "unused".into(),
            },
        )
        .await?;
    assert!(snapshot.is_some());
    assert_eq!(
        stored_date(
            raw,
            "verifications",
            "created_at",
            "synthetic-record",
            naive
        )
        .await?,
        Some(historical)
    );
    assert_eq!(
        stored_date(
            raw,
            "verifications",
            "updated_at",
            "synthetic-record",
            naive
        )
        .await?,
        Some(historical + Duration::seconds(1))
    );
    assert!(
        store
            .compare_and_swap_verification(
                "synthetic-record",
                "record-proof",
                "cas-proof",
                expires + Duration::minutes(5)
            )
            .await?
    );
    assert_eq!(
        stored_date(
            raw,
            "verifications",
            "expires_at",
            "synthetic-record",
            naive
        )
        .await?,
        Some(expires + Duration::minutes(5))
    );
    assert!(
        store
            .consume_verification("record", "cas-proof")
            .await?
            .is_some()
    );
    assert!(
        store
            .get_latest_verification_by_identifier("record")
            .await?
            .is_none()
    );
    Ok(())
}
