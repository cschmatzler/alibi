//! Existing CHAR(30) schemas: native store bindings, indexed plans and ownership.
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives expose associated types in private fixtures"
)]
use super::{Backend, Db, Raw, TestResult, on_raw};
use alibi::{AuthConfig, AuthSchema};
use alibi_core::store::{AuthStore, UserStore};
use alibi_core::{
    AuthAccount, AuthSession, AuthUser, AuthVerification, CreateAccount, CreateSession, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};
use chrono::{Duration, NaiveDateTime, Utc};
use sqlx::Row;

fn new_id() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "new_{:026}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}
// One application schema contract, derived independently by each adapter.
macro_rules! auth_model {
    (sqlx, $module:ident, $role:literal, $table:literal, [$($charfield:ident : $chartype:ty),*], {$($fields:tt)*}) => {
        pub mod $module {
            use super::*;
            #[derive(alibi::sqlx::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
            #[auth(role = $role, table = $table, id_generator = "super::super::new_id")]
            pub struct Model {
                #[auth(column_type = "bpchar")]
                pub id: String,
                $(#[auth(column_type = "bpchar")] pub $charfield: $chartype,)*
                $($fields)*
            }
        }
    };
    (seaorm, $module:ident, $role:literal, $table:literal, [$($charfield:ident : $chartype:ty),*], {$($fields:tt)*}) => {
        pub mod $module {
            use super::*;
            use alibi::seaorm::sea_orm::{self, entity::prelude::*};
            #[derive(alibi::seaorm::AuthEntity, Clone, Debug, serde::Serialize, DeriveEntityModel)]
            #[auth(role = $role, id_generator = "super::super::new_id")]
            #[sea_orm(table_name = $table)]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(30))", save_as = "bpchar")]
                pub id: String,
                $(#[sea_orm(column_type = "Char(Some(30))", save_as = "bpchar")] pub $charfield: $chartype,)*
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
        auth_model!($backend, user, "user", "users", [linked_id: Option<String>], {
            pub email: String,
            pub name: String,
            pub email_verified: bool,
            pub image: Option<String>,
            pub created_at: $date,
            pub updated_at: $date,
        });
        auth_model!($backend, session, "session", "sessions", [user_id: String], {
            pub token: String,
            pub expires_at: $date,
            pub created_at: $date,
            pub updated_at: $date,
            pub ip_address: Option<String>,
            pub user_agent: Option<String>,
            pub active: bool,
        });
        auth_model!($backend, account, "account", "accounts", [user_id: String], {
            pub account_id: String,
            pub provider_id: String,
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
        auth_model!($backend, verification, "verification", "verifications", [], {
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

mod mapped_organizations;

mod sqlx_char {
    use super::*;
    auth_models!(sqlx, NaiveDateTime);
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_native_char_ids() -> TestResult {
        let db = Db::postgres().await?;
        install(&db).await?;
        baseline(&db).await?;
        let connection = super::super::Sqlx::connect(&db.url, Some(1)).await?;
        let pool = connection.as_postgres().unwrap().clone();
        let store = alibi::sqlx::SqlxStore::<Schema>::new(
            AuthConfig::new("char-schema-test-secret-at-least-32"),
            connection,
        );
        let id = "usr_00000000000000000000010000";
        assert_eq!(store.get_user_by_id(id).await?.unwrap().id(), id);
        native_plan(&pool, "bpchar", id, true).await?;
        exercise(&db.raw, &store).await?;
        typed_null(&pool, "bpchar").await?;
        native_ownership_bindings(&pool, "bpchar").await?;
        native_mutation_bindings(&pool, "bpchar").await?;
        Ok(())
    }
    #[tokio::test]
    async fn sqlite_native_char_ids() -> TestResult {
        let db = Db::sqlite().await?;
        install(&db).await?;
        let connection = super::super::Sqlx::connect(&db.url, Some(1)).await?;
        let store = alibi::sqlx::SqlxStore::<Schema>::new(
            AuthConfig::new("char-schema-test-secret-at-least-32"),
            connection,
        );
        exercise(&db.raw, &store).await
    }
}
mod seaorm_char {
    use super::*;
    auth_models!(seaorm, NaiveDateTime);
    #[tokio::test]
    async fn sqlite_native_char_ids() -> TestResult {
        let db = Db::sqlite().await?;
        install(&db).await?;
        let connection = super::super::SeaOrm::connect(&db.url, Some(1)).await?;
        let store = alibi::seaorm::SeaOrmStore::<Schema>::new(
            AuthConfig::new("char-schema-test-secret-at-least-32"),
            connection,
        );
        exercise(&db.raw, &store).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_native_char_ids() -> TestResult {
        let db = Db::postgres().await?;
        install(&db).await?;
        let connection = super::super::SeaOrm::connect(&db.url, Some(1)).await?;
        let pool = connection.get_postgres_connection_pool().clone();
        let store = alibi::seaorm::SeaOrmStore::<Schema>::new(
            AuthConfig::new("char-schema-test-secret-at-least-32"),
            connection,
        );
        let id = "usr_00000000000000000000010000";
        assert_eq!(store.get_user_by_id(id).await?.unwrap().id(), id);
        // SeaORM's supported save_as applies a bpchar cast to the parameter;
        // its upstream string binder still sends text on the wire.
        native_plan(&pool, "text", id, true).await?;
        exercise(&db.raw, &store).await?;
        typed_null(&pool, "text").await?;
        native_ownership_bindings(&pool, "text").await?;
        native_mutation_bindings(&pool, "text").await?;
        Ok(())
    }
}

// No override: reproduce the consumer's actual native SqlxStore lookup.
mod baseline_model {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "user", table = "users")]
    pub struct User {
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: NaiveDateTime,
        pub updated_at: NaiveDateTime,
    }
    pub struct Schema;
    impl AuthSchema for Schema {
        type User = User;
        type Session = alibi_sqlx::store::entities::session::Model;
        type Account = alibi_sqlx::store::entities::account::Model;
        type Verification = alibi_sqlx::store::entities::verification::Model;
    }
}
async fn baseline(db: &Db) -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db.url)
        .await?;
    let store = alibi::sqlx::SqlxStore::<baseline_model::Schema>::new(
        AuthConfig::new("baseline-char-schema-test-secret"),
        pool.clone(),
    );
    let id = "usr_00000000000000000000010000";
    assert_eq!(store.get_user_by_id(id).await?.unwrap().id(), id);
    native_plan(&pool, "text", id, false).await?;
    pool.close().await;
    Ok(())
}
async fn native_plan(pool: &sqlx::PgPool, wire_type: &str, id: &str, indexed: bool) -> TestResult {
    let rows = sqlx::query(r#"SELECT name, statement, parameter_types::text AS types, (SELECT typname FROM pg_type WHERE oid = parameter_types[1]) AS first_type, cardinality(parameter_types) AS parameters FROM pg_prepared_statements WHERE statement NOT LIKE '%pg_prepared_statements%' AND statement LIKE 'SELECT %FROM "users" WHERE %"id" = %'"#).fetch_all(pool).await?;
    assert_eq!(rows.len(), 1, "must inspect the native user ID query");
    let row = &rows[0];
    let name: String = row.try_get("name")?;
    let statement: String = row.try_get("statement")?;
    let types: String = row.try_get("types")?;
    assert_eq!(row.try_get::<String, _>("first_type")?, wire_type);
    let mut args = format!("'{}'", id.replace('\'', "''"));
    for _ in 1..row.try_get::<i32, _>("parameters")? {
        args.push_str(", 1");
    }
    // EXPLAIN EXECUTE reuses the exact SQL and parameter types prepared by the
    // native store, on the same physical connection. No planner overrides.
    let explain = format!(
        "EXPLAIN (ANALYZE, BUFFERS) EXECUTE \"{}\"({args})",
        name.replace('"', "\"\"")
    );
    let lines: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(explain))
        .fetch_all(pool)
        .await?;
    let plan = lines.join("\n");
    eprintln!("native SQL: {statement}\nparameter_types: {types}\n{plan}");
    if indexed {
        assert!(plan.contains("Index Scan"), "{plan}");
        assert!(plan.contains("Index Cond: (id = "), "{plan}");
        assert!(!plan.contains("(id)::text"), "{plan}");
    } else {
        assert!(plan.contains("Seq Scan"), "{plan}");
        assert!(plan.contains("(id)::text"), "{plan}");
        assert!(!plan.contains("Index Cond"), "{plan}");
    }
    Ok(())
}
async fn typed_null(pool: &sqlx::PgPool, wire_type: &str) -> TestResult {
    let rows = sqlx::query(r#"SELECT parameter_types::text AS types, statement FROM pg_prepared_statements WHERE statement LIKE 'INSERT INTO "users" (%"linked_id"%VALUES%'"#).fetch_all(pool).await?;
    assert!(!rows.is_empty());
    for row in rows {
        let statement: String = row.try_get("statement")?;
        let types: String = row.try_get("types")?;
        eprintln!("native optional CHAR NULL insert: {statement}\nparameter_types: {types}");
        assert!(types.contains(if wire_type == "bpchar" {
            "character"
        } else {
            wire_type
        }));
        if wire_type == "bpchar" {
            assert!(types.matches("character").count() >= 2, "{types}");
        } else {
            assert!(statement.matches("AS bpchar)").count() >= 2, "{statement}");
        }
    }
    Ok(())
}

async fn install(db: &Db) -> TestResult {
    install_as(
        db,
        if db.is_postgres() { "CHAR(30)" } else { "TEXT" },
        true,
        true,
    )
    .await
}
async fn install_as(db: &Db, char_type: &str, seed: bool, required_text: bool) -> TestResult {
    let nullable_text = if required_text { "NOT NULL" } else { "" };
    for statement in [
        format!(
            "CREATE TABLE users (id {char_type} PRIMARY KEY, linked_id {char_type}, email TEXT {nullable_text}, name TEXT {nullable_text}, email_verified BOOLEAN NOT NULL, image TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)"
        ),
        format!(
            "CREATE TABLE sessions (id {char_type} PRIMARY KEY, user_id {char_type} NOT NULL REFERENCES users(id), token TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, ip_address TEXT, user_agent TEXT, active BOOLEAN NOT NULL)"
        ),
        format!(
            "CREATE TABLE accounts (id {char_type} PRIMARY KEY, user_id {char_type} NOT NULL REFERENCES users(id), account_id TEXT NOT NULL, provider_id TEXT NOT NULL, access_token TEXT, refresh_token TEXT, id_token TEXT, access_token_expires_at TIMESTAMP, refresh_token_expires_at TIMESTAMP, scope TEXT, password TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)"
        ),
        format!(
            "CREATE TABLE verifications (id {char_type} PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL)"
        ),
    ] {
        _ = db.execute(&statement, &[]).await?;
    }
    _ = db
        .execute(
            "CREATE TABLE api_keys (id TEXT PRIMARY KEY, reference_id TEXT NOT NULL)",
            &[],
        )
        .await?;
    if db.is_postgres() && seed {
        _ = db.execute("INSERT INTO users SELECT 'usr_' || lpad(i::text, 26, '0'), NULL, 'synthetic-' || i || '@example.invalid', 'Synthetic', TRUE, NULL, '2026-01-01', '2026-01-01' FROM generate_series(1, 10000) i", &[]).await?;
        _ = db.execute("ANALYZE users", &[]).await?;
    }
    Ok(())
}

async fn exercise<S: AuthSchema>(raw: &Raw, store: &dyn AuthStore<S>) -> TestResult {
    let id = "owner_000000000000000000000001";
    let foreign = "owner_000000000000000000000002";
    let absent = "owner_000000000000000000000003";
    for id in [id, foreign] {
        let mut create = CreateUser::new()
            .with_email(format!("{id}@example.invalid"))
            .with_name("Created");
        create.id = Some(id.into());
        _ = create
            .additional_fields
            .insert("linkedId".into(), alibi_core::utils::json::JsValue::Null);
        let user = store.create_user(create).await?;
        assert_eq!(user.id(), id);
        assert_eq!(user.name(), Some("Created"));
        assert_eq!(user.email(), Some(format!("{id}@example.invalid").as_str()));
    }
    assert!(store.get_user_by_id(absent).await?.is_none());
    let actual: String = on_raw!(raw, |pool| sqlx::query_scalar(
        "SELECT id FROM users WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?);
    assert_eq!(actual, id);
    let null: Option<String> = on_raw!(raw, |pool| sqlx::query_scalar(
        "SELECT linked_id FROM users WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?);
    assert_eq!(null, None);
    // Column equality, including list operands, must use CHAR semantics.
    if raw.is_postgres() {
        assert_eq!(
            store
                .get_user_by_id(&format!("{id}   "))
                .await?
                .unwrap()
                .id(),
            id
        );
        let users = store.list_users_by_ids(&[format!("{id}   ")]).await?;
        assert_eq!(users.len(), 1);
        for operator in ["in", "eq"] {
            let (_, total) = store
                .list_users(alibi_core::ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(alibi_core::UserFilterValue::Multiple(vec![format!(
                        "{id}   "
                    )])),
                    ..Default::default()
                })
                .await?;
            assert_eq!(total, 1);
        }
        let mut short = CreateUser::new();
        short.id = Some("é".into());
        let padded = format!("é{}", " ".repeat(29));
        assert_eq!(store.create_user(short).await?.id(), padded);
        assert_eq!(store.get_user_by_id("é ").await?.unwrap().id(), padded);
        store.delete_user("é").await?;
        assert!(store.get_user_by_id("é").await?.is_none());
        let mut overlong = CreateUser::new();
        overlong.id = Some(format!("{id}x"));
        assert!(store.create_user(overlong).await.is_err());
    }
    let user = store
        .update_user(
            id,
            UpdateUser {
                name: Some("updated".into()),
                email: Some("updated@example.invalid".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(user.id(), id);
    assert_eq!(user.name(), Some("updated"));
    assert_eq!(user.email(), Some("updated@example.invalid"));
    assert!(
        store
            .update_user(absent, UpdateUser::default())
            .await
            .is_err()
    );
    for linked in [Some(foreign), None] {
        let mut update = UpdateUser::default();
        _ = update.additional_fields.insert(
            "linkedId".into(),
            linked.map_or(alibi_core::utils::json::JsValue::Null, |id| {
                alibi_core::utils::json::JsValue::String(id.into())
            }),
        );
        let updated = store.update_user(id, update).await?;
        assert_eq!(updated.id(), id);
        let actual: Option<String> = on_raw!(raw, |pool| sqlx::query_scalar(
            "SELECT linked_id FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_one(pool)
        .await?);
        assert_eq!(actual.as_deref(), linked);
    }
    let account = store
        .create_account(CreateAccount {
            additional_fields: Default::default(),
            user_id: id.into(),
            account_id: "provider-account".into(),
            provider_id: "synthetic".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        })
        .await?;
    assert_eq!(account.id().len(), 30);
    assert_eq!(account.user_id(), id);
    assert_eq!(store.get_user_accounts(id).await?.len(), 1);
    if raw.is_postgres() {
        assert_eq!(store.get_user_accounts(&format!("{id}  ")).await?.len(), 1);
    }
    assert!(store.get_user_accounts(foreign).await?.is_empty());
    assert!(store.get_user_accounts(absent).await?.is_empty());
    let updated = store
        .update_account(
            account.id().as_ref(),
            UpdateAccount {
                access_token: Some("updated-token".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.id(), account.id());
    assert_eq!(updated.access_token(), Some("updated-token"));
    assert!(store.delete_account(absent).await.is_err());
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: id.into(),
            token: Some("char-session".into()),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    assert_eq!(session.id().len(), 30);
    assert_eq!(session.user_id(), id);
    assert_eq!(
        store
            .get_user_by_id(
                store
                    .get_session(session.token())
                    .await?
                    .unwrap()
                    .user_id()
                    .as_ref()
            )
            .await?
            .unwrap()
            .id(),
        id
    );
    assert_eq!(store.get_user_sessions(id).await?.len(), 1);
    if raw.is_postgres() {
        assert_eq!(store.get_user_sessions(&format!("{id}  ")).await?.len(), 1);
    }
    assert!(store.get_user_sessions(foreign).await?.is_empty());
    assert!(store.get_user_sessions(absent).await?.is_empty());
    store.delete_user_sessions(foreign).await?;
    assert!(store.get_session(session.token()).await?.is_some());
    let refreshed = store
        .refresh_session(session.token(), Utc::now() + Duration::hours(2))
        .await?
        .unwrap();
    assert_eq!(refreshed.id(), session.id());
    let verification = store
        .create_verification(CreateVerification {
            identifier: "char-proof".into(),
            value: "expected".into(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await?;
    assert_eq!(verification.id().len(), 30);
    assert!(
        !store
            .compare_and_swap_verification(
                verification.id().as_ref(),
                "foreign",
                "wrong",
                Utc::now()
            )
            .await?
    );
    assert!(
        !store
            .compare_and_swap_verification(absent, "expected", "wrong", Utc::now())
            .await?
    );
    assert!(
        store
            .compare_and_swap_verification(
                verification.id().as_ref(),
                "expected",
                "updated",
                Utc::now() + Duration::hours(1)
            )
            .await?
    );
    assert_eq!(
        store
            .get_verification("char-proof", "updated")
            .await?
            .unwrap()
            .id(),
        verification.id()
    );
    for (table, expected) in [
        ("accounts", account.id()),
        ("sessions", session.id()),
        ("verifications", verification.id()),
    ] {
        let actual: String = on_raw!(raw, |pool| sqlx::query_scalar(sqlx::AssertSqlSafe(
            format!("SELECT id FROM {table} WHERE id = $1")
        ))
        .bind(expected.as_ref())
        .fetch_one(pool)
        .await?);
        assert_eq!(actual, expected);
    }
    store
        .delete_verification(verification.id().as_ref())
        .await?;
    assert!(
        store
            .get_verification("char-proof", "updated")
            .await?
            .is_none()
    );
    store.delete_account(account.id().as_ref()).await?;
    assert!(store.get_user_accounts(id).await?.is_empty());
    store.delete_user_sessions(id).await?;
    assert!(store.get_session(session.token()).await?.is_none());
    store.delete_user(id).await?;
    assert!(store.get_user_by_id(id).await?.is_none());
    assert!(store.get_user_by_id(foreign).await?.is_some());
    eprintln!("native CHAR store lifecycle and absent/foreign ownership passed");
    Ok(())
}

async fn native_ownership_bindings(pool: &sqlx::PgPool, wire_type: &str) -> TestResult {
    for table in ["accounts", "sessions"] {
        let rows = sqlx::query("SELECT statement, parameter_types::text AS types, (SELECT typname FROM pg_type WHERE oid = parameter_types[1]) AS first_type FROM pg_prepared_statements WHERE statement NOT LIKE '%pg_prepared_statements%' AND statement LIKE $1")
            .bind(format!("SELECT %FROM \"{table}\" WHERE %\"user_id\" = %"))
            .fetch_all(pool).await?;
        assert!(!rows.is_empty(), "missing native {table} owner predicates");
        for row in rows {
            let statement: String = row.try_get("statement")?;
            let types: String = row.try_get("types")?;
            assert_eq!(row.try_get::<String, _>("first_type")?, wire_type);
            if wire_type == "text" {
                assert!(statement.contains("AS bpchar)"));
            }
            eprintln!("native {table} owner SQL: {statement}\nparameter_types: {types}");
        }
    }
    Ok(())
}

mod seaorm_text {
    use super::*;
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, alibi::seaorm::AuthEntity)]
    #[sea_orm(table_name = "users")]
    #[auth(role = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: NaiveDateTime,
        pub updated_at: NaiveDateTime,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
    pub struct Schema;
    impl AuthSchema for Schema {
        type User = Model;
        type Session = super::seaorm_char::session::Model;
        type Account = super::seaorm_char::account::Model;
        type Verification = super::seaorm_char::verification::Model;
    }
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_text_and_varchar_ids_retain_significant_spaces() -> TestResult {
    for column in ["TEXT", "VARCHAR(60)"] {
        let db = Db::postgres().await?;
        install_as(&db, column, false, false).await?;
        let connection = super::Sqlx::connect(&db.url, Some(1)).await?;
        let store = alibi::sqlx::SqlxStore::<baseline_model::Schema>::new(
            AuthConfig::new("ordinary-string-column-test-secret"),
            connection,
        );
        ordinary_strings(&store, "sqlx").await?;
        let connection = super::SeaOrm::connect(&db.url, Some(1)).await?;
        let store = alibi::seaorm::SeaOrmStore::<seaorm_text::Schema>::new(
            AuthConfig::new("ordinary-string-column-test-secret"),
            connection,
        );
        ordinary_strings(&store, "seaorm").await?;
        eprintln!("{column}: both native stores preserve ordinary string IDs");
    }
    Ok(())
}
async fn ordinary_strings<S: AuthSchema>(store: &dyn AuthStore<S>, prefix: &str) -> TestResult {
    let id = format!("{prefix}-significant-spaces  ");
    let mut input = CreateUser::new();
    input.id = Some(id.clone());
    assert_eq!(store.create_user(input).await?.id(), id);
    assert_eq!(store.get_user_by_id(&id).await?.unwrap().id(), id);
    assert!(store.get_user_by_id(id.trim_end()).await?.is_none());
    let generated = store.create_user(CreateUser::new()).await?;
    assert_eq!(
        generated.id().len(),
        36,
        "ordinary models retain the UUID default"
    );
    assert!(
        store
            .get_user_by_id(generated.id().as_ref())
            .await?
            .is_some()
    );
    Ok(())
}

// Correct CRUD alone would miss the original planner bug: inspect the ID
// predicate's actual prepared parameter, including UPDATE and DELETE paths.
async fn native_mutation_bindings(pool: &sqlx::PgPool, wire_type: &str) -> TestResult {
    let rows = sqlx::query("SELECT statement, ARRAY(SELECT typname::text FROM unnest(parameter_types) WITH ORDINALITY AS args(oid, position) JOIN pg_type ON pg_type.oid = args.oid ORDER BY position) AS types FROM pg_prepared_statements WHERE statement NOT LIKE '%pg_prepared_statements%' AND (statement LIKE 'UPDATE %' OR statement LIKE 'DELETE FROM %')").fetch_all(pool).await?;
    let mut tables = std::collections::BTreeSet::new();
    for row in rows {
        let statement: String = row.try_get("statement")?;
        let types: Vec<String> = row.try_get("types")?;
        let Some((_, predicate)) = statement.split_once(".\"id\" = ") else {
            continue;
        };
        let (_, argument) = predicate
            .split_once('$')
            .ok_or("missing bound primary ID")?;
        let number: String = argument.chars().take_while(char::is_ascii_digit).collect();
        let index: usize = number.parse()?;
        assert_eq!(
            types.get(index - 1).map(String::as_str),
            Some(wire_type),
            "{statement}: {types:?}"
        );
        if wire_type == "text" {
            assert!(predicate.starts_with("CAST("), "{statement}");
        }
        for table in ["users", "accounts", "sessions", "verifications"] {
            if statement.contains(&format!("\"{table}\"")) {
                _ = tables.insert(table);
            }
        }
        eprintln!("native ID mutation SQL: {statement}\nparameter types: {types:?}");
    }
    assert_eq!(
        tables,
        std::collections::BTreeSet::from(["users", "accounts", "sessions", "verifications"])
    );
    Ok(())
}
