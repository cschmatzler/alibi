//! Numeric application IDs must use resolved identity for admin authorization.
#![allow(
    unreachable_pub,
    reason = "SeaORM requires public entity types in private fixtures"
)]
use better_auth::plugins::{AdminConfig, AdminPlugin, RolePermissions};
use better_auth::{AuthBuilder, AuthConfig, AuthSchema};
use better_auth_core::store::AuthStore;
use better_auth_core::{
    AuthRequest, AuthResult, AuthSession, AuthUser, CreateSession, CreateUser, UpdateUser,
};
use chrono::Utc;
use sqlx::Row;
use std::{borrow::Cow, collections::HashMap, sync::Arc};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

macro_rules! user_contract {
    () => {
        impl AuthUser for Model {
            fn id(&self) -> Cow<'_, str> {
                Cow::Owned(self.id.to_string())
            }
            fn email(&self) -> Option<&str> {
                self.email.as_deref()
            }
            fn name(&self) -> Option<&str> {
                self.name.as_deref()
            }
            fn email_verified(&self) -> bool {
                false
            }
            fn image(&self) -> Option<&str> {
                None
            }
            fn created_at(&self) -> chrono::DateTime<Utc> {
                self.created_at
            }
            fn updated_at(&self) -> chrono::DateTime<Utc> {
                self.updated_at
            }
            fn username(&self) -> Option<&str> {
                None
            }
            fn display_username(&self) -> Option<&str> {
                None
            }
            fn two_factor_enabled(&self) -> bool {
                false
            }
            fn role(&self) -> Option<&str> {
                self.role.as_deref()
            }
            fn banned(&self) -> bool {
                false
            }
            fn ban_reason(&self) -> Option<&str> {
                None
            }
            fn ban_expires(&self) -> Option<chrono::DateTime<Utc>> {
                None
            }
            fn metadata(&self) -> &serde_json::Value {
                &serde_json::Value::Null
            }
        }
    };
}

#[cfg(feature = "sqlx")]
mod sqlx_numeric {
    use super::*;
    use better_auth::sqlx::model::ActiveRow;
    use better_auth::sqlx::value::SqlValue;
    use better_auth::sqlx::{SqlxPool, SqlxStore, SqlxUserModel};
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, better_auth::sqlx::SqlxModel)]
    #[auth(table = "users")]
    pub struct Model {
        pub id: i64,
        pub email: Option<String>,
        pub name: Option<String>,
        pub role: Option<String>,
        pub created_at: chrono::DateTime<Utc>,
        pub updated_at: chrono::DateTime<Utc>,
    }
    user_contract!();
    impl SqlxUserModel for Model {
        fn id_column() -> &'static str {
            "id"
        }
        fn email_column() -> &'static str {
            "email"
        }
        fn name_column() -> &'static str {
            "name"
        }
        fn created_at_column() -> &'static str {
            "created_at"
        }
        fn parse_id(id: &str) -> AuthResult<SqlValue> {
            Ok(SqlValue::BigInt(Some(id.parse().map_err(|_| {
                better_auth_core::AuthError::bad_request("invalid numeric ID")
            })?)))
        }
        fn new_active(
            id: Option<SqlValue>,
            user: CreateUser,
            now: chrono::DateTime<Utc>,
        ) -> ActiveRow {
            let mut row = ActiveRow::new();
            if let Some(id) = id {
                row.set("id", id);
            }
            row.set("email", user.email);
            row.set("name", user.name);
            row.set("role", user.role);
            row.set("created_at", now);
            row.set("updated_at", now);
            row
        }
        fn apply_update(row: &mut ActiveRow, user: UpdateUser, now: chrono::DateTime<Utc>) {
            if let Some(email) = user.email {
                row.set("email", email);
            }
            if let Some(name) = user.name {
                row.set("name", name);
            }
            if let Some(role) = user.role {
                row.set("role", role);
            }
            row.set("updated_at", now);
        }
    }
    struct Schema;
    impl AuthSchema for Schema {
        type User = Model;
        type Session = better_auth_sqlx::store::entities::session::Model;
        type Account = better_auth_sqlx::store::entities::account::Model;
        type Verification = better_auth_sqlx::store::entities::verification::Model;
    }
    #[tokio::test]
    async fn canonical_admin_identity() -> TestResult {
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        better_auth_sqlx::store::__private_test_support::migrator::run_migrations(&pool).await?;
        let raw = pool.as_sqlite().ok_or("not SQLite")?.clone();
        install(&raw).await?;
        exercise(Arc::new(SqlxStore::<Schema>::new(config(), pool)), &raw).await
    }
}

#[cfg(feature = "seaorm")]
mod seaorm_numeric {
    use super::*;
    use better_auth::seaorm::sea_orm::{self, ActiveValue::Set, entity::prelude::*};
    use better_auth::seaorm::{SeaOrmStore, SeaOrmUserModel};
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub email: Option<String>,
        pub name: Option<String>,
        pub role: Option<String>,
        pub created_at: chrono::DateTime<Utc>,
        pub updated_at: chrono::DateTime<Utc>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
    user_contract!();
    impl SeaOrmUserModel for Model {
        type Id = i64;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;
        fn id_column() -> Column {
            Column::Id
        }
        fn email_column() -> Column {
            Column::Email
        }
        fn name_column() -> Column {
            Column::Name
        }
        fn created_at_column() -> Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<i64> {
            id.parse()
                .map_err(|_| better_auth_core::AuthError::bad_request("invalid numeric ID"))
        }
        fn new_active(
            id: Option<i64>,
            user: CreateUser,
            now: chrono::DateTime<Utc>,
        ) -> ActiveModel {
            ActiveModel {
                id: id.map_or(sea_orm::ActiveValue::NotSet, Set),
                email: Set(user.email),
                name: Set(user.name),
                role: Set(user.role),
                created_at: Set(now),
                updated_at: Set(now),
            }
        }
        fn apply_update(row: &mut ActiveModel, user: UpdateUser, now: chrono::DateTime<Utc>) {
            if let Some(email) = user.email {
                row.email = Set(Some(email));
            }
            if let Some(name) = user.name {
                row.name = Set(Some(name));
            }
            if let Some(role) = user.role {
                row.role = Set(Some(role));
            }
            row.updated_at = Set(now);
        }
    }
    struct Schema;
    impl AuthSchema for Schema {
        type User = Model;
        type Session = better_auth_seaorm::store::entities::session::Model;
        type Account = better_auth_seaorm::store::entities::account::Model;
        type Verification = better_auth_seaorm::store::entities::verification::Model;
    }
    #[tokio::test]
    async fn canonical_admin_identity() -> TestResult {
        let database = better_auth::seaorm::Database::connect("sqlite::memory:").await?;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await?;
        let raw = database.get_sqlite_connection_pool().clone();
        install(&raw).await?;
        exercise(
            Arc::new(SeaOrmStore::<Schema>::new(config(), database)),
            &raw,
        )
        .await
    }
}

fn config() -> AuthConfig {
    AuthConfig::new("numeric-admin-identity-secret-at-least-32")
}
async fn install(raw: &sqlx::SqlitePool) -> TestResult {
    _ = sqlx::query(sqlx::AssertSqlSafe("DROP TABLE users"))
        .execute(raw)
        .await?;
    _ = sqlx::query(sqlx::AssertSqlSafe("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT, role TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")).execute(raw).await?;
    for (id, role) in [
        (1, "operator"),
        (2, "operator,elevated"),
        (3, "elevated"),
        (42, "user"),
        (43, "user"),
    ] {
        _ = sqlx::query(sqlx::AssertSqlSafe(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
        ))
        .bind(id)
        .bind(format!("id-{id}@identity.fixture.test"))
        .bind(format!("User {id}"))
        .bind(role)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(raw)
        .await?;
    }
    for id in [1, 2, 3, 42, 43] {
        _ = sqlx::query(sqlx::AssertSqlSafe("INSERT INTO accounts (id, account_id, provider_id, user_id, password, created_at, updated_at) VALUES (?, ?, 'credential', ?, 'fixture-password', ?, ?)"))
            .bind(format!("account-{id}")).bind(id.to_string()).bind(id.to_string()).bind(Utc::now()).bind(Utc::now()).execute(raw).await?;
    }
    Ok(())
}
// Independent physical snapshots include every column, including peer sessions
// and account credentials, rather than replaying store projections.
async fn rows(raw: &sqlx::SqlitePool, table: &str) -> TestResult<Vec<String>> {
    let columns = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info({table})")))
        .fetch_all(raw)
        .await?;
    let names = columns
        .iter()
        .map(|column| column.get::<String, _>("name"))
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(",");
    let values: Vec<(String,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT json_array({names}) FROM {table} ORDER BY id"
    )))
    .fetch_all(raw)
    .await?;
    Ok(values.into_iter().map(|row| row.0).collect())
}
async fn exercise<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    raw: &sqlx::SqlitePool,
) -> TestResult {
    assert_eq!(
        store
            .get_user_by_id("00042")
            .await?
            .ok_or("target absent")?
            .id(),
        "42"
    );
    let roles = HashMap::from([
        (
            "operator".into(),
            RolePermissions::new().allow("user", ["impersonate"]),
        ),
        (
            "elevated".into(),
            RolePermissions::new().allow("user", ["impersonate-admins"]),
        ),
        ("user".into(), RolePermissions::new()),
    ]);
    let auth = AuthBuilder::<S>::new(config())
        .store_arc(Arc::clone(&store))
        .plugin(AdminPlugin::with_config(AdminConfig {
            roles: Some(roles),
            admin_roles: Some(vec![]),
            admin_user_ids: Some(vec!["42".into()]),
            ..Default::default()
        }))
        .build()
        .await?;
    for (actor, target, status) in [
        ("1", "42", 403),
        ("1", "00042", 403),
        ("1", "00043", 200),
        ("2", "00042", 200),
        ("3", "00043", 403),
    ] {
        let original = store
            .create_session(CreateSession {
                additional_fields: Default::default(),
                token: None,
                active_team_id: None,
                user_id: actor.into(),
                expires_at: Utc::now() + chrono::Duration::days(7),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let before_users = rows(raw, "users").await?;
        let before_accounts = rows(raw, "accounts").await?;
        let before_sessions = rows(raw, "sessions").await?;
        let count: (i64,) = sqlx::query_as(sqlx::AssertSqlSafe("SELECT COUNT(*) FROM sessions"))
            .fetch_one(raw)
            .await?;
        let cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
            original.token(),
            config().current_secret(),
        );
        let mut request = AuthRequest::new(
            better_auth_core::HttpMethod::Post,
            "/admin/impersonate-user",
        );
        _ = request
            .headers
            .insert("origin".into(), config().base_url.clone());
        _ = request.headers.insert(
            "cookie".into(),
            format!("better-auth.session_token={cookie}"),
        );
        _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        request.body = Some(serde_json::to_vec(&serde_json::json!({"userId": target}))?);
        let response = auth.handle_request(request).await?;
        assert_eq!(response.status, status, "actor={actor} selector={target}");
        let after: (i64,) = sqlx::query_as(sqlx::AssertSqlSafe("SELECT COUNT(*) FROM sessions"))
            .fetch_one(raw)
            .await?;
        assert_eq!(after.0, count.0 + i64::from(status == 200));
        if status == 200 {
            let body: serde_json::Value = serde_json::from_slice(&response.body)?;
            let canonical = target.parse::<i64>()?.to_string();
            assert_eq!(
                body.pointer("/user/id").and_then(serde_json::Value::as_str),
                Some(canonical.as_str())
            );
            assert_eq!(
                body.pointer("/session/userId")
                    .and_then(serde_json::Value::as_str),
                Some(canonical.as_str())
            );
            assert_eq!(
                body.pointer("/session/impersonatedBy")
                    .and_then(serde_json::Value::as_str),
                Some(actor)
            );
            let token = body
                .pointer("/session/token")
                .and_then(serde_json::Value::as_str)
                .ok_or("no token")?;
            let session = store
                .get_session(token)
                .await?
                .ok_or("no persisted session")?;
            assert_eq!(session.user_id(), canonical);
            assert_eq!(session.impersonated_by(), Some(actor));
            assert_ne!(session.id(), original.id());
        } else {
            let body: serde_json::Value = serde_json::from_slice(&response.body)?;
            assert_eq!(
                body.get("message").and_then(serde_json::Value::as_str),
                Some(if actor == "3" {
                    "You are not allowed to impersonate users"
                } else {
                    "You cannot impersonate admins"
                })
            );
        }
        assert_eq!(
            store
                .get_session(original.token())
                .await?
                .ok_or("original session deleted")?
                .id(),
            original.id()
        );
        let after_users = rows(raw, "users").await?;
        let after_accounts = rows(raw, "accounts").await?;
        let after_sessions = rows(raw, "sessions").await?;
        assert_eq!(before_users, after_users);
        assert_eq!(before_accounts, after_accounts);
        for original_row in &before_sessions {
            assert!(
                after_sessions.contains(original_row),
                "existing session changed"
            );
        }
        if status != 200 {
            assert_eq!(before_sessions, after_sessions);
        }
        eprintln!(
            "identity observation: {}",
            serde_json::json!({"actor":actor,"selector":target,"status":response.status,"response":serde_json::from_slice::<serde_json::Value>(&response.body)?,"before":{"users":before_users,"accounts":before_accounts,"sessions":before_sessions},"after":{"users":after_users,"accounts":after_accounts,"sessions":after_sessions}})
        );
    }
    Ok(())
}
