//! Numeric application IDs must use resolved identity for admin authorization.
#![allow(
    clippy::indexing_slicing,
    reason = "contract assertions inspect public JSON fields directly"
)]
#![allow(
    unreachable_pub,
    reason = "SeaORM requires public entity types in private fixtures"
)]
use alibi::plugins::{AdminConfig, AdminPlugin, RolePermissions};
use alibi::store::AuthStore;
use alibi::{AuthBuilder, AuthConfig, AuthSchema};
use alibi::{
    AuthRequest, AuthResult, AuthSession, AuthUser, CreateSession, CreateUser, UpdateUser,
};
use chrono::Utc;
use sqlx::Row;
use std::{borrow::Cow, collections::HashMap, sync::Arc};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

macro_rules! user_contract {
    () => {
        impl AuthUser for Model {
            fn additional_fields(&self) -> alibi::field_policy::FieldOutput {
                serde_json::json!({"score":self.score,"reviewedAt":self.reviewed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"profile":self.profile}).as_object().cloned().unwrap_or_default()
            }
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
            fn banned(&self) -> bool { self.banned }
            fn ban_reason(&self) -> Option<&str> { self.ban_reason.as_deref() }
            fn ban_expires(&self) -> Option<chrono::DateTime<Utc>> { self.ban_expires }
            fn metadata(&self) -> &serde_json::Value {
                &serde_json::Value::Null
            }
        }
    };
}

#[cfg(feature = "sqlx")]
mod sqlx_numeric {
    use super::*;
    use alibi::sqlx::model::ActiveRow;
    use alibi::sqlx::value::SqlValue;
    use alibi::sqlx::{SqlxPool, SqlxStore, SqlxUserModel};
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)]
    #[auth(table = "users")]
    pub struct Model {
        pub id: i64,
        pub email: Option<String>,
        pub name: Option<String>,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<chrono::DateTime<Utc>>,
        pub score: i64,
        pub reviewed_at: chrono::DateTime<Utc>,
        pub profile: serde_json::Value,
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
        fn list_users_column(field: &str) -> Option<&'static str> {
            match field {
                "id" => Some("id"),
                "email" => Some("email"),
                "name" => Some("name"),
                "createdAt" => Some("created_at"),
                "score" => Some("score"),
                "reviewedAt" => Some("reviewed_at"),
                "profile" => Some("profile"),
                _ => None,
            }
        }
        fn parse_id(id: &str) -> AuthResult<SqlValue> {
            Ok(SqlValue::BigInt(Some(id.parse().map_err(|_| {
                alibi::AuthError::bad_request("invalid numeric ID")
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
            row.set("banned", user.banned.unwrap_or(false));
            row.set("ban_reason", Option::<String>::None);
            row.set("ban_expires", Option::<chrono::DateTime<Utc>>::None);
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
            if let Some(banned) = user.banned {
                row.set("banned", banned);
            }
            row.set("ban_reason", user.ban_reason);
            if let Some(expiry) = user.ban_expires {
                row.set("ban_expires", expiry);
            } else if user.banned == Some(false) {
                row.set("ban_expires", Option::<chrono::DateTime<Utc>>::None);
            }
            row.set("updated_at", now);
        }
    }
    struct Schema;
    impl AuthSchema for Schema {
        type User = Model;
        type Session = alibi::sqlx::store::entities::session::Model;
        type Account = alibi::sqlx::store::entities::account::Model;
        type Verification = alibi::sqlx::store::entities::verification::Model;
    }
    #[tokio::test]
    #[ignore = "requires CLOCK_REALTIME proof clock; see admin closure audit"]
    async fn strict_expiry_and_mutation_hook_order() -> TestResult {
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        alibi::sqlx::store::__private_test_support::migrator::run_migrations(&pool).await?;
        let raw = pool.as_sqlite().ok_or("not SQLite")?.clone();
        install(&raw).await?;
        let hooks = Arc::new(AdmissionEvents::default());
        exercise_admission(
            Arc::new(SqlxStore::<Schema>::new(config(), pool).with_hooks(vec![hooks.clone()])),
            &raw,
            hooks,
        )
        .await
    }
    #[tokio::test]
    async fn configured_scalar_filters_and_physical_paging() -> TestResult {
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        alibi::sqlx::store::__private_test_support::migrator::run_migrations(&pool).await?;
        let raw = pool.as_sqlite().ok_or("not SQLite")?.clone();
        install(&raw).await?;
        exercise_custom_query(Arc::new(SqlxStore::<Schema>::new(config(), pool)), &raw).await
    }
    #[tokio::test]
    async fn date_sort_default_pages_ascending() -> TestResult {
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        alibi::sqlx::store::__private_test_support::migrator::run_migrations(&pool).await?;
        let raw = pool.as_sqlite().ok_or("not SQLite")?.clone();
        install(&raw).await?;
        exercise_query(Arc::new(SqlxStore::<Schema>::new(config(), pool)), &raw).await
    }
    #[tokio::test]
    async fn canonical_admin_identity() -> TestResult {
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        alibi::sqlx::store::__private_test_support::migrator::run_migrations(&pool).await?;
        let raw = pool.as_sqlite().ok_or("not SQLite")?.clone();
        install(&raw).await?;
        exercise(Arc::new(SqlxStore::<Schema>::new(config(), pool)), &raw).await
    }
}

#[cfg(feature = "seaorm")]
mod seaorm_numeric {
    use super::*;
    use alibi::seaorm::sea_orm::{self, ActiveValue::Set, entity::prelude::*};
    use alibi::seaorm::{SeaOrmStore, SeaOrmUserModel};
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub email: Option<String>,
        pub name: Option<String>,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<chrono::DateTime<Utc>>,
        pub score: i64,
        pub reviewed_at: chrono::DateTime<Utc>,
        pub profile: serde_json::Value,
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
        fn list_users_column(field: &str) -> Option<Column> {
            match field {
                "id" => Some(Column::Id),
                "email" => Some(Column::Email),
                "name" => Some(Column::Name),
                "createdAt" => Some(Column::CreatedAt),
                "score" => Some(Column::Score),
                "reviewedAt" => Some(Column::ReviewedAt),
                "profile" => Some(Column::Profile),
                _ => None,
            }
        }
        fn parse_id(id: &str) -> AuthResult<i64> {
            id.parse()
                .map_err(|_| alibi::AuthError::bad_request("invalid numeric ID"))
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
                banned: Set(user.banned.unwrap_or(false)),
                ban_reason: Set(None),
                ban_expires: Set(None),
                score: Set(0),
                reviewed_at: Set(now),
                profile: Set(serde_json::json!({})),
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
            if let Some(banned) = user.banned {
                row.banned = Set(banned);
            }
            row.ban_reason = Set(user.ban_reason);
            if let Some(expiry) = user.ban_expires {
                row.ban_expires = Set(expiry);
            } else if user.banned == Some(false) {
                row.ban_expires = Set(None);
            }
            row.updated_at = Set(now);
        }
    }
    struct Schema;
    impl AuthSchema for Schema {
        type User = Model;
        type Session = alibi::seaorm::store::entities::session::Model;
        type Account = alibi::seaorm::store::entities::account::Model;
        type Verification = alibi::seaorm::store::entities::verification::Model;
    }
    #[tokio::test]
    #[ignore = "requires CLOCK_REALTIME proof clock; see admin closure audit"]
    async fn strict_expiry_and_mutation_hook_order() -> TestResult {
        let database = alibi::seaorm::Database::connect("sqlite::memory:").await?;
        alibi::seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
        let raw = database.get_sqlite_connection_pool().clone();
        install(&raw).await?;
        let hooks = Arc::new(AdmissionEvents::default());
        exercise_admission(
            Arc::new(
                SeaOrmStore::<Schema>::new(config(), database).with_hooks(vec![hooks.clone()]),
            ),
            &raw,
            hooks,
        )
        .await
    }
    #[tokio::test]
    async fn configured_scalar_filters_and_physical_paging() -> TestResult {
        let database = alibi::seaorm::Database::connect("sqlite::memory:").await?;
        alibi::seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
        let raw = database.get_sqlite_connection_pool().clone();
        install(&raw).await?;
        exercise_custom_query(
            Arc::new(SeaOrmStore::<Schema>::new(config(), database)),
            &raw,
        )
        .await
    }
    #[tokio::test]
    async fn date_sort_default_pages_ascending() -> TestResult {
        let database = alibi::seaorm::Database::connect("sqlite::memory:").await?;
        alibi::seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
        let raw = database.get_sqlite_connection_pool().clone();
        install(&raw).await?;
        exercise_query(
            Arc::new(SeaOrmStore::<Schema>::new(config(), database)),
            &raw,
        )
        .await
    }
    #[tokio::test]
    async fn canonical_admin_identity() -> TestResult {
        let database = alibi::seaorm::Database::connect("sqlite::memory:").await?;
        alibi::seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
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
    let mut config = AuthConfig::new("numeric-admin-identity-secret-at-least-32");
    for (name, schema, column) in [
        ("score", serde_json::json!({"type":"number"}), "score"),
        (
            "reviewedAt",
            serde_json::json!({"type":"string","format":"date-time"}),
            "reviewed_at",
        ),
        ("profile", serde_json::json!({"type":"object"}), "profile"),
    ] {
        let mut field = alibi::field_policy::FieldConfig::new(schema);
        field.field_name = Some(column.into());
        _ = config.user.additional_fields.insert(name.into(), field);
    }
    config
}
async fn install(raw: &sqlx::SqlitePool) -> TestResult {
    _ = sqlx::query(sqlx::AssertSqlSafe("DROP TABLE users"))
        .execute(raw)
        .await?;
    _ = sqlx::query(sqlx::AssertSqlSafe("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT, role TEXT, banned BOOLEAN NOT NULL DEFAULT 0, ban_reason TEXT, ban_expires TEXT, score INTEGER NOT NULL DEFAULT 0, reviewed_at TEXT NOT NULL DEFAULT '2020-01-01T00:00:00Z', profile TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")).execute(raw).await?;
    for (id, role) in [
        (1, "operator"),
        (2, "operator,elevated"),
        (3, "elevated"),
        (42, "user"),
        (43, "user"),
    ] {
        _ = sqlx::query(sqlx::AssertSqlSafe(
            "INSERT INTO users (id,email,name,role,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?)",
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
        let cookie = alibi::utils::cookie_utils::sign_cookie_value(
            original.token(),
            config().current_secret(),
        );
        let mut request = AuthRequest::new(alibi::HttpMethod::Post, "/admin/impersonate-user");
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
    // This handwritten model intentionally supplies no additional-field
    // binding. Reject the complete update before even its supported name writes.
    let auth = AuthBuilder::<S>::new(config())
        .store_arc(Arc::clone(&store))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
        .build()
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: "43".into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            token: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: Default::default(),
        })
        .await?;
    let cookie =
        alibi::utils::cookie_utils::sign_cookie_value(session.token(), config().current_secret());
    for (input, status) in [
        (
            serde_json::json!({"name":"must-not-persist","score":99}),
            500,
        ),
        (serde_json::json!({"name":"Supported mutation"}), 200),
    ] {
        let before = rows(raw, "users").await?;
        let mut request = AuthRequest::new(alibi::HttpMethod::Post, "/update-user");
        request.headers.extend([
            ("origin".into(), config().base_url.clone()),
            (
                "cookie".into(),
                format!("better-auth.session_token={cookie}"),
            ),
            ("content-type".into(), "application/json".into()),
        ]);
        request.body = Some(serde_json::to_vec(&input)?);
        let response = Box::pin(auth.handle_request(request)).await?;
        assert_eq!(
            response.status,
            status,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        if status == 500 {
            assert_eq!(rows(raw, "users").await?, before);
        } else {
            assert_eq!(
                store.get_user_by_id("43").await?.unwrap().name(),
                Some("Supported mutation")
            );
        }
    }
    Ok(())
}

// Shared public-route contract, with independent physical SQLite fixtures for
// each adapter. Existing identity checks do not inspect query order or paging.
async fn exercise_query<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    raw: &sqlx::SqlitePool,
) -> TestResult {
    for (id, day) in [(1, 1), (2, 5), (3, 4), (42, 3), (43, 2)] {
        let date = chrono::DateTime::parse_from_rfc3339(&format!("2020-01-{day:02}T00:00:00Z"))?
            .with_timezone(&Utc);
        _ = sqlx::query(sqlx::AssertSqlSafe(
            "UPDATE users SET created_at = ?, updated_at = ? WHERE id = ?",
        ))
        .bind(date)
        .bind(date)
        .bind(id)
        .execute(raw)
        .await?;
    }
    let auth = AuthBuilder::<S>::new(config())
        .store_arc(Arc::clone(&store))
        .plugin(AdminPlugin::with_config(AdminConfig {
            admin_user_ids: Some(vec!["1".into()]),
            ..Default::default()
        }))
        .build()
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: "1".into(),
            expires_at: Utc::now() + chrono::Duration::days(7),
            additional_fields: Default::default(),
            token: None,
            active_team_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let before = [
        rows(raw, "users").await?,
        rows(raw, "accounts").await?,
        rows(raw, "sessions").await?,
    ];
    for (direction, expected) in [
        (None, vec!["42", "3"]),
        (Some("asc"), vec!["42", "3"]),
        (Some("desc"), vec!["3", "42"]),
    ] {
        let mut request = AuthRequest::new(alibi::HttpMethod::Get, "/admin/list-users");
        _ = request.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                alibi::utils::cookie_utils::sign_cookie_value(
                    session.token(),
                    config().current_secret()
                )
            ),
        );
        for (key, value) in [
            ("sortBy", "createdAt"),
            ("filterField", "createdAt"),
            ("filterOperator", "gt"),
            ("filterValue", "2020-01-01T00:00:00Z"),
            ("offset", "1"),
            ("limit", "2"),
        ] {
            _ = request.query.insert(key.into(), value.into());
        }
        if let Some(direction) = direction {
            _ = request
                .query
                .insert("sortDirection".into(), direction.into());
        }
        let response = auth.handle_request(request).await?;
        let body: serde_json::Value = serde_json::from_slice(&response.body)?;
        println!(
            "{}",
            serde_json::json!({"adapter": std::any::type_name::<S>(), "direction": direction, "status": response.status, "body": body, "before": before, "after": [rows(raw, "users").await?, rows(raw, "accounts").await?, rows(raw, "sessions").await?]})
        );
        assert_eq!(response.status, 200);
        let ids = body
            .get("users")
            .and_then(serde_json::Value::as_array)
            .ok_or("no users")?
            .iter()
            .map(|user| {
                user.get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("no ID")
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(ids, expected, "direction={direction:?}");
        assert_eq!(body.get("total"), Some(&serde_json::json!(4)));
        assert_eq!(body.get("offset"), Some(&serde_json::json!(1)));
        assert_eq!(body.get("limit"), Some(&serde_json::json!(2)));
    }
    let after = [
        rows(raw, "users").await?,
        rows(raw, "accounts").await?,
        rows(raw, "sessions").await?,
    ];
    println!(
        "{}",
        serde_json::json!({"adapter": std::any::type_name::<S>(), "before": before, "after": after})
    );
    assert_eq!(after, before);
    Ok(())
}

// Scalar application columns were previously filtered against a fixed built-in
// projection. Numeric physical ordering must also precede pagination.
async fn exercise_custom_query<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    raw: &sqlx::SqlitePool,
) -> TestResult {
    for (id, score, day, tier) in [
        (1, 1, 1, "a"),
        (2, 20, 5, "b"),
        (3, 10, 4, "a"),
        (42, 3, 3, "b"),
        (43, 2, 2, "a"),
    ] {
        _ = sqlx::query(sqlx::AssertSqlSafe(
            "UPDATE users SET score=?, reviewed_at=?, profile=?, created_at=?, updated_at=? WHERE id=?",
        ))
        .bind(score)
        .bind(format!("2020-01-{day:02}T00:00:00Z"))
        .bind(serde_json::json!({"tier":tier}).to_string())
        .bind("2019-01-01T00:00:00Z")
        .bind("2019-01-01T00:00:00Z")
        .bind(id)
        .execute(raw)
        .await?;
    }
    let auth = AuthBuilder::<S>::new(config())
        .store_arc(Arc::clone(&store))
        .plugin(AdminPlugin::with_config(AdminConfig {
            admin_user_ids: Some(vec!["1".into()]),
            ..Default::default()
        }))
        .build()
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: "1".into(),
            expires_at: Utc::now() + chrono::Duration::days(7),
            additional_fields: Default::default(),
            token: None,
            active_team_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let before = [
        rows(raw, "users").await?,
        rows(raw, "accounts").await?,
        rows(raw, "sessions").await?,
    ];
    for (field, operator, value, sort, direction, expected, total) in [
        ("score", "gte", "3", "score", "asc", vec!["3", "2"], 3),
        ("score", "gte", "3", "score", "desc", vec!["3", "42"], 3),
        (
            "reviewedAt",
            "gt",
            "2020-01-01T00:00:00Z",
            "reviewedAt",
            "asc",
            vec!["42", "3"],
            4,
        ),
        (
            "profile",
            "eq",
            r#"{"tier":"a"}"#,
            "score",
            "asc",
            vec!["43", "3"],
            3,
        ),
        ("profile", "contains", "b", "id", "asc", vec!["42"], 2),
        ("score", "gte", "3", "profile", "asc", vec!["2", "42"], 3),
        ("score", "lt", "3", "id", "desc", vec!["1"], 2),
    ] {
        let mut request = AuthRequest::new(alibi::HttpMethod::Get, "/admin/list-users");
        _ = request.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                alibi::utils::cookie_utils::sign_cookie_value(
                    session.token(),
                    config().current_secret()
                )
            ),
        );
        for (key, value) in [
            ("filterField", field),
            ("filterOperator", operator),
            ("filterValue", value),
            ("sortBy", sort),
            ("sortDirection", direction),
            ("offset", "1"),
            ("limit", "2"),
        ] {
            _ = request.query.insert(key.into(), value.into());
        }
        let response = auth.handle_request(request).await?;
        let body: serde_json::Value = serde_json::from_slice(&response.body)?;
        let after = [
            rows(raw, "users").await?,
            rows(raw, "accounts").await?,
            rows(raw, "sessions").await?,
        ];
        println!(
            "custom observation: {}",
            serde_json::json!({"adapter":std::any::type_name::<S>(),"field":field,"operator":operator,"value":value,"sort":sort,"direction":direction,"status":response.status,"body":body,"before":before,"after":after})
        );
        assert_eq!(response.status, 200);
        let ids = body["users"]
            .as_array()
            .ok_or("no users")?
            .iter()
            .map(|u| u["id"].as_str().ok_or("no id"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(ids, expected, "{field} {operator} {direction}");
        assert_eq!(body["total"], serde_json::json!(total));
        assert_eq!(body["offset"], 1);
        assert_eq!(body["limit"], 2);
        assert_eq!(after, before);
    }
    Ok(())
}

#[derive(Default)]
struct AdmissionEvents {
    mode: std::sync::atomic::AtomicU8,
    events: tokio::sync::Mutex<Vec<String>>,
}
impl AdmissionEvents {
    async fn event(&self, event: &str, failure: u8) -> AuthResult<()> {
        self.events.lock().await.push(event.into());
        let mode = self.mode.load(std::sync::atomic::Ordering::SeqCst);
        if mode == failure {
            return Err(alibi::AuthError::Upstream {
                status: 409,
                code: "HOOK_REFUSED",
                message: "configured hook refused",
            });
        }
        if (mode == 2 && event == "session-before")
            || (mode == 8 && event == "user-before")
            || (mode == 9 && event == "user-after")
            || (mode == 10 && event == "session-after")
        {
            return Err(alibi::AuthError::internal("ordinary hook failure"));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema, B: alibi::store::HookBackend> alibi::store::DatabaseHooks<S, B>
    for AdmissionEvents
{
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        _: &alibi::store::DatabaseHookContext<'_, B>,
    ) -> AuthResult<alibi::store::HookControl> {
        self.event("session-before", 1).await?;
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 5 {
            input.user_id = "42".into();
        }
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 6 {
            return Ok(alibi::store::HookControl::Cancel);
        }
        Ok(alibi::store::HookControl::Continue)
    }
    async fn after_create_session(
        &self,
        _: &S::Session,
        _: &alibi::store::DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        self.event("session-after", 7).await
    }
    async fn before_update_user(
        &self,
        _: &str,
        _: &mut UpdateUser,
        _: &alibi::store::DatabaseHookContext<'_, B>,
    ) -> AuthResult<alibi::store::HookControl> {
        self.event("user-before", 3).await?;
        Ok(alibi::store::HookControl::Continue)
    }
    async fn after_update_user(
        &self,
        _: &S::User,
        _: &alibi::store::DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        self.event("user-after", 4).await
    }
}

async fn exercise_admission<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    raw: &sqlx::SqlitePool,
    hooks: Arc<AdmissionEvents>,
) -> TestResult {
    let clock = Utc::now();
    assert_eq!(
        clock.timestamp_millis(),
        1893456000000,
        "run under supplied frozen realtime clock"
    );
    assert_eq!(clock.timestamp_subsec_nanos(), 0);
    let auth = AuthBuilder::<S>::new(config())
        .store_arc(store.clone())
        .plugin(AdminPlugin::with_config(AdminConfig {
            admin_user_ids: Some(vec!["1".into()]),
            ..Default::default()
        }))
        .build()
        .await?;
    let original = store
        .create_session(CreateSession {
            user_id: "1".into(),
            expires_at: clock + chrono::Duration::days(7),
            additional_fields: Default::default(),
            token: None,
            active_team_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let peer = store
        .create_session(CreateSession {
            user_id: "42".into(),
            expires_at: clock + chrono::Duration::days(7),
            additional_fields: Default::default(),
            token: None,
            active_team_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    for (mode, delta, target, status, events, cleared, inserted) in [
        (0, 0, "00042", 403, vec![], false, false),
        (0, 1, "00042", 403, vec![], false, false),
        (
            0,
            -1,
            "00042",
            200,
            vec![
                "user-before",
                "user-after",
                "session-before",
                "session-after",
            ],
            true,
            true,
        ),
        (
            1,
            -1,
            "00042",
            409,
            vec!["user-before", "user-after", "session-before"],
            true,
            false,
        ),
        (
            2,
            -1,
            "00042",
            500,
            vec!["user-before", "user-after", "session-before"],
            true,
            false,
        ),
        (3, -1, "00042", 409, vec!["user-before"], false, false),
        (
            4,
            -1,
            "00042",
            409,
            vec!["user-before", "user-after"],
            true,
            false,
        ),
        (
            5,
            0,
            "43",
            200,
            vec!["session-before", "session-after"],
            false,
            true,
        ),
        (
            6,
            -1,
            "00042",
            500,
            vec!["user-before", "user-after", "session-before"],
            true,
            false,
        ),
        (
            7,
            -1,
            "00042",
            409,
            vec![
                "user-before",
                "user-after",
                "session-before",
                "session-after",
            ],
            true,
            true,
        ),
        (8, -1, "00042", 500, vec!["user-before"], false, false),
        (
            9,
            -1,
            "00042",
            500,
            vec!["user-before", "user-after"],
            true,
            false,
        ),
        (
            10,
            -1,
            "00042",
            500,
            vec![
                "user-before",
                "user-after",
                "session-before",
                "session-after",
            ],
            true,
            true,
        ),
    ] {
        _=sqlx::query(sqlx::AssertSqlSafe("UPDATE users SET banned=1,ban_reason='boundary',ban_expires=?,updated_at=? WHERE id=42")).bind(clock+chrono::Duration::milliseconds(delta)).bind(clock).execute(raw).await?;
        hooks.events.lock().await.clear();
        hooks.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
        let before = [
            rows(raw, "users").await?,
            rows(raw, "accounts").await?,
            rows(raw, "sessions").await?,
        ];
        let mut request = AuthRequest::new(alibi::HttpMethod::Post, "/admin/impersonate-user");
        _ = request
            .headers
            .insert("origin".into(), config().base_url.clone());
        _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        _ = request.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                alibi::utils::cookie_utils::sign_cookie_value(
                    original.token(),
                    config().current_secret()
                )
            ),
        );
        request.body = Some(serde_json::to_vec(&serde_json::json!({"userId":target}))?);
        let response = auth.handle_request(request).await?;
        let observed = hooks.events.lock().await.clone();
        let after = [
            rows(raw, "users").await?,
            rows(raw, "accounts").await?,
            rows(raw, "sessions").await?,
        ];
        println!(
            "admission observation: {}",
            serde_json::json!({"adapter":std::any::type_name::<S>(),"clockMs":clock.timestamp_millis(),"mode":mode,"delta":delta,"target":target,"status":response.status,"body":String::from_utf8_lossy(&response.body),"events":observed,"before":before,"after":after})
        );
        assert_eq!(response.status, status, "mode={mode} delta={delta}");
        assert_eq!(observed, events);
        let target = store
            .get_user_by_id("42")
            .await?
            .ok_or("missing principal")?;
        assert_eq!(target.banned(), !cleared);
        assert_eq!(target.ban_expires().is_none(), cleared);
        assert_eq!(target.ban_reason().is_none(), cleared);
        if !cleared {
            assert_eq!(before[0], after[0]);
        } else {
            for row in before[0].iter().filter(|row| !row.starts_with("[42,")) {
                assert!(after[0].contains(row));
            }
        }
        assert_eq!(before[1], after[1]);
        assert_eq!(after[2].len(), before[2].len() + usize::from(inserted));
        for row in &before[2] {
            assert!(after[2].contains(row));
        }
        assert_eq!(
            store
                .get_session(peer.token())
                .await?
                .ok_or("peer removed")?
                .user_id(),
            "42"
        );
        if status == 200 {
            let body: serde_json::Value = serde_json::from_slice(&response.body)?;
            assert_eq!(body["session"]["userId"], "42");
            assert_eq!(body["session"]["impersonatedBy"], "1");
        }
        if matches!(mode, 2 | 8 | 9 | 10) {
            assert!(
                response.body.is_empty(),
                "ordinary callback exception must remain empty HTTP 500"
            );
        }
    }
    Ok(())
}

// No database uses cookie-only sessions and the real initialized memory store.
// This guards the shared sign-in ban check independently of impersonation.
#[tokio::test]
#[ignore = "requires CLOCK_REALTIME proof clock; see admin closure audit"]
#[expect(
    clippy::panic_in_result_fn,
    reason = "contract assertions fail fast while fixture setup propagates errors"
)]
async fn no_database_strict_expiry() -> TestResult {
    let clock = Utc::now();
    assert_eq!(clock.timestamp_millis(), 1893456000000);
    let auth =
        AuthBuilder::without_database(AuthConfig::new("numeric-admin-identity-secret-at-least-32"))
            .plugin(AdminPlugin::new())
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .build()
            .await?;
    let store = auth.store();
    let actor = store
        .create_user(CreateUser {
            id: Some("1".into()),
            email: Some("actor@no-db.fixture.test".into()),
            name: Some("Actor".into()),
            role: Some("admin".into()),
            ..Default::default()
        })
        .await?;
    let target = store
        .create_user(CreateUser {
            id: Some("42".into()),
            email: Some("target@no-db.fixture.test".into()),
            name: Some("Target".into()),
            ..Default::default()
        })
        .await?;
    let _account = store
        .create_account(alibi::CreateAccount {
            user_id: target.id().into_owned(),
            account_id: target.id().into_owned(),
            provider_id: "credential".into(),
            password: Some(auth.context().hash_password(None, "Password123!").await?),
            additional_fields: Default::default(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await?;
    let original = store
        .create_session(CreateSession {
            user_id: actor.id().into_owned(),
            expires_at: clock + chrono::Duration::days(7),
            additional_fields: Default::default(),
            token: None,
            active_team_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    for path in ["/admin/impersonate-user", "/sign-in/email"] {
        for (delta, status) in [(0, 403), (1, 403), (-1, 200)] {
            drop(
                store
                    .update_user(
                        target.id().as_ref(),
                        UpdateUser {
                            banned: Some(true),
                            ban_reason: Some("boundary".into()),
                            ban_expires: Some(Some(clock + chrono::Duration::milliseconds(delta))),
                            ..Default::default()
                        },
                    )
                    .await?,
            );
            let before = serde_json::json!({"actor":store.get_user_by_id(actor.id().as_ref()).await?,"target":store.get_user_by_id(target.id().as_ref()).await?,"accounts":store.get_user_accounts(target.id().as_ref()).await?,"actorSessions":store.get_user_sessions(actor.id().as_ref()).await?,"targetSessions":store.get_user_sessions(target.id().as_ref()).await?});
            let mut request = AuthRequest::new(alibi::HttpMethod::Post, path);
            _ = request
                .headers
                .insert("origin".into(), auth.config().base_url.clone());
            _ = request
                .headers
                .insert("content-type".into(), "application/json".into());
            _ = request.headers.insert(
                "cookie".into(),
                format!(
                    "better-auth.session_token={}",
                    alibi::utils::cookie_utils::sign_cookie_value(
                        original.token(),
                        auth.config().current_secret()
                    )
                ),
            );
            request.body = Some(serde_json::to_vec(&if path == "/sign-in/email" {
                serde_json::json!({"email":"target@no-db.fixture.test","password":"Password123!"})
            } else {
                serde_json::json!({"userId":target.id()})
            })?);
            let response = auth.handle_request(request).await?;
            let after = serde_json::json!({"actor":store.get_user_by_id(actor.id().as_ref()).await?,"target":store.get_user_by_id(target.id().as_ref()).await?,"accounts":store.get_user_accounts(target.id().as_ref()).await?,"actorSessions":store.get_user_sessions(actor.id().as_ref()).await?,"targetSessions":store.get_user_sessions(target.id().as_ref()).await?});
            println!(
                "no-db observation: {}",
                serde_json::json!({"path":path,"delta":delta,"clockMs":clock.timestamp_millis(),"status":response.status,"body":String::from_utf8_lossy(&response.body),"before":before,"after":after})
            );
            assert_eq!(response.status, status);
            assert_eq!(before["actor"], after["actor"]);
            assert_eq!(before["accounts"], after["accounts"]);
            assert_eq!(before["actorSessions"], after["actorSessions"]);
            if status == 403 {
                assert_eq!(before, after);
            } else {
                let body: serde_json::Value = serde_json::from_slice(&response.body)?;
                assert_eq!(body["user"]["id"], target.id().as_ref());
                assert!(
                    !store
                        .get_user_by_id(target.id().as_ref())
                        .await?
                        .ok_or("missing target")?
                        .banned()
                );
            }
        }
    }
    Ok(())
}

// PostgreSQL is a distinct driver boundary: text operands require parameter
// casts to the declared physical numeric types, without casting indexed columns.
#[cfg(all(feature = "sqlx", feature = "seaorm"))]
mod postgres_numeric_columns {
    use super::*;
    use crate::storage::Db;
    use alibi::{ListUsersParams, UserFilterValue, store::UserStore};

    macro_rules! model_fields {
        (sqlx) => {
            #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
            #[auth(role = "user", table = "app_people")]
            pub struct Model {
                pub id: String,
                #[sqlx(rename = "mailbox")]
                pub email: Option<String>,
                pub name: Option<String>,
                pub email_verified: bool,
                pub image: Option<String>,
                pub created_at: chrono::DateTime<Utc>,
                pub updated_at: chrono::DateTime<Utc>,
                #[sqlx(rename = "score32")]
                pub small: i32,
                #[sqlx(rename = "score64")]
                pub large: i64,
                pub real32: f32,
                pub real64: f64,
            }
        };
        (seaorm) => {
            use alibi::seaorm::sea_orm::{self, entity::prelude::*};
            #[derive(
                Clone, Debug, serde::Serialize, DeriveEntityModel, alibi::seaorm::AuthEntity,
            )]
            #[auth(role = "user")]
            #[sea_orm(table_name = "app_people")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[sea_orm(column_name = "mailbox")]
                pub email: Option<String>,
                pub name: Option<String>,
                pub email_verified: bool,
                pub image: Option<String>,
                pub created_at: chrono::DateTime<Utc>,
                pub updated_at: chrono::DateTime<Utc>,
                #[sea_orm(column_name = "score32")]
                pub small: i32,
                #[sea_orm(column_name = "score64")]
                pub large: i64,
                pub real32: f32,
                pub real64: f64,
            }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        };
    }
    macro_rules! schema {
        ($($backend:ident)::+) => {
            struct Schema;
            impl AuthSchema for Schema {
                type User = Model;
                type Session = $($backend)::+::store::entities::session::Model;
                type Account = $($backend)::+::store::entities::account::Model;
                type Verification = $($backend)::+::store::entities::verification::Model;
            }
        };
    }
    mod sqlx_model {
        use super::*;
        model_fields!(sqlx);
        schema!(alibi::sqlx);
        #[tokio::test]
        #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
        async fn declared_numeric_filters_preserve_rows_types_and_index() -> TestResult {
            let db = Db::postgres().await?;
            let crate::storage::Raw::Postgres(raw) = &db.raw else {
                return Err("numeric filter fixture requires a PostgreSQL pool".into());
            };
            install(raw).await?;
            let connection = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&db.url)
                .await?;
            let store = alibi::sqlx::SqlxStore::<Schema>::new(config(), connection.clone());
            exercise(&store, raw, &connection).await?;
            connection.close().await;
            Ok(())
        }
    }
    mod seaorm_model {
        use super::*;
        model_fields!(seaorm);
        schema!(alibi::seaorm);
        #[tokio::test]
        #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
        async fn declared_numeric_filters_preserve_rows_types_and_index() -> TestResult {
            let db = Db::postgres().await?;
            let crate::storage::Raw::Postgres(raw) = &db.raw else {
                return Err("numeric filter fixture requires a PostgreSQL pool".into());
            };
            install(raw).await?;
            let mut options = alibi::seaorm::sea_orm::ConnectOptions::new(db.url.clone());
            _ = options.max_connections(1).min_connections(1);
            let connection = alibi::seaorm::Database::connect(options).await?;
            let store = alibi::seaorm::SeaOrmStore::<Schema>::new(config(), connection.clone());
            exercise(&store, raw, connection.get_postgres_connection_pool()).await?;
            connection.close().await?;
            Ok(())
        }
    }
    async fn install(raw: &sqlx::PgPool) -> TestResult {
        _ = sqlx::query("CREATE TABLE app_people (id text PRIMARY KEY, mailbox text UNIQUE, name text, email_verified boolean NOT NULL, image text, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, score32 integer NOT NULL DEFAULT 0, score64 bigint NOT NULL DEFAULT 0, real32 real NOT NULL DEFAULT 0, real64 double precision NOT NULL DEFAULT 0)").execute(raw).await?;
        _ = sqlx::query("INSERT INTO app_people SELECT n::text, n::text || '@numeric.fixture.test', n::text, false, NULL, '2020-01-01Z'::timestamptz, '2020-01-01Z'::timestamptz, n, n, n, n FROM generate_series(1,10000) n").execute(raw).await?;
        _ = sqlx::query("CREATE INDEX app_people_score64_idx ON app_people(score64)")
            .execute(raw)
            .await?;
        _ = sqlx::query("CREATE TABLE app_dependents (user_id text PRIMARY KEY REFERENCES app_people(id), payload text NOT NULL CHECK (payload <> ''))").execute(raw).await?;
        _ = sqlx::query("INSERT INTO app_dependents VALUES ('1', 'retained application data')")
            .execute(raw)
            .await?;
        // Application-owned populated-schema migration, with an idempotent retry.
        for _ in 0..2 {
            _ = sqlx::query("ALTER TABLE app_people ADD COLUMN IF NOT EXISTS retained text NOT NULL DEFAULT 'application-default' CHECK (retained <> '')").execute(raw).await?;
        }
        _ = sqlx::query("ANALYZE app_people").execute(raw).await?;
        Ok(())
    }
    async fn snapshot(raw: &sqlx::PgPool) -> TestResult<String> {
        Ok(
            sqlx::query_scalar("SELECT json_build_object('users',(SELECT json_agg(r ORDER BY id) FROM app_people r),'dependents',(SELECT json_agg(r ORDER BY user_id) FROM app_dependents r),'constraints',(SELECT json_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint WHERE conrelid IN ('app_people'::regclass,'app_dependents'::regclass)))::text")
                .fetch_one(raw)
                .await?,
        )
    }
    async fn exercise<S: AuthSchema>(
        store: &dyn UserStore<S>,
        raw: &sqlx::PgPool,
        native: &sqlx::PgPool,
    ) -> TestResult {
        // Native writes preserve the application's omitted upgraded column;
        // database defaults and dependent constraints remain physical contracts.
        let created = store
            .create_user(CreateUser::new().with_email("new@numeric.fixture.test"))
            .await?;
        let retained: String = sqlx::query_scalar("SELECT retained FROM app_people WHERE id=$1")
            .bind(created.id().as_ref())
            .fetch_one(raw)
            .await?;
        assert_eq!(retained, "application-default");
        let updated = store
            .update_user(
                "1",
                UpdateUser {
                    name: Some("Updated application owner".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.name(), Some("Updated application owner"));
        let dependent: (String, String) = sqlx::query_as("SELECT p.retained, d.payload FROM app_people p JOIN app_dependents d ON d.user_id=p.id WHERE p.id='1'").fetch_one(raw).await?;
        assert_eq!(
            dependent,
            (
                "application-default".into(),
                "retained application data".into()
            )
        );
        let before = snapshot(raw).await?;
        // Distinct wire types, numeric aliases, physical fields and pagination.
        for field in ["small", "large", "real32", "real64"] {
            for value in ["9998", "0x270e", "9.998e3"] {
                let (users, total) = store
                    .list_users(ListUsersParams {
                        filter_field: Some(field.into()),
                        filter_value: Some(UserFilterValue::Scalar(value.into())),
                        filter_operator: Some("gte".into()),
                        sort_by: Some(field.into()),
                        limit: Some(1),
                        offset: Some(1),
                        ..Default::default()
                    })
                    .await?;
                assert_eq!(total, 3);
                assert_eq!(
                    users
                        .iter()
                        .map(|u| u.id().into_owned())
                        .collect::<Vec<_>>(),
                    ["9999"]
                );
            }
            for (values, expected) in [(vec!["0x1", "2e0"], vec!["1", "2"])] {
                let (users, total) = store
                    .list_users(ListUsersParams {
                        filter_field: Some(field.into()),
                        filter_value: Some(UserFilterValue::Multiple(
                            values.into_iter().map(str::to_owned).collect(),
                        )),
                        filter_operator: Some("in".into()),
                        sort_by: Some(field.into()),
                        ..Default::default()
                    })
                    .await?;
                assert_eq!(total, expected.len());
                assert_eq!(
                    users
                        .iter()
                        .map(|u| u.id().into_owned())
                        .collect::<Vec<_>>(),
                    expected
                );
            }
            assert!(
                matches!(
                    store
                        .list_users(ListUsersParams {
                            filter_field: Some(field.into()),
                            filter_value: Some(UserFilterValue::Multiple(vec![])),
                            filter_operator: Some("in".into()),
                            ..Default::default()
                        })
                        .await,
                    Err(alibi::AuthError::Database(_))
                ),
                "Source PostgreSQL rejects IN ()"
            );
        }
        for (field, value) in [
            ("small", "1.5"),
            ("large", "1.5"),
            ("large", "Infinity"),
            ("large", "NaN"),
            ("large", ""),
            ("large", "1e21"),
            ("small", "2147483648"),
        ] {
            assert!(
                matches!(
                    store
                        .list_users(ListUsersParams {
                            filter_field: Some(field.into()),
                            filter_value: Some(UserFilterValue::Scalar(value.into())),
                            filter_operator: Some("eq".into()),
                            ..Default::default()
                        })
                        .await,
                    Err(alibi::AuthError::Database(_))
                ),
                "{field}: {value}"
            );
        }
        // Source keeps the entire array as strings when one element is invalid.
        assert!(matches!(
            store
                .list_users(ListUsersParams {
                    filter_field: Some("real64".into()),
                    filter_value: Some(UserFilterValue::Multiple(vec![
                        "0x1".into(),
                        "invalid".into()
                    ])),
                    filter_operator: Some("in".into()),
                    ..Default::default()
                })
                .await,
            Err(alibi::AuthError::Database(_))
        ));
        let array_error = store
            .list_users(ListUsersParams {
                filter_field: Some("large".into()),
                filter_value: Some(UserFilterValue::Multiple(vec!["1e0".into(), "NaN".into()])),
                filter_operator: Some("in".into()),
                ..Default::default()
            })
            .await
            .err()
            .ok_or("invalid integer array succeeded")?;
        assert!(array_error.to_string().contains("\"1e0\""), "{array_error}");
        assert!(matches!(
            store
                .list_users(ListUsersParams {
                    filter_field: Some("unmapped".into()),
                    filter_value: Some(UserFilterValue::Scalar("1".into())),
                    ..Default::default()
                })
                .await,
            Err(alibi::AuthError::BadRequest(_))
        ));
        // Explain the real prepared statement, with the actual bound value,
        // on the same one-connection native pool that executed it.
        let (name, statement): (String, String) = sqlx::query_as("SELECT name, statement FROM pg_prepared_statements WHERE statement LIKE '%score64% >= %::int8%' ORDER BY prepare_time LIMIT 1").fetch_one(native).await?;
        assert!(!statement.contains("CAST(\"app_people\".\"score64\""));
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN EXECUTE \"{}\"('9998')",
            name.replace('"', "\"\"")
        )))
        .fetch_all(native)
        .await?;
        assert!(
            plan.iter()
                .any(|line| line.contains("Index") && line.contains("app_people_score64_idx")),
            "{plan:?}"
        );
        assert!(
            plan.iter()
                .any(|line| line.contains("Index Cond") && line.contains("score64")),
            "{plan:?}"
        );
        assert_eq!(
            snapshot(raw).await?,
            before,
            "all rows and native date/number bytes survive successful and failed reads"
        );
        Ok(())
    }
}
