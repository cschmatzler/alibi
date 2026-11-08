use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::{CacheAdapter, MemoryCacheAdapter, SessionStore};
use alibi::{
    AuthBuilder, AuthConfig, AuthSchema, AuthSession, AuthUser, CreateSession, CreateUser,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

backend_tests!(
    secondary_cache_expiry_clock_matches_actual_phases,
    secondary_cache_fields_clock_matches_actual_phases,
    secondary_mirror_expiry_clock_matches_actual_phases,
    secondary_mirror_fields_clock_matches_actual_phases,
    secondary_cache_explicit_clock_matches_actual_phases,
    secondary_mirror_explicit_clock_matches_actual_phases
);
postgres_tests!(
    secondary_cache_expiry_clock_matches_actual_phases,
    secondary_cache_fields_clock_matches_actual_phases,
    secondary_mirror_expiry_clock_matches_actual_phases,
    secondary_mirror_fields_clock_matches_actual_phases,
    secondary_cache_explicit_clock_matches_actual_phases,
    secondary_mirror_explicit_clock_matches_actual_phases
);

async fn check<B: Backend>(db: Db, persist: bool, action: &str) -> TestResult {
    let secret = "session-secondary-clock-source-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if db.is_postgres() {
        include_str!("../../fixtures/session-secondary-postgres-clock.json")
    } else if action == "explicit" {
        include_str!("../../fixtures/session-secondary-explicit-clock.json")
    } else {
        include_str!("../../fixtures/session-secondary-clock.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(
        fixture["backend"],
        if db.is_postgres() {
            "postgres"
        } else {
            "sqlite"
        }
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        if db.is_postgres() {
            6
        } else if action == "explicit" {
            2
        } else {
            4
        }
    );
    let raw_store = B::store(Arc::new(AuthConfig::new(secret)), &connection);
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(cache.clone());
    config.session.store_in_database = persist;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Clock")
                .with_email(format!("secondary-clock-{persist}@example.com")),
        )
        .await?;
    let case = cases
        .iter()
        .find(|case| case["persist"] == persist && case["action"] == action)
        .unwrap();
    let token = format!("secondary-clock-{persist}-{action}");
    let created_at: DateTime<Utc> = "2020-01-01T00:00:00.123Z".parse()?;
    let updated_at: DateTime<Utc> = "2020-02-01T00:00:00.123Z".parse()?;
    let expires_at = "2031-01-01T00:00:00.123Z".parse()?;
    let renewed_expiry = "2032-01-01T00:00:00.123Z".parse()?;
    let supplied_clock: DateTime<Utc> = "2030-01-01T00:00:00.123Z".parse()?;
    let mut fields = alibi::field_policy::FieldValues::new();
    _ = fields.insert(
        "createdAt".into(),
        alibi::utils::json::JsValue::Date(created_at),
    );
    _ = fields.insert(
        "updatedAt".into(),
        alibi::utils::json::JsValue::Date(updated_at),
    );
    let created = auth
        .store()
        .create_session(CreateSession {
            additional_fields: fields,
            token: Some(token.clone()),
            user_id: owner.id().into_owned(),
            expires_at,
            ip_address: Some("".into()),
            user_agent: Some("".into()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    assert_eq!(created.updated_at(), updated_at, "source creation override");
    let updated = if action == "expiry" {
        auth.store().refresh_session(&token, renewed_expiry).await?
    } else {
        let mut fields = alibi::field_policy::FieldValues::new();
        if action == "explicit" {
            _ = fields.insert(
                "updatedAt".into(),
                alibi::utils::json::JsValue::Date(supplied_clock),
            );
        }
        auth.store().update_session_fields(&token, fields).await?
    }
    .ok_or("updated secondary session missing")?;
    if action == "explicit" {
        assert_eq!(
            updated.updated_at(),
            supplied_clock,
            "supplied update clock"
        );
    }
    let readback = auth
        .store()
        .get_session(&token)
        .await?
        .ok_or("secondary session readback missing")?;
    let cached: alibi::utils::json::JsValue = alibi::utils::json::from_storage_str(
        &cache
            .get(&token)
            .await?
            .ok_or("secondary cache row missing")?,
    )?;
    let cached_session =
        <B::Schema as AuthSchema>::Session::from_secondary_snapshot(cached["session"].clone())?;
    let database_clock = raw_store
        .get_session(&token)
        .await?
        .map(|session| session.updated_at());
    assert_eq!(database_clock.is_some(), persist);
    assert_eq!(updated.id(), created.id());
    assert_eq!(readback.id(), created.id());
    let clock = json!({
        "created_at_preserved": updated.created_at() == created_at,
        "updated_at_preserved": updated.updated_at() == updated_at,
        "updated_at_millisecond_aligned": updated.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "expires_at_preserved": updated.expires_at() == if action == "expiry" { renewed_expiry } else { expires_at },
        "readback_matches": readback.updated_at() == updated.updated_at() && readback.expires_at() == updated.expires_at(),
        "cache_matches": cached_session.updated_at() == updated.updated_at() && cached_session.expires_at() == updated.expires_at(),
        "database_clock_preserved": database_clock.map(|date| date == updated_at),
    });
    assert_eq!(clock, case["clock"], "persist={persist}/{action}");
    B::close(connection).await
}

async fn secondary_cache_expiry_clock_matches_actual_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "expiry").await
}
async fn secondary_cache_fields_clock_matches_actual_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "fields").await
}
async fn secondary_mirror_expiry_clock_matches_actual_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "expiry").await
}
async fn secondary_mirror_fields_clock_matches_actual_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "fields").await
}
async fn secondary_cache_explicit_clock_matches_actual_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "explicit").await
}
async fn secondary_mirror_explicit_clock_matches_actual_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "explicit").await
}
