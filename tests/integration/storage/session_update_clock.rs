use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::{SessionStore, UserStore};
use alibi::{AuthSession, AuthUser, CreateSession, CreateUser};
use serde_json::{Value, json};

backend_tests!(
    session_expiry_update_clock_matches_actual_precision,
    session_refresh_clock_matches_actual_precision,
    session_refresh_fields_clock_matches_actual_precision,
    session_fields_update_clock_matches_actual_precision
);
postgres_tests!(
    session_expiry_update_clock_matches_actual_precision,
    session_refresh_clock_matches_actual_precision,
    session_refresh_fields_clock_matches_actual_precision,
    session_fields_update_clock_matches_actual_precision
);

#[derive(Clone, Copy)]
enum Operation {
    Expiry,
    Refresh,
    RefreshFields,
    Fields,
}

async fn check<B: Backend>(db: Db, operation: Operation) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("session-update-clock-source-secret-at-least-32")
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/session-update-clock.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backends"], json!(["sqlite", "postgres", "mysql"]));
    let action = if matches!(operation, Operation::Fields) {
        "fields"
    } else {
        "expiry"
    };
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    let case = cases.iter().find(|case| case["action"] == action).unwrap();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Clock")
                .with_email("session-update-clock@example.com"),
        )
        .await?;
    let expires_at = "2031-01-01T00:00:00.123Z".parse()?;
    let renewed_expiry = "2032-01-01T00:00:00.123Z".parse()?;
    let created = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            token: Some(format!("session-clock-{action}")),
            user_id: owner.id().into_owned(),
            expires_at,
            ip_address: Some("".into()),
            user_agent: Some("".into()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let updated = match operation {
        Operation::Expiry => {
            store
                .update_session_expiry(created.token(), renewed_expiry)
                .await?;
            store.get_session(created.token()).await?
        }
        Operation::Refresh => {
            store
                .refresh_session(created.token(), renewed_expiry)
                .await?
        }
        Operation::RefreshFields => {
            store
                .refresh_session_with_fields(created.token(), renewed_expiry, Default::default())
                .await?
        }
        Operation::Fields => {
            store
                .update_session_fields(created.token(), Default::default())
                .await?
        }
    }
    .ok_or("updated session missing")?;
    let readback = store
        .get_session(created.token())
        .await?
        .ok_or("updated session readback missing")?;
    assert_eq!(updated.id(), created.id());
    assert_eq!(readback.id(), created.id());
    let clock = json!({
        "created_at_preserved": created.created_at() == updated.created_at(),
        "updated_at_millisecond_aligned": updated.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "expires_at_preserved": updated.expires_at() == if action == "expiry" { renewed_expiry } else { expires_at },
        "readback_matches": updated.created_at() == readback.created_at() && updated.updated_at() == readback.updated_at() && updated.expires_at() == readback.expires_at(),
    });
    assert_eq!(clock, case["clock"], "{action}");
    B::close(connection).await
}

async fn session_expiry_update_clock_matches_actual_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, Operation::Expiry).await
}

async fn session_refresh_clock_matches_actual_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, Operation::Refresh).await
}

async fn session_refresh_fields_clock_matches_actual_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, Operation::RefreshFields).await
}

async fn session_fields_update_clock_matches_actual_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, Operation::Fields).await
}
