use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::{SessionStore, UserStore};
use alibi::{AuthSession, AuthUser, CreateSession, CreateUser};
use serde_json::{Value, json};

backend_tests!(generated_session_clock_matches_actual_millisecond_readback);
postgres_tests!(generated_session_clock_matches_actual_millisecond_readback);

async fn generated_session_clock_matches_actual_millisecond_readback<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("session-creation-clock-source-secret-at-least-32")
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/session-creation-clock.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backends"], json!(["sqlite", "postgres", "mysql"]));
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Updated clock")
                .with_email("user-clock@example.com"),
        )
        .await?;
    let expiry = "2031-01-01T00:00:00.123Z".parse()?;
    let generated = store
        .create_session(CreateSession {
            additional_fields: alibi::field_policy::FieldValues::default(),
            token: Some("generated-session-clock".into()),
            user_id: owner.id().into_owned(),
            expires_at: expiry,
            ip_address: Some("".into()),
            user_agent: Some("".into()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let readback = store
        .get_session(generated.token())
        .await?
        .ok_or("created session missing")?;
    let clock = json!({
        "created_at_millisecond_aligned":generated.created_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "updated_at_millisecond_aligned":generated.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "expires_at_preserved":generated.expires_at() == expiry,
        "readback_matches":generated.created_at() == readback.created_at() && generated.updated_at() == readback.updated_at() && generated.expires_at() == readback.expires_at(),
    });
    assert_eq!(clock, fixture["clock"]);
    B::close(connection).await
}
