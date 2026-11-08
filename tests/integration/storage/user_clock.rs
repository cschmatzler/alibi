use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::UserStore;
use alibi::{AuthUser, CreateUser};
use serde_json::{Value, json};

backend_tests!(generated_user_clock_matches_actual_millisecond_readback);
postgres_tests!(generated_user_clock_matches_actual_millisecond_readback);

async fn generated_user_clock_matches_actual_millisecond_readback<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("user-creation-clock-source-secret-at-least-32")
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/user-creation-clock.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backends"], json!(["sqlite", "postgres", "mysql"]));
    let generated = store
        .create_user(
            CreateUser::new()
                .with_name("Clock")
                .with_email("user-clock@example.com"),
        )
        .await?;
    let readback = store
        .get_user_by_id(generated.id().as_ref())
        .await?
        .ok_or("created user missing")?;
    let clock = json!({
        "created_at_millisecond_aligned":generated.created_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "updated_at_millisecond_aligned":generated.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "readback_matches":generated.created_at() == readback.created_at() && generated.updated_at() == readback.updated_at(),
    });
    assert_eq!(clock, fixture["clock"]);
    B::close(connection).await
}
