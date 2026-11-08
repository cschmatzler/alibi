use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::UserStore;
use alibi::{AuthUser, CreateUser, UpdateUser};
use serde_json::{Value, json};

backend_tests!(generated_user_update_clock_matches_actual_millisecond_readback);
postgres_tests!(generated_user_update_clock_matches_actual_millisecond_readback);

async fn generated_user_update_clock_matches_actual_millisecond_readback<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("user-update-clock-source-secret-at-least-32")
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/user-update-clock.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backends"], json!(["sqlite", "postgres", "mysql"]));
    let created = store
        .create_user(
            CreateUser::new()
                .with_name("Clock")
                .with_email("user-clock@example.com"),
        )
        .await?;
    let updated = store
        .update_user(
            created.id().as_ref(),
            UpdateUser {
                name: Some("Updated clock".into()),
                ..Default::default()
            },
        )
        .await?;
    let readback = store
        .get_user_by_id(created.id().as_ref())
        .await?
        .ok_or("updated user missing")?;
    let clock = json!({
        "created_at_preserved":created.created_at() == updated.created_at(),
        "updated_at_millisecond_aligned":updated.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,
        "readback_matches":updated.created_at() == readback.created_at() && updated.updated_at() == readback.updated_at(),
    });
    assert_eq!(clock, fixture["clock"]);
    B::close(connection).await
}
