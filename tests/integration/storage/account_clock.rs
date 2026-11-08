use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::{AccountStore, UserStore};
use alibi::{AuthAccount, AuthUser, CreateAccount, CreateUser, UpdateAccount};
use serde_json::{Value, json};

backend_tests!(
    generated_account_creation_clock_matches_actual_precision,
    generated_account_update_clock_matches_actual_precision
);
postgres_tests!(
    generated_account_creation_clock_matches_actual_precision,
    generated_account_update_clock_matches_actual_precision
);

async fn check<B: Backend>(db: Db, action: &str) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("account-clock-source-secret-at-least-32")
        .await?;
    let fixture: Value = serde_json::from_str(include_str!("../../fixtures/account-clock.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backends"], json!(["sqlite", "postgres", "mysql"]));
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    let case = cases.iter().find(|case| case["action"] == action).unwrap();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Updated clock")
                .with_email("user-clock@example.com"),
        )
        .await?;
    let created = store
        .create_account(CreateAccount {
            additional_fields: alibi::field_policy::FieldValues::default(),
            user_id: owner.id().into_owned(),
            account_id: "generated-account-clock".into(),
            provider_id: "clock-provider".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("opaque-hash".into()),
        })
        .await?;
    let account = match action {
        "create" => created.clone(),
        "update" => {
            store
                .update_account(
                    created.id().as_ref(),
                    UpdateAccount {
                        scope: Some("email".into()),
                        ..Default::default()
                    },
                )
                .await?
        }
        _ => panic!("unknown source account action: {action}"),
    };
    let readback = store
        .get_account("clock-provider", &"generated-account-clock".into())
        .await?
        .ok_or("created account missing")?;
    assert_eq!(account.id(), created.id());
    assert_eq!(readback.id(), created.id());
    let same = account.created_at() == readback.created_at()
        && account.updated_at() == readback.updated_at();
    let clock = match action {
        "create" => {
            json!({"created_at_millisecond_aligned":account.created_at().timestamp_subsec_nanos() % 1_000_000 == 0,
            "updated_at_millisecond_aligned":account.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,"readback_matches":same})
        }
        "update" => {
            assert_eq!(readback.scope(), Some("email"));
            json!({"created_at_preserved":created.created_at() == account.created_at(),
                "updated_at_millisecond_aligned":account.updated_at().timestamp_subsec_nanos() % 1_000_000 == 0,"readback_matches":same})
        }
        _ => unreachable!(),
    };
    assert_eq!(clock, case["clock"], "{action}");
    B::close(connection).await
}

async fn generated_account_creation_clock_matches_actual_precision<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, "create").await
}

async fn generated_account_update_clock_matches_actual_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "update").await
}
