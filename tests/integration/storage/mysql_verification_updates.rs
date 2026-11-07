use super::{Backend, SeaOrm, TestResult};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use alibi::store::{
    DatabaseHookContext, DatabaseHooks, HookBackend, HookControl, VerificationStore,
};
use alibi::verification::VerificationSnapshot;
use alibi::{AuthConfig, AuthResult, AuthSchema, CreateVerification, UpdateVerification};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct UpdateHook {
    mode: String,
    events: Arc<Mutex<Vec<Value>>>,
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for UpdateHook {
    async fn before_update_verification(
        &self,
        identifier: &str,
        update: &mut UpdateVerification,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        assert!(ctx.tx.is_none());
        assert_eq!(identifier, "mysql-update-proof");
        self.events
            .lock()
            .unwrap()
            .push(json!({"hook":"before","value":update.value}));
        if self.mode == "veto" {
            return Ok(HookControl::Cancel);
        }
        if self.mode == "mutate" {
            update.value = Some("hook-value".into());
        }
        Ok(HookControl::Continue)
    }

    async fn after_update_verification_record(
        &self,
        snapshot: Option<&VerificationSnapshot>,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(ctx.tx.is_none());
        self.events.lock().unwrap().push(
            json!({"hook":"after","value":snapshot.map(VerificationSnapshot::value).transpose()?}),
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_verification_updates_match_actual_hooks_and_nullable_readback() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!(
        "alibi_verification_update_{}",
        uuid::Uuid::new_v4().simple()
    );
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in include_str!("../../fixtures/mysql-source-schema.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/mysql-verification-updates.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let expires_at: chrono::DateTime<chrono::Utc> = "2030-01-02T03:04:05.678Z".parse()?;
    for case in cases {
        let action = case["action"].as_str().unwrap();
        _ = connection
            .execute_unprepared("DELETE FROM verification")
            .await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = SeaOrm::hook(
            SeaOrm::store(
                Arc::new(AuthConfig::new(
                    "mysql-verification-update-secret-at-least-32",
                )),
                &connection,
            ),
            UpdateHook {
                mode: action.into(),
                events: events.clone(),
            },
        );
        if action != "missing" {
            _ = store
                .create_verification(CreateVerification {
                    identifier: "mysql-update-proof".into(),
                    value: "original".into(),
                    expires_at,
                })
                .await?;
            if action == "siblings" {
                _ = store
                    .create_verification(CreateVerification {
                        identifier: "mysql-update-proof".into(),
                        value: "sibling".into(),
                        expires_at,
                    })
                    .await?;
            }
        }
        if action == "sql-failure" {
            _ = connection.execute_unprepared("ALTER TABLE verification ADD CONSTRAINT reject_changed_value CHECK (value = 'original')").await?;
        }
        let outcome = store
            .update_verification_by_identifier(
                "mysql-update-proof",
                UpdateVerification {
                    value: Some("changed".into()),
                    expires_at: Some(expires_at),
                },
            )
            .await;
        assert_eq!(
            outcome.is_err(),
            case["failed"].as_bool().unwrap(),
            "{action}: {outcome:?}"
        );
        let result = match outcome {
            Ok(Some(row)) => {
                json!({"identifier":row.identifier()?,"value":row.value()?,"expiresAt":row.expires_at()?})
            }
            Ok(None) => Value::Null,
            Err(error) => {
                assert!(
                    error.to_string().contains("reject_changed_value"),
                    "{error}"
                );
                Value::Null
            }
        };
        if action == "sql-failure" {
            _ = connection
                .execute_unprepared("ALTER TABLE verification DROP CHECK reject_changed_value")
                .await?;
        }
        assert_eq!(result, case["result"], "{action}");
        assert_eq!(json!(*events.lock().unwrap()), case["events"], "{action}");
        let mut stored = Vec::new();
        for row in connection
            .query_all_raw(Statement::from_string(
                DbBackend::MySql,
                "SELECT value, expiresAt FROM verification ORDER BY value".to_owned(),
            ))
            .await?
        {
            stored.push(json!({"value":row.try_get::<String>("", "value")?,"expiresAt":row.try_get::<chrono::DateTime<chrono::Utc>>("", "expiresAt")?}));
        }
        assert_eq!(json!(stored), case["stored"], "{action}");
    }
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
