use super::{Backend, SeaOrm, TestResult};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, VerificationStore};
use alibi::{AuthConfig, AuthResult, AuthSchema, AuthVerification};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct ClaimedSnapshots(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for ClaimedSnapshots {
    async fn after_update_verification(
        &self,
        row: &S::Verification,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        assert!(ctx.tx.is_none());
        self.0
            .lock()
            .unwrap()
            .push(json!({"id":row.id(),"value":row.value(),"expiresAt":row.expires_at()}));
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_verification_claims_match_actual_guarded_snapshots() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_verification_claim_{}", uuid::Uuid::new_v4().simple());
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
        "../../fixtures/mysql-verification-claims.json"
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
        if action != "missing" {
            _ = connection.execute_unprepared("INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES ('mysql-claimed-proof', 'mysql-claim', 'original', '2029-01-01 00:00:00.123', '2026-01-01 00:00:00.123', '2026-01-01 00:00:00.123')").await?;
        }
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::new(SeaOrm::hook(
            SeaOrm::store(
                Arc::new(AuthConfig::new(
                    "mysql-verification-claims-secret-at-least-32",
                )),
                &connection,
            ),
            ClaimedSnapshots(snapshots.clone()),
        ));
        if action == "sql-failure" {
            _ = connection.execute_unprepared("ALTER TABLE verification ADD CONSTRAINT reject_claim CHECK (value = 'original')").await?;
        }
        let mut claims = tokio::task::JoinSet::new();
        for _ in 0..case["calls"].as_u64().unwrap() {
            let store = store.clone();
            let expected = case["expected"].as_str().unwrap().to_owned();
            let value = case["value"].as_str().unwrap().to_owned();
            _ = claims.spawn(async move {
                store
                    .compare_and_swap_verification(
                        "mysql-claimed-proof",
                        &expected,
                        &value,
                        expires_at,
                    )
                    .await
            });
        }
        let mut winners = 0;
        let mut failed = false;
        while let Some(result) = claims.join_next().await {
            match result? {
                Ok(won) => winners += usize::from(won),
                Err(error) => {
                    assert!(
                        error.to_string().contains("reject_claim"),
                        "{action}: {error}"
                    );
                    failed = true;
                }
            }
        }
        if action == "sql-failure" {
            _ = connection
                .execute_unprepared("ALTER TABLE verification DROP CHECK reject_claim")
                .await?;
        }
        assert_eq!(json!(failed), case["failed"], "{action}");
        assert_eq!(json!(winners), case["winners"], "{action}");
        assert_eq!(
            json!(*snapshots.lock().unwrap()),
            case["snapshots"],
            "{action}"
        );
        let mut stored = Vec::new();
        for row in connection
            .query_all_raw(Statement::from_string(
                DbBackend::MySql,
                "SELECT id, value, expiresAt FROM verification".to_owned(),
            ))
            .await?
        {
            stored.push(json!({"id":row.try_get::<String>("", "id")?,"value":row.try_get::<String>("", "value")?,"expiresAt":row.try_get::<chrono::DateTime<chrono::Utc>>("", "expiresAt")?}));
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
