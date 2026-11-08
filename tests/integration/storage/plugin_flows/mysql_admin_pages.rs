use super::mysql_workflow::exchange;
use super::*;
use alibi::plugins::AdminPlugin;
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use std::collections::BTreeMap;

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_admin_pages_match_actual_numeric_queries_and_sql_errors() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_admin_page_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in include_str!("../../../fixtures/mysql-source-schema.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    let config = AuthConfig::new("mysql-admin-pages-secret-at-least-32-characters")
        .base_url("http://localhost");
    let auth = AuthBuilder::new(config.clone())
        .store(<super::super::SeaOrm as Backend>::store(
            Arc::new(config),
            &connection,
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let mut jar = BTreeMap::new();
    let owner = exchange(
        &auth,
        &mut jar,
        "/sign-up/email",
        Some(json!({"name":"Owner","email":"owner@example.com","password":"Password123!"})),
    )
    .await;
    assert_eq!(owner.status, 200);
    for email in ["a@example.com", "b@example.com"] {
        let response = exchange(
            &auth,
            &mut BTreeMap::new(),
            "/sign-up/email",
            Some(json!({"name":&email[..1],"email":email,"password":"Password123!"})),
        )
        .await;
        assert_eq!(response.status, 200);
    }
    _ = connection
        .execute_unprepared("UPDATE user SET role = 'admin' WHERE email = 'owner@example.com'")
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/mysql-admin-pages.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    let cookie = jar
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let mut req = request("/admin/list-users", None, &cookie);
        _ = req
            .headers
            .insert("origin".into(), "http://localhost".into());
        let mut query: Vec<(String, String)> = case["query"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
            .collect();
        query.extend([
            ("sortBy".into(), "email".into()),
            ("sortDirection".into(), "asc".into()),
        ]);
        req.set_query_pairs(query);
        let response = Box::pin(auth.handle_request(req)).await?;
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{action}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let mut output = body(&response);
        output["users"] = Value::Array(
            output["users"]
                .as_array()
                .unwrap()
                .iter()
                .map(|user| user["email"].clone())
                .collect(),
        );
        assert_eq!(output, case["output"], "{action}");
    }
    let remaining = connection
        .query_one_raw(Statement::from_string(
            DbBackend::MySql,
            "SELECT COUNT(*) AS total FROM user".to_owned(),
        ))
        .await?
        .unwrap();
    assert_eq!(remaining.try_get::<i64>("", "total")?, 3);
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
