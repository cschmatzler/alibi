#![allow(
    unreachable_pub,
    reason = "Application model fixtures expose derived associated types"
)]

use super::{Backend, Db, SeaOrm, Sqlx, TestResult};
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthRequest, AuthSchema, HttpMethod};
use serde_json::{Value, json};

#[allow(
    dead_code,
    reason = "Reuse only the generated source-core model definitions"
)]
#[path = "../../fixtures/cli/seaorm_core.rs"]
mod seaorm_core;
#[allow(
    dead_code,
    reason = "Reuse only the generated source-core model definitions"
)]
#[path = "../../fixtures/cli/sqlx_core.rs"]
mod sqlx_core;

struct SqlxSchema;
impl AuthSchema for SqlxSchema {
    type User = <super::postgres_user_jsonb_values::SqlxSchema as AuthSchema>::User;
    type Session = <sqlx_core::AppAuthSchema as AuthSchema>::Session;
    type Account = <sqlx_core::AppAuthSchema as AuthSchema>::Account;
    type Verification = <sqlx_core::AppAuthSchema as AuthSchema>::Verification;
}

struct SeaOrmSchema;
impl AuthSchema for SeaOrmSchema {
    type User = <super::postgres_user_jsonb_values::SeaOrmSchema as AuthSchema>::User;
    type Session = <seaorm_core::AppAuthSchema as AuthSchema>::Session;
    type Account = <seaorm_core::AppAuthSchema as AuthSchema>::Account;
    type Verification = <seaorm_core::AppAuthSchema as AuthSchema>::Verification;
}

async fn setup(db: &Db) -> TestResult<AuthConfig> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-user-jsonb-signup.json"
    ))?;
    for sql in fixture["schema_sql"]
        .as_str()
        .unwrap()
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = db.execute(sql, &[]).await?;
    }
    let mut config = AuthConfig::new("postgres-user-jsonb-values-secret-at-least-32")
        .base_url("http://localhost");
    _ = config.user.additional_fields.insert(
        "metadata".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"json"})),
    );
    Ok(config)
}

async fn check<S: AuthSchema>(db: &Db, auth: &Alibi<S>) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-user-jsonb-signup.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let email = format!("{name}@jsonb-values.example.com");
        let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-up/email");
        request.headers.extend([
            ("origin".into(), "http://localhost".into()),
            ("content-type".into(), "application/json".into()),
        ]);
        request.body = Some(serde_json::to_vec(
            &json!({"name":"JSONB values","email":email,"password":"Password123!","metadata":case["input"]}),
        )?);
        let response = Box::pin(auth.handle_request(request)).await?;
        let body: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(json!(response.status), case["status"], "{name}: {body}");
        let output = if response.status == 200 {
            json!({"metadata":body["user"].get("metadata").ok_or("public metadata missing")?,"has_token":body["token"].is_string()})
        } else {
            body
        };
        assert_eq!(output, case["output"], "{name}");
        let readback = auth
            .store()
            .get_user_by_email(&email.as_str().into())
            .await?;
        let readback = readback.map(|row| -> TestResult<Value> { Ok(json!({"metadata":serde_json::to_value(auth.context().trusted_user_view(&row)?)?["metadata"]})) }).transpose()?.unwrap_or(Value::Null);
        assert_eq!(readback, case["readback"], "{name}");
        let stored: Value = serde_json::from_str(&db.text("SELECT json_build_object('row_count', count(*), 'stored', (jsonb_agg(jsonb_build_object('metadata', metadata, 'sql_null', metadata IS NULL))->0))::text FROM \"applicationUser\" WHERE email = $1", &[&email]).await?.unwrap())?;
        assert_eq!(stored["row_count"], case["row_count"], "{name}");
        assert_eq!(stored["stored"], case["stored"], "{name}");
        let counts: Value = serde_json::from_str(&db.text("SELECT json_build_object('users', (SELECT count(*) FROM \"applicationUser\"), 'accounts', (SELECT count(*) FROM account), 'sessions', (SELECT count(*) FROM session))::text", &[]).await?.unwrap())?;
        assert_eq!(counts, case["counts"], "{name}");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn sqlx_user_jsonb_signup_matches_actual_http_and_atomic_rows() -> TestResult {
    let db = Db::postgres().await?;
    let config = setup(&db).await?;
    let connection = Sqlx::connect(&db.url, None).await?;
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::sqlx::SqlxStore::<SqlxSchema>::new(
            config,
            connection.clone(),
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    check(&db, &auth).await?;
    drop(auth);
    Sqlx::close(connection).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn seaorm_user_jsonb_signup_matches_actual_http_and_atomic_rows() -> TestResult {
    let db = Db::postgres().await?;
    let config = setup(&db).await?;
    let connection = SeaOrm::connect(&db.url, None).await?;
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::seaorm::SeaOrmStore::<SeaOrmSchema>::new(
            config,
            connection.clone(),
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    check(&db, &auth).await?;
    drop(auth);
    SeaOrm::close(connection).await
}
