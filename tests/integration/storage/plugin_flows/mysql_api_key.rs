use super::*;
use alibi::plugins::api_key::{ApiKeyVerificationInput, CreateKeyRequest};
use alibi::plugins::{ApiKeyConfig, ApiKeyPlugin};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

async fn verify_burst<S: AuthSchema>(
    auth: &Arc<Alibi<S>>,
    key: &str,
    calls: u64,
) -> TestResult<Vec<Value>> {
    let mut pending = tokio::task::JoinSet::new();
    for _ in 0..calls {
        let auth = auth.clone();
        let key = key.to_owned();
        _ = pending.spawn(async move {
            let endpoint = ApiKeyPlugin::verify_endpoint(&ApiKeyVerificationInput {
                key,
                config_id: None,
                permissions: None,
            })
            .unwrap();
            let response = Box::pin(auth.dispatch_endpoint(endpoint, Default::default()))
                .await
                .unwrap()
                .into_response()
                .unwrap();
            assert_eq!(response.status, 200);
            body(&response)
        });
    }
    let mut responses = Vec::new();
    while let Some(result) = pending.join_next().await {
        responses.push(result?);
    }
    Ok(responses)
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_api_key_usage_matches_actual_server_endpoint() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_key_usage_{}", uuid::Uuid::new_v4().simple());
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
    let config =
        AuthConfig::new("mysql-api-key-secret-at-least-32-characters").base_url("http://localhost");
    let auth = Arc::new(
        AuthBuilder::new(config.clone())
            .store(<super::super::SeaOrm as Backend>::store(
                Arc::new(config),
                &connection,
            ))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(ApiKeyPlugin::with_config(ApiKeyConfig::default()))
            .build()
            .await?,
    );
    let owner = Box::pin(auth.dispatch_endpoint(
        EmailPasswordPlugin::sign_up_email_endpoint(&serde_json::from_value(
            json!({"name":"Owner","email":"mysql-api-key@example.com","password":"Password123!"}),
        )?)?,
        Default::default(),
    ))
    .await?
    .decode()?;
    let owner_id = owner.user["id"].as_str().unwrap().to_owned();
    let created = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
            name: Some("Quota key".into()),
            user_id: Some(owner_id.clone()),
            remaining: Some(2.0),
            rate_limit_enabled: Some(false),
            ..Default::default()
        })?,
        Default::default(),
    ))
    .await?
    .decode()?;
    assert_eq!(created.api_key.remaining, Some(2.0));
    let key = created.key;
    let id = created.api_key.id;
    let fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/mysql-api-key-usage.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let response = Box::pin(auth.dispatch_endpoint(
            ApiKeyPlugin::verify_endpoint(&ApiKeyVerificationInput {
                key: key.clone(),
                config_id: None,
                permissions: None,
            })?,
            Default::default(),
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let value = body(&response);
        let projected_key = if value["key"].is_null() {
            Value::Null
        } else {
            assert_eq!(value["key"]["referenceId"], owner_id);
            json!({"name":value["key"]["name"],"configId":value["key"]["configId"],"enabled":value["key"]["enabled"],"remaining":value["key"]["remaining"],"requestCount":value["key"]["requestCount"],"rateLimitEnabled":value["key"]["rateLimitEnabled"],"metadata":value["key"]["metadata"]})
        };
        assert_eq!(
            json!({"valid":value["valid"],"error":value["error"],"key":projected_key}),
            case["output"],
            "claim {}",
            case["call"]
        );
        let stored = connection.query_one_raw(Statement::from_sql_and_values(DbBackend::MySql, "SELECT remaining, requestCount, CAST(enabled AS SIGNED) AS enabled, CAST(rateLimitEnabled AS SIGNED) AS rateLimitEnabled FROM apikey WHERE id = ?", [id.clone().into()])).await?;
        let stored = if let Some(row) = stored {
            json!({"remaining":row.try_get::<Option<i32>>("", "remaining")?,"requestCount":row.try_get::<Option<i32>>("", "requestCount")?,"enabled":row.try_get::<i64>("", "enabled")?,"rateLimitEnabled":row.try_get::<i64>("", "rateLimitEnabled")?})
        } else {
            Value::Null
        };
        assert_eq!(stored, case["stored"]);
    }
    let limited = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
            name: Some("Refill key".into()),
            user_id: Some(owner_id.clone()),
            remaining: Some(3.0),
            refill_amount: Some(3.0),
            refill_interval: Some(3_600_000.0),
            rate_limit_enabled: Some(false),
            ..Default::default()
        })?,
        Default::default(),
    ))
    .await?
    .decode()?;
    let limited_id = limited.api_key.id;
    let replies = verify_burst(
        &auth,
        &limited.key,
        fixture["concurrent"]["calls"].as_u64().unwrap(),
    )
    .await?;
    let allowed = replies
        .iter()
        .filter(|reply| reply["valid"] == true)
        .count();
    let exhausted = replies
        .iter()
        .filter(|reply| reply["valid"] == false && reply["error"]["code"] == "USAGE_EXCEEDED")
        .count();
    let remaining = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT remaining FROM apikey WHERE id = ?",
            [limited_id.into()],
        ))
        .await?
        .unwrap()
        .try_get::<i32>("", "remaining")?;
    assert_eq!(
        json!({"calls":replies.len(),"allowed":allowed,"exhausted":exhausted,"remaining":remaining}),
        fixture["concurrent"]
    );
    let due = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
            name: Some("Due refill key".into()),
            user_id: Some(owner_id.clone()),
            remaining: Some(0.0),
            refill_amount: Some(3.0),
            refill_interval: Some(3_600_000.0),
            rate_limit_enabled: Some(false),
            ..Default::default()
        })?,
        Default::default(),
    ))
    .await?
    .decode()?;
    let due_id = due.api_key.id;
    _ = connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "UPDATE apikey SET lastRefillAt = '2000-01-01 00:00:00.123' WHERE id = ?",
            [due_id.clone().into()],
        ))
        .await?;
    let replies = verify_burst(
        &auth,
        &due.key,
        fixture["refill_concurrent"]["calls"].as_u64().unwrap(),
    )
    .await?;
    let allowed = replies
        .iter()
        .filter(|reply| reply["valid"] == true)
        .count();
    let exhausted = replies
        .iter()
        .filter(|reply| reply["valid"] == false && reply["error"]["code"] == "USAGE_EXCEEDED")
        .count();
    let refilled = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT remaining, lastRefillAt FROM apikey WHERE id = ?",
            [due_id.into()],
        ))
        .await?
        .unwrap();
    let old: chrono::DateTime<chrono::Utc> = "2000-01-01T00:00:00.123Z".parse()?;
    assert_eq!(
        json!({"calls":replies.len(),"allowed":allowed,"exhausted":exhausted,"remaining":refilled.try_get::<i32>("", "remaining")?,"refilled":refilled.try_get::<chrono::DateTime<chrono::Utc>>("", "lastRefillAt")? > old}),
        fixture["refill_concurrent"]
    );
    let rated = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
            name: Some("Rate key".into()),
            user_id: Some(owner_id.clone()),
            rate_limit_enabled: Some(true),
            rate_limit_max: Some(3.0),
            rate_limit_time_window: Some(3_600_000.0),
            ..Default::default()
        })?,
        Default::default(),
    ))
    .await?
    .decode()?;
    let rated_id = rated.api_key.id;
    let replies = verify_burst(
        &auth,
        &rated.key,
        fixture["rate_concurrent"]["calls"].as_u64().unwrap(),
    )
    .await?;
    let allowed = replies
        .iter()
        .filter(|reply| reply["valid"] == true)
        .count();
    let code = fixture["rate_concurrent"]["code"].as_str().unwrap();
    let denied = replies
        .iter()
        .filter(|reply| reply["valid"] == false && reply["error"]["code"] == code)
        .count();
    let count = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT requestCount FROM apikey WHERE id = ?",
            [rated_id.into()],
        ))
        .await?
        .unwrap()
        .try_get::<i32>("", "requestCount")?;
    assert_eq!(
        json!({"calls":replies.len(),"allowed":allowed,"denied":denied,"code":code,"requestCount":count}),
        fixture["rate_concurrent"]
    );
    let reset = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
            name: Some("Reset key".into()),
            user_id: Some(owner_id),
            rate_limit_enabled: Some(true),
            rate_limit_max: Some(3.0),
            rate_limit_time_window: Some(3_600_000.0),
            ..Default::default()
        })?,
        Default::default(),
    ))
    .await?
    .decode()?;
    let reset_id = reset.api_key.id;
    _ = connection.execute_raw(Statement::from_sql_and_values(DbBackend::MySql, "UPDATE apikey SET requestCount = 99, lastRequest = '2000-01-01 00:00:00.123' WHERE id = ?", [reset_id.clone().into()])).await?;
    let replies = verify_burst(
        &auth,
        &reset.key,
        fixture["reset_concurrent"]["calls"].as_u64().unwrap(),
    )
    .await?;
    let allowed = replies
        .iter()
        .filter(|reply| reply["valid"] == true)
        .count();
    let code = fixture["reset_concurrent"]["code"].as_str().unwrap();
    let denied = replies
        .iter()
        .filter(|reply| reply["valid"] == false && reply["error"]["code"] == code)
        .count();
    let reset = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT requestCount, lastRequest FROM apikey WHERE id = ?",
            [reset_id.into()],
        ))
        .await?
        .unwrap();
    assert_eq!(
        json!({"calls":replies.len(),"allowed":allowed,"denied":denied,"code":code,"requestCount":reset.try_get::<i32>("", "requestCount")?,"reset":reset.try_get::<chrono::DateTime<chrono::Utc>>("", "lastRequest")? > old}),
        fixture["reset_concurrent"]
    );
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
