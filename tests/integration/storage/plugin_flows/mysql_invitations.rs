use super::mysql_workflow::exchange;
use super::*;
use alibi::InvitationStatus;
use alibi::plugins::organization::OrganizationPlugin;
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use std::collections::BTreeMap;

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_invitation_acceptance_matches_actual_rollback_and_status_claims() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_invitation_{}", uuid::Uuid::new_v4().simple());
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
    let config = AuthConfig::new("mysql-invitation-secret-at-least-32-characters")
        .base_url("http://localhost");
    let auth = AuthBuilder::new(config.clone())
        .store(<super::super::SeaOrm as Backend>::store(
            Arc::new(config),
            &connection,
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/mysql-invitation-acceptance.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let mut owner_jar = BTreeMap::new();
    let mut guest_jar = BTreeMap::new();
    for (jar, email) in [
        (&mut owner_jar, "mysql-owner@example.com"),
        (&mut guest_jar, "mysql-guest@example.com"),
    ] {
        let response = exchange(
            &auth,
            jar,
            "/sign-up/email",
            Some(json!({"name":"Owner","email":email,"password":"Password123!"})),
        )
        .await;
        assert_eq!(response.status, 200);
    }
    let empty = exchange(
        &auth,
        &mut owner_jar,
        "/organization/create",
        Some(json!({"name":"Empty metadata","slug":"mysql-empty"})),
    )
    .await;
    assert_eq!(
        empty.status,
        200,
        "{}",
        String::from_utf8_lossy(&empty.body)
    );
    let empty_id = body(&empty)["id"].as_str().unwrap().to_owned();
    let empty_row = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT metadata FROM organization WHERE id = ?",
            [empty_id.into()],
        ))
        .await?
        .unwrap();
    assert_eq!(
        json!(empty_row.try_get::<Option<String>>("", "metadata")?),
        fixture["metadata"]["omitted"]
    );
    let response = exchange(
        &auth,
        &mut owner_jar,
        "/organization/create",
        Some(json!({"name":"MySQL organization","slug":"mysql-invitations","metadata":{"clock":"2025-02-03T04:05:06Z","project":"invitations","revisions":[1,2]}})),
    )
    .await;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let org_id = body(&response)["id"].as_str().unwrap().to_owned();
    assert_eq!(body(&response)["metadata"], fixture["metadata"]["created"]);
    let updated = exchange(&auth, &mut owner_jar, "/organization/update", Some(json!({"organizationId":org_id,"data":{"metadata":{"clock":"2025-02-03T04:05:06Z","project":"updated","revisions":[3]}}}))).await;
    assert_eq!(
        updated.status,
        200,
        "{}",
        String::from_utf8_lossy(&updated.body)
    );
    assert_eq!(body(&updated)["metadata"], fixture["metadata"]["updated"]);
    let metadata = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT metadata FROM organization WHERE id = ?",
            [org_id.clone().into()],
        ))
        .await?
        .unwrap();
    assert_eq!(
        json!(metadata.try_get::<String>("", "metadata")?),
        fixture["metadata"]["stored"]
    );
    let response = exchange(
        &auth,
        &mut owner_jar,
        "/organization/invite-member",
        Some(json!({"email":"mysql-guest@example.com","role":"member","organizationId":org_id})),
    )
    .await;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let invitation_id = body(&response)["id"].as_str().unwrap().to_owned();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let action = case["action"].as_str().unwrap();
        if action == "fail-membership" {
            _ = connection.execute_unprepared("ALTER TABLE member ADD CONSTRAINT reject_guest_member CHECK (role <> 'member')").await?;
        }
        let response = exchange(
            &auth,
            &mut guest_jar,
            "/organization/accept-invitation",
            Some(json!({"invitationId":invitation_id})),
        )
        .await;
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{action}: {}",
            String::from_utf8_lossy(&response.body)
        );
        if action == "fail-membership" {
            let cookie = guest_jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            let failed = Box::pin(auth.dispatch_endpoint(
                OrganizationPlugin::accept_invitation_endpoint(&serde_json::from_value(
                    json!({"invitationId":invitation_id}),
                )?)?,
                alibi::endpoint::EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into()),
                    ..Default::default()
                },
            ))
            .await;
            let error = failed.expect_err("membership CHECK must reject the logical endpoint too");
            assert!(
                error.error.to_string().contains("reject_guest_member"),
                "{error:?}"
            );
            assert_eq!(case["sql_failure"], true);
            _ = connection
                .execute_unprepared("ALTER TABLE member DROP CHECK reject_guest_member")
                .await?;
        } else {
            assert_eq!(case["sql_failure"], false);
        }
        let value = if response.body.is_empty() {
            Value::Null
        } else {
            body(&response)
        };
        let output = if action == "retry" {
            assert_eq!(value["invitation"]["id"], invitation_id);
            assert_eq!(value["invitation"]["organizationId"], org_id);
            assert_eq!(value["member"]["organizationId"], org_id);
            json!({"invitation":{"status":value["invitation"]["status"],"email":value["invitation"]["email"],"role":value["invitation"]["role"]},"member":{"role":value["member"]["role"]}})
        } else {
            value
        };
        assert_eq!(output, case["output"], "{action}");
        let invitation = connection
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::MySql,
                "SELECT status FROM invitation WHERE id = ?",
                [invitation_id.clone().into()],
            ))
            .await?
            .unwrap();
        assert_eq!(
            json!(invitation.try_get::<String>("", "status")?),
            case["invitation_status"],
            "{action}"
        );
        let members = connection
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::MySql,
                "SELECT role FROM member WHERE organizationId = ? ORDER BY role",
                [org_id.clone().into()],
            ))
            .await?;
        let roles = members
            .iter()
            .map(|row| row.try_get::<String>("", "role"))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(json!(roles), case["roles"], "{action}");
        let sessions = connection.query_all_raw(Statement::from_string(DbBackend::MySql, "SELECT activeOrganizationId FROM session WHERE userId = (SELECT id FROM user WHERE email = 'mysql-guest@example.com')".to_owned())).await?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            json!(
                sessions[0]
                    .try_get::<Option<String>>("", "activeOrganizationId")?
                    .as_deref()
                    == Some(org_id.as_str())
            ),
            case["active_organization"],
            "{action}"
        );
    }
    let mut claims = tokio::task::JoinSet::new();
    for _ in 0..fixture["concurrent"]["calls"].as_u64().unwrap() {
        let store = auth.store().clone();
        let id = invitation_id.clone();
        _ = claims.spawn(async move {
            store
                .update_invitation_status_if_status(
                    &id,
                    InvitationStatus::Accepted,
                    InvitationStatus::Canceled,
                )
                .await
        });
    }
    let mut winners = 0;
    while let Some(result) = claims.join_next().await {
        if let Some(row) = result?? {
            assert_eq!(row.status, InvitationStatus::Canceled);
            winners += 1;
        }
    }
    assert_eq!(json!(winners), fixture["concurrent"]["winners"]);
    let stored = connection
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::MySql,
            "SELECT status FROM invitation WHERE id = ?",
            [invitation_id.into()],
        ))
        .await?
        .unwrap();
    assert_eq!(
        json!(stored.try_get::<String>("", "status")?),
        fixture["concurrent"]["status"]
    );
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
