//! User replacement updates canonical state and its managed authentication profile atomically.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(scim_user_replace_preserves_identity_and_replaces_managed_profile);
postgres_tests!(scim_user_replace_preserves_identity_and_replaces_managed_profile);
async fn replace<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    value: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::replace_user_endpoint(id)?.with_body(value)?,
        EndpointOptions {
            headers: token.map(|token| {
                [("authorization".into(), format!("Bearer {token}"))]
                    .into_iter()
                    .collect()
            }),
            ..Default::default()
        },
    ))
    .await;
    match result {
        Ok(output) => output.into_response(),
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()
        }
    }
}
async fn scim_user_replace_preserves_identity_and_replaces_managed_profile<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let input = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"new@example.com","displayName":"New Name","active":false});
    assert_eq!(replace(&auth, "missing", &input, None).await?.status, 401);
    let initial=super::scim_user_create::create(&auth,&json!({"schemas":input["schemas"],"userName":"old@example.com","externalId":"old-external","name":{"givenName":"Old","familyName":"Name"},"roles":[{"value":"admin"}]}),Some("group-reader")).await?;
    assert_eq!(initial.status, 201);
    let initial = body(&initial);
    let id = initial["id"].as_str().unwrap();
    assert_eq!(
        replace(&auth, id, &input, Some("users-reader"))
            .await?
            .status,
        403
    );
    assert_eq!(
        replace(&auth, id, &input, Some("other-reader"))
            .await?
            .status,
        404
    );
    let original_sources: Value = serde_json::from_str(&db.table("scimUser").await?)?;
    let uid = original_sources[0]["userId"].as_str().unwrap();
    _ = auth
        .store()
        .update_user(
            uid,
            alibi::UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    _ = auth
        .store()
        .create_session(alibi::CreateSession {
            additional_fields: Default::default(),
            token: None,
            user_id: uid.into(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let sessions: Value = serde_json::from_str(&db.table("session").await?)?;
    assert_eq!(sessions.as_array().unwrap().len(), 1);
    let response = replace(&auth, id, &input, Some("group-reader")).await?;
    assert_eq!(response.status, 200);
    let value = body(&response);
    assert_eq!(value["id"], initial["id"]);
    assert_eq!(value["userName"], "new@example.com");
    assert_eq!(value["displayName"], "New Name");
    assert_eq!(value["name"], json!({"formatted":"New Name"}));
    assert!(value.get("externalId").is_none());
    assert!(value.get("roles").is_none());
    assert_eq!(value["active"], false);
    assert_eq!(value["meta"]["created"], initial["meta"]["created"]);
    let users: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(users[0]["email"], "new@example.com");
    assert_eq!(users[0]["name"], "New Name");
    let sources: Value = serde_json::from_str(&db.table("scimUser").await?)?;
    assert_eq!(sources[0]["givenName"], Value::Null);
    assert_eq!(sources[0]["externalIdKey"], Value::Null);
    assert_eq!(db.table("session").await?, "[]");
    assert!(users[0]["emailVerified"] == false || users[0]["emailVerified"] == 0);
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 3);
    assert_eq!(subject[0]["profileSourceId"], initial["id"]);
    for (email, total) in [("new@example.com", 1), ("old@example.com", 0)] {
        let listed = super::scim_user_list::list(
            &auth,
            &json!({"filter":format!("emails.value eq \"{email}\"")}),
            Some("group-reader"),
        )
        .await?;
        assert_eq!(listed.status, 200);
        assert_eq!(body(&listed)["totalResults"], total);
    }
    let mut before = Vec::new();
    for table in [
        "user",
        "scimUser",
        "scimSubject",
        "scimConnectionBinding",
        "session",
    ] {
        before.push((table, db.table(table).await?));
    }
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let configured = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(super::scim_group_create::GroupProjection(
                    fail.clone(),
                ))),
        )
        .build()
        .await?;
    let mut failure_input = input.clone();
    failure_input["userName"] = json!("rolled-back@example.com");
    failure_input["active"] = json!(true);
    let failed = replace(&configured, id, &failure_input, Some("group-reader")).await?;
    assert_eq!(failed.status, 500);
    assert_eq!(
        body(&failed)["detail"],
        "SCIM projection reconciliation failed"
    );
    for (table, expected) in &before {
        assert_eq!(db.table(table).await?, *expected);
    }
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    _ = db
        .execute(
            "UPDATE \"scimSubject\" SET \"profileSourceId\"=NULL WHERE \"profileSourceId\"=$1",
            &[id],
        )
        .await?;
    let mut req = request(
        &format!("/scim/v2/Users/{id}"),
        Some(
            json!({"schemas":input["schemas"],"userName":"preserved@example.com","displayName":"Provider name"}),
        ),
        "",
    );
    req.method = HttpMethod::Put;
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    _ = req
        .headers
        .insert("content-type".into(), "application/scim+json".into());
    let http = call(&configured, req, 200).await;
    assert_eq!(body(&http)["active"], true);
    assert_eq!(body(&http)["displayName"], "Provider name");
    assert_eq!(body(&http)["emails"][0]["value"], "preserved@example.com");
    let preserved: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(preserved[0]["email"], "new@example.com");
    assert_eq!(preserved[0]["name"], "Projected active");
    let other=super::scim_user_create::create(&configured,&json!({"schemas":input["schemas"],"userName":"other@example.com","externalId":"collision"}),Some("group-reader")).await?;
    assert_eq!(other.status, 201);
    for (value, detail) in [
        (
            json!({"schemas":input["schemas"],"userName":"OTHER@example.com"}),
            "SCIM User userName already exists",
        ),
        (
            json!({"schemas":input["schemas"],"userName":"unique@example.com","externalId":"collision"}),
            "SCIM User externalId already exists",
        ),
    ] {
        let denied = replace(&configured, id, &value, Some("group-reader")).await?;
        assert_eq!(denied.status, 409);
        assert_eq!(body(&denied)["detail"], detail);
        assert_eq!(body(&denied)["scimType"], "uniqueness");
    }
    _ = db
        .execute(
            "UPDATE \"scimUser\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"=$1",
            &[id],
        )
        .await?;
    assert_eq!(
        replace(&configured, id, &input, Some("group-reader"))
            .await?
            .status,
        409
    );
    Ok(())
}
