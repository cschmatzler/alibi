//! Group reads enforce bearer admission and immutable connection ownership.
use super::*;
use alibi::AuthResult;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::scim::{ScimConnectionOptions, ScimCredential, ScimPlugin};
backend_tests!(scim_group_read_authenticates_and_projects_owned_members);
postgres_tests!(scim_group_read_authenticates_and_projects_owned_members);
fn connections() -> Vec<ScimConnectionOptions> {
    let mut limited = ScimCredential::new("limited", "users-reader");
    limited.scopes = Some(vec!["scim.users.read".into()]);
    let mut expired = ScimCredential::new("expired", "expired-reader");
    expired.expires_at = Some(
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    vec![
        ScimConnectionOptions {
            id: "conn-a".into(),
            provisioning_domain_id: Some("tenant-a".into()),
            credentials: vec![
                ScimCredential::new("reader", "group-reader"),
                limited,
                expired,
            ],
        },
        ScimConnectionOptions {
            id: "conn-b".into(),
            provisioning_domain_id: Some("tenant-a".into()),
            credentials: vec![ScimCredential::new("reader", "other-reader")],
        },
    ]
}
pub(super) async fn read<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    query: &Value,
    token: Option<&str>,
) -> AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::group_endpoint(id)?.with_query(query)?,
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
async fn scim_group_read_authenticates_and_projects_owned_members<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(connections()))
        .build()
        .await?;
    let unauthenticated = read(&auth, "staff", &json!({}), None).await?;
    assert_eq!(unauthenticated.status, 401);
    assert_eq!(
        body(&unauthenticated),
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"SCIM bearer token is required"})
    );
    assert_eq!(
        unauthenticated
            .headers
            .get("www-authenticate")
            .map(String::as_str),
        Some("Bearer realm=\"SCIM\"")
    );
    for token in ["invalid-reader", "expired-reader"] {
        let denied = read(&auth, "staff", &json!({}), Some(token)).await?;
        assert_eq!(denied.status, 401);
        assert_eq!(body(&denied)["detail"], "Invalid SCIM bearer token");
    }
    let denied = read(&auth, "staff", &json!({}), Some("users-reader")).await?;
    assert_eq!(denied.status, 403);
    assert_eq!(
        body(&denied)["detail"],
        "The SCIM bearer token is missing the scim.groups.read scope"
    );
    assert!(denied.headers.get("www-authenticate").is_none());
    assert_eq!(db.table("scimConnectionBinding").await?, "[]");
    let invalid_shape = read(
        &auth,
        "staff",
        &json!({"attributes":1,"excludedAttributes":false}),
        None,
    )
    .await?;
    assert_eq!(invalid_shape.status, 400);
    assert_eq!(
        body(&invalid_shape)["detail"],
        "[query.attributes] Invalid input; [query.excludedAttributes] Invalid input"
    );
    let signed = signup(&auth, "group-read-owner@example.com").await;
    let owner = body(&signed);
    let uid = owner["user"]["id"].as_str().unwrap();
    for (id, cid, domain, display) in [
        ("member-a", "conn-a", "tenant-a", "Inactive member"),
        ("member-b", "conn-b", "tenant-a", "Foreign member"),
        ("member-c", "conn-a", "tenant-b", "Other domain member"),
    ] {
        _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,$4,$1,$1,$1,'group-read-owner@example.com','[]','[]',$5,$5,'[]',false,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain,uid,display]).await?;
    }
    for (id, cid, domain) in [
        ("staff", "conn-a", "tenant-a"),
        ("other", "conn-b", "tenant-a"),
        ("drift", "conn-a", "tenant-b"),
    ] {
        _=db.execute("INSERT INTO \"scimGroup\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"externalId\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,0,'Staff',$1,'external-staff',$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain]).await?;
    }
    for (id, time) in [
        ("member-a", "2026-01-02T03:04:05.001Z"),
        ("member-b", "2026-01-02T03:04:05.002Z"),
        ("member-c", "2026-01-02T03:04:05.003Z"),
    ] {
        _=db.execute("INSERT INTO \"scimGroupMember\" (\"id\",\"connectionId\",\"groupId\",\"scimUserId\",\"membershipKey\",\"createdAt\") VALUES ($1,'conn-a','staff',$1,$1,'2026-01-02T03:04:05.000Z')",&[id]).await?;
        db.set_timestamp(
            "scimGroupMember",
            "createdAt",
            ("id", id),
            chrono::DateTime::parse_from_rfc3339(time)?.with_timezone(&chrono::Utc),
        )
        .await?;
    }
    let response = read(&auth, "staff", &json!({}), Some("group-reader")).await?;
    assert_eq!(response.status, 200);
    let expected = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"staff","externalId":"external-staff","displayName":"Staff","meta":{"resourceType":"Group","created":"2026-01-02T03:04:05.000Z","lastModified":"2026-01-02T03:04:05.000Z","location":format!("{ORIGIN}/api/auth/scim/v2/Groups/staff")},"members":[{"value":"member-a","$ref":format!("{ORIGIN}/api/auth/scim/v2/Users/member-a"),"display":"Inactive member","type":"User"},{"value":"member-c","$ref":format!("{ORIGIN}/api/auth/scim/v2/Users/member-c"),"display":"Other domain member","type":"User"}]});
    assert_eq!(body(&response), expected);
    let selected = read(
        &auth,
        "staff",
        &json!({"attributes":[" DISPLAYNAME ","members.value,meta.location"]}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(
        body(&selected),
        json!({"schemas":expected["schemas"],"id":"staff","displayName":"Staff","meta":{"location":expected["meta"]["location"]},"members":[{"value":"member-a"},{"value":"member-c"}]})
    );
    let excluded = read(
        &auth,
        "staff",
        &json!({"excludedAttributes":"id,schemas,members.display,meta"}),
        Some("group-reader"),
    )
    .await?;
    let mut retained = expected.clone();
    _ = retained.as_object_mut().unwrap().remove("meta");
    for member in retained["members"].as_array_mut().unwrap() {
        _ = member.as_object_mut().unwrap().remove("display");
    }
    assert_eq!(body(&excluded), retained);
    let date_projection = read(
        &auth,
        "staff",
        &json!({"excludedAttributes":"members,meta.created.fake"}),
        Some("group-reader"),
    )
    .await?;
    let mut dates = expected.clone();
    _ = dates.as_object_mut().unwrap().remove("members");
    dates["meta"]["created"] = json!({});
    assert_eq!(body(&date_projection), dates);
    for id in ["missing", "other"] {
        assert_eq!(
            read(&auth, id, &json!({}), Some("group-reader"))
                .await?
                .status,
            404
        );
    }
    let drift = read(&auth, "drift", &json!({}), Some("group-reader")).await?;
    assert_eq!(drift.status, 409);
    assert_eq!(
        body(&drift)["detail"],
        "The connection provisioningDomainId changed after resources were created"
    );
    let invalid = read(
        &auth,
        "staff",
        &json!({"attributes":"displayName","excludedAttributes":"members"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(invalid.status, 400);
    assert_eq!(body(&invalid)["scimType"], "invalidValue");
    let missing = read(
        &auth,
        "missing",
        &json!({"attributes":"displayName","excludedAttributes":"members"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(missing.status, 404);
    let mut req = request("/scim/v2/Groups/staff", None, "");
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    let http = call(&auth, req, 200).await;
    assert_eq!(body(&http), expected);
    assert_eq!(
        http.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    assert!(http.headers.get("x-better-auth-scim-response").is_none());
    let bindings: Value = serde_json::from_str(&db.table("scimConnectionBinding").await?)?;
    assert_eq!(bindings.as_array().unwrap().len(), 1);
    assert_eq!(bindings[0]["decommissionStatus"], "active");
    _ = db.execute("WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1001) INSERT INTO \"scimGroupMember\" (\"id\",\"connectionId\",\"groupId\",\"scimUserId\",\"membershipKey\",\"createdAt\") SELECT 'cap-'||CAST(n AS TEXT),'conn-a','staff','member-a','cap-'||CAST(n AS TEXT),(SELECT \"createdAt\" FROM \"scimUser\" WHERE \"id\"='member-a') FROM seq", &[]).await?;
    let oversized = read(&auth, "staff", &json!({}), Some("group-reader")).await?;
    assert_eq!(oversized.status, 500);
    assert_eq!(
        body(&oversized)["detail"],
        "Persisted SCIM Group membership exceeds the server limit"
    );
    let selected = read(
        &auth,
        "staff",
        &json!({"attributes":"displayName"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(selected.status, 200);
    assert_eq!(
        body(&selected),
        json!({"schemas":expected["schemas"],"id":"staff","displayName":"Staff"})
    );
    _ = db.execute("UPDATE \"scimConnectionBinding\" SET \"provisioningDomainId\"='drifted-domain' WHERE \"connectionId\"='conn-a'", &[]).await?;
    let changed = read(&auth, "staff", &json!({}), Some("group-reader")).await?;
    assert_eq!(changed.status, 409);
    assert_eq!(
        body(&changed)["detail"],
        "The connection provisioningDomainId changed after the connection was first used"
    );
    _ = db.execute("UPDATE \"scimConnectionBinding\" SET \"provisioningDomainId\"='tenant-a',\"decommissionStatus\"='complete' WHERE \"connectionId\"='conn-a'", &[]).await?;
    let retired = read(&auth, "staff", &json!({}), Some("group-reader")).await?;
    assert_eq!(retired.status, 401);
    assert_eq!(
        body(&retired)["detail"],
        "SCIM connection is decommissioned"
    );

    Ok(())
}
