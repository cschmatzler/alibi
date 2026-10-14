//! Canonical User reads validate stored state, rebuild mirrors and project extensions.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(scim_user_read_reconstructs_and_projects_validated_attributes);
postgres_tests!(scim_user_read_reconstructs_and_projects_validated_attributes);
async fn read<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    query: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let output = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::user_endpoint(id)?.with_query(query)?,
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
    match output {
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
async fn scim_user_read_reconstructs_and_projects_validated_attributes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(read(&auth, "rich", &json!({}), None).await?.status, 401);
    let signed = signup(&auth, "user-read-owner@example.com").await;
    let owner = body(&signed);
    let uid = owner["user"]["id"].as_str().unwrap();
    let attrs = json!({"schemas":["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","urn:ietf:params:scim:schemas:core:2.0:User"],"name":{"formatted":" Alice Example ","givenName":" Alice ","ignored":"drop"},"emails":[{"value":"Alice@example.com","primary":true,"type":"WORK","ignored":"drop"}],"title":" Principal ","phoneNumbers":[{"value":" +1 555 ","type":"WORK","primary":true}],"addresses":[{"streetAddress":" 1 Road ","type":"WORK","primary":true}],"roles":[{"value":" admin ","display":" Admin ","type":"CUSTOM","primary":true}],"enterprise":{"employeeNumber":[" 42 "],"organization":" Example ","manager":{"value":" manager ","displayName":"drop"}},"userName":"spoof","active":true});
    let serialized = attrs.to_string();
    for (id, cid, domain) in [
        ("rich", "conn-a", "tenant-a"),
        ("legacy", "conn-a", "tenant-a"),
        ("corrupt", "conn-a", "tenant-a"),
        ("foreign", "conn-b", "tenant-a"),
        ("drift", "conn-a", "tenant-b"),
    ] {
        _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"givenName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,$4,$1,'alice',$1,'Alice@example.com','[]','[]','Alice from row',' Legacy Name ',' Legacy ','[{\"value\":\"legacy@example.com\",\"primary\":true}]',false,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain,uid]).await?;
    }
    _=db.execute("UPDATE \"scimUser\" SET \"serializedAttributes\"=$1,\"externalId\"='external-alice' WHERE \"id\"='rich'",&[&serialized]).await?;
    _ = db
        .execute(
            "UPDATE \"scimUser\" SET \"serializedAttributes\"='not-json' WHERE \"id\"='corrupt'",
            &[],
        )
        .await?;
    let response = read(&auth, "rich", &json!({}), Some("users-reader")).await?;
    assert_eq!(response.status, 200);
    let expected = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"id":"rich","externalId":"external-alice","userName":"alice","displayName":"Alice from row","active":false,"name":{"formatted":"Alice Example","givenName":"Alice"},"emails":[{"value":"Alice@example.com","primary":true,"type":"work"}],"title":"Principal","phoneNumbers":[{"value":"+1 555","type":"work","primary":true}],"addresses":[{"streetAddress":"1 Road","type":"work","primary":true}],"roles":[{"value":"admin","display":"Admin","type":"custom","primary":true}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"42","organization":"Example","manager":{"value":"manager"}},"meta":{"resourceType":"User","created":"2026-01-02T03:04:05.000Z","lastModified":"2026-01-02T03:04:05.000Z","location":format!("{ORIGIN}/api/auth/scim/v2/Users/rich")}});
    assert_eq!(body(&response), expected);
    let selected=read(&auth,"rich",&json!({"attributes":"userName,emails.value,urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value"}),Some("users-reader")).await?;
    assert_eq!(
        body(&selected),
        json!({"schemas":expected["schemas"],"id":"rich","userName":"alice","emails":[{"value":"Alice@example.com"}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":"manager"}}})
    );
    let legacy = read(&auth, "legacy", &json!({}), Some("users-reader")).await?;
    assert_eq!(legacy.status, 200);
    assert_eq!(
        body(&legacy)["name"],
        json!({"formatted":"Legacy Name","givenName":"Legacy"})
    );
    assert_eq!(
        body(&legacy)["emails"],
        json!([{"value":"legacy@example.com","primary":true}])
    );
    for id in ["missing", "foreign"] {
        assert_eq!(
            read(&auth, id, &json!({}), Some("users-reader"))
                .await?
                .status,
            404
        );
    }
    assert_eq!(
        read(&auth, "drift", &json!({}), Some("users-reader"))
            .await?
            .status,
        409
    );
    let corrupt = read(
        &auth,
        "corrupt",
        &json!({"attributes":"id"}),
        Some("users-reader"),
    )
    .await?;
    assert_eq!(corrupt.status, 500);
    assert_eq!(
        body(&corrupt)["detail"],
        "Stored SCIM User attribute state is invalid"
    );
    let base = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"name":{"formatted":"Valid Name"},"emails":[{"value":"valid@example.com","primary":true}]});
    let mut invalid = Vec::new();
    for (field, value) in [
        ("emails", json!([])),
        (
            "emails",
            json!([{"value":"valid@example.com","primary":false}]),
        ),
        (
            "emails",
            json!([{"value":"one@example.com","primary":true,"type":"WORK"},{"value":"two@example.com","primary":false,"type":"work"}]),
        ),
        (
            "emails",
            json!([{"value":"valid@example.com","primary":true},{"value":"VALID@example.com","primary":false}]),
        ),
        (
            "schemas",
            json!(["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]),
        ),
        ("enterprise", json!({})),
        ("addresses", json!([{"type":"work"}])),
        ("title", json!(["Title"])),
        (
            "phoneNumbers",
            Value::Array(
                (0..11)
                    .map(|index| json!({"value":format!("phone-{index}")}))
                    .collect(),
            ),
        ),
    ] {
        let mut candidate = base.clone();
        candidate[field] = value;
        invalid.push(candidate.to_string());
    }
    invalid.push(format!("{}{}", " ".repeat(65536), base));
    for candidate in invalid {
        _ = db
            .execute(
                "UPDATE \"scimUser\" SET \"serializedAttributes\"=$1 WHERE \"id\"='rich'",
                &[&candidate],
            )
            .await?;
        let invalid = read(
            &auth,
            "rich",
            &json!({"attributes":"id"}),
            Some("users-reader"),
        )
        .await?;
        assert_eq!(invalid.status, 500);
        assert_eq!(
            body(&invalid)["detail"],
            "Stored SCIM User attribute state is invalid"
        );
    }
    _ = db
        .execute(
            "UPDATE \"scimUser\" SET \"serializedAttributes\"=$1 WHERE \"id\"='rich'",
            &[&serialized],
        )
        .await?;
    let mut req = request("/scim/v2/Users/rich", None, "");
    _ = req
        .headers
        .insert("authorization".into(), "Bearer users-reader".into());
    let http = call(&auth, req, 200).await;
    assert_eq!(body(&http), expected);
    Ok(())
}
