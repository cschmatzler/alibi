//! Full Group replacement preserves retained member records and rolls back projection failures.
use super::scim_group_create::{GroupProjection, create, seed};
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(scim_group_replace_preserves_retained_members_and_clears_omitted_fields);
postgres_tests!(scim_group_replace_preserves_retained_members_and_clears_omitted_fields);
async fn replace<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    value: &Value,
    query: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(
        auth.dispatch_endpoint(
            ScimPlugin::replace_group_endpoint(id)?
                .with_body(value)?
                .with_query(query)?,
            EndpointOptions {
                headers: token.map(|token| {
                    [("authorization".into(), format!("Bearer {token}"))]
                        .into_iter()
                        .collect()
                }),
                ..Default::default()
            },
        ),
    )
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
async fn scim_group_replace_preserves_retained_members_and_clears_omitted_fields<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    let update =
        json!({"schemas":[schema],"displayName":" Renamed ","members":[{"value":"member-c"}]});
    assert_eq!(
        replace(&auth, "missing", &update, &json!({}), None)
            .await?
            .status,
        401
    );
    seed(&db, &auth).await?;
    let initial=body(&create(&auth,&json!({"schemas":[schema],"displayName":"Original","externalId":"old-external","members":[{"value":"member-a"},{"value":"member-c"}]}),&json!({}),Some("group-reader")).await?);
    let id = initial["id"].as_str().unwrap();
    let original_members: Value = serde_json::from_str(&db.table("scimGroupMember").await?)?;
    let retained = original_members
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["scimUserId"] == "member-c")
        .unwrap()
        .clone();
    assert_eq!(
        replace(&auth, id, &update, &json!({}), Some("users-reader"))
            .await?
            .status,
        403
    );
    assert_eq!(
        replace(&auth, id, &update, &json!({}), Some("other-reader"))
            .await?
            .status,
        404
    );
    let renamed = replace(&auth, id, &update, &json!({}), Some("group-reader")).await?;
    assert_eq!(renamed.status, 200);
    let value = body(&renamed);
    assert_eq!(value["id"], id);
    assert_eq!(value["displayName"], "Renamed");
    assert!(value.get("externalId").is_none());
    assert_eq!(value["members"].as_array().unwrap().len(), 1);
    assert_eq!(value["members"][0]["value"], "member-c");
    assert_eq!(value["meta"]["created"], initial["meta"]["created"]);
    assert!(renamed.headers.get("content-location").is_none());
    let after: Value = serde_json::from_str(&db.table("scimGroupMember").await?)?;
    assert_eq!(after.as_array().unwrap(), &vec![retained]);
    assert_eq!(
        create(
            &auth,
            &json!({"schemas":[schema],"displayName":"Occupied","externalId":"taken"}),
            &json!({}),
            Some("group-reader")
        )
        .await?
        .status,
        201
    );
    let groups = db.table("scimGroup").await?;
    let members = db.table("scimGroupMember").await?;
    let subjects = db.table("scimSubject").await?;
    for (body, status, detail) in [
        (
            json!({"schemas":[schema],"displayName":"OCCUPIED"}),
            409,
            "SCIM Group displayName already exists",
        ),
        (
            json!({"schemas":[schema],"displayName":"Else","externalId":"taken"}),
            409,
            "SCIM Group externalId already exists",
        ),
        (
            json!({"schemas":[schema],"displayName":"Invalid","members":[{"value":"member-b"}]}),
            400,
            "One or more Group members are invalid",
        ),
    ] {
        let failure = replace(&auth, id, &body, &json!({}), Some("group-reader")).await?;
        assert_eq!(failure.status, status);
        assert_eq!(super::body(&failure)["detail"], detail);
        assert_eq!(db.table("scimGroup").await?, groups);
        assert_eq!(db.table("scimGroupMember").await?, members);
        assert_eq!(db.table("scimSubject").await?, subjects);
    }
    let fail = Arc::new(AtomicBool::new(true));
    let configured = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(GroupProjection(fail.clone()))),
        )
        .build()
        .await?;
    let users = db.table("user").await?;
    let input = json!({"schemas":[schema],"displayName":"Callback success","members":[{"value":"member-a"}]});
    let failure = replace(&configured, id, &input, &json!({}), Some("group-reader")).await?;
    assert_eq!(failure.status, 500);
    assert_eq!(
        body(&failure)["detail"],
        "SCIM projection reconciliation failed"
    );
    assert_eq!(db.table("scimGroup").await?, groups);
    assert_eq!(db.table("scimGroupMember").await?, members);
    assert_eq!(db.table("scimSubject").await?, subjects);
    assert_eq!(db.table("user").await?, users);
    fail.store(false, Ordering::SeqCst);
    let projected = replace(
        &configured,
        id,
        &input,
        &json!({"attributes":"displayName"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(projected.status, 200);
    assert_eq!(body(&projected)["displayName"], "Callback success");
    assert!(body(&projected).get("members").is_none());
    assert!(db.table("user").await?.contains("Projected inactive"));
    let mut req = request(
        &format!("/scim/v2/Groups/{id}"),
        Some(json!({"schemas":[schema],"displayName":"HTTP replaced"})),
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
    assert_eq!(body(&http)["members"], json!([]));
    assert_eq!(body(&http)["displayName"], "HTTP replaced");
    assert_eq!(db.table("scimGroupMember").await?, "[]");
    _ = db
        .execute(
            "UPDATE \"scimGroup\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"=$1",
            &[id],
        )
        .await?;
    assert_eq!(
        replace(&configured, id, &update, &json!({}), Some("group-reader"))
            .await?
            .status,
        409
    );
    Ok(())
}
