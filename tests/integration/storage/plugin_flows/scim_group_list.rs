//! Classic Group collections isolate connections and preserve filter/pagination semantics.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
backend_tests!(scim_group_list_filters_pages_and_checks_domain_before_query_semantics);
postgres_tests!(scim_group_list_filters_pages_and_checks_domain_before_query_semantics);
async fn list<S: AuthSchema>(
    auth: &Alibi<S>,
    query: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::groups_endpoint().with_query(query)?,
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
async fn scim_group_list_filters_pages_and_checks_domain_before_query_semantics<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(list(&auth, &json!({}), None).await?.status, 401);
    for (id, cid, name, external, order) in [
        ("group-c", "conn-a", "Third", "EXTERNAL-C", "3"),
        ("group-a", "conn-a", "Staff and Crew", "EXTERNAL-A", "1"),
        ("group-b", "conn-a", "Second", "EXTERNAL-B", "2"),
        ("foreign", "conn-b", "Foreign", "EXTERNAL-F", "0"),
    ] {
        let display = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[
            "scim-group-display-name",
            cid,
            &name.to_lowercase(),
        ])?));
        let key = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[
            "scim-group-external-id",
            cid,
            external,
        ])?));
        _=db.execute("INSERT INTO \"scimGroup\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"externalId\",\"externalIdKey\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,'tenant-a',0,$3,$4,$5,$6,$7,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,name,&display,external,&key,order]).await?;
    }
    let page = list(
        &auth,
        &json!({"startIndex":"2","count":"1","attributes":"displayName"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(page.status, 200);
    assert_eq!(
        body(&page),
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"startIndex":2,"itemsPerPage":1,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"group-b","displayName":"Second"}]})
    );
    for (filter, total, id) in [
        ("displayName eq \"STAFF AND CREW\"", 1, Some("group-a")),
        (
            "externalId eq \"EXTERNAL-B\" and id eq \"group-b\"",
            1,
            Some("group-b"),
        ),
        ("displayName eq \" Staff and Crew \"", 0, None),
        ("id eq \"foreign\"", 0, None),
    ] {
        let result = list(
            &auth,
            &json!({"filter":filter,"attributes":"displayName"}),
            Some("group-reader"),
        )
        .await?;
        assert_eq!(result.status, 200);
        let data = body(&result);
        assert_eq!(data["totalResults"], total);
        if let Some(id) = id {
            assert_eq!(data["Resources"][0]["id"], id);
        }
    }
    let empty = list(
        &auth,
        &json!({"startIndex":-5,"count":-1}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(
        body(&empty),
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"startIndex":1,"itemsPerPage":0,"Resources":[]})
    );
    let full = list(&auth, &json!({}), Some("group-reader")).await?;
    assert_eq!(body(&full)["Resources"][0]["members"], json!([]));
    assert_eq!(body(&full)["itemsPerPage"], 3);
    for (query, kind, detail) in [
        (
            json!({"count":"1.5"}),
            "invalidValue",
            "count must be an integer",
        ),
        (
            json!({"count":"+2"}),
            "invalidValue",
            "count must be an integer",
        ),
        (
            json!({"startIndex":"9007199254740992"}),
            "invalidValue",
            "startIndex must be an integer",
        ),
        (
            json!({"filter":"displayName co \"Staff\""}),
            "invalidFilter",
            "filter operator co is not supported",
        ),
        (
            json!({"filter":"active eq \"true\""}),
            "invalidFilter",
            "filter attribute active is not supported for Group",
        ),
        (
            json!({"filter":"id eq 5"}),
            "invalidFilter",
            "filter equality value must be a quoted string",
        ),
    ] {
        let response = list(&auth, &query, Some("group-reader")).await?;
        assert_eq!(response.status, 400);
        assert_eq!(body(&response)["scimType"], kind);
        assert_eq!(body(&response)["detail"], detail);
    }
    let mut req = request("/scim/v2/Groups", None, "");
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    let http = call(&auth, req, 200).await;
    assert_eq!(body(&http), body(&full));
    for index in 0..101 {
        let id = format!("extra-{index:03}");
        let name = format!("Extra {index}");
        let order = format!("z{index:03}");
        let key = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[
            "scim-group-display-name",
            "conn-a",
            &name.to_lowercase(),
        ])?));
        _=db.execute("INSERT INTO \"scimGroup\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,'conn-a','tenant-a',0,$2,$3,$4,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[&id,&name,&key,&order]).await?;
    }
    let bounded = list(
        &auth,
        &json!({"count":1000,"attributes":"id"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(body(&bounded)["totalResults"], 104);
    assert_eq!(body(&bounded)["itemsPerPage"], 100);
    assert_eq!(body(&bounded)["Resources"].as_array().unwrap().len(), 100);
    let beyond = list(
        &auth,
        &json!({"startIndex":500,"count":2}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(body(&beyond)["totalResults"], 104);
    assert_eq!(body(&beyond)["startIndex"], 500);
    assert_eq!(body(&beyond)["itemsPerPage"], 0);
    let shape = list(&auth, &json!({"count":[]}), None).await?;
    assert_eq!(shape.status, 400);
    assert_eq!(body(&shape)["detail"], "[query.count] Invalid input");

    _ = db
        .execute(
            "UPDATE \"scimGroup\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"='group-c'",
            &[],
        )
        .await?;
    let changed = list(
        &auth,
        &json!({"filter":"id eq \"group-a\"","count":"bad"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(changed.status, 409);
    Ok(())
}
