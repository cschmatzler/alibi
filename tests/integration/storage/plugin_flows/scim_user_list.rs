//! User collections use scoped username/email indexes and validate each returned row.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
backend_tests!(scim_user_list_filters_email_indexes_and_validates_only_returned_rows);
postgres_tests!(scim_user_list_filters_email_indexes_and_validates_only_returned_rows);
pub(super) async fn list<S: AuthSchema>(
    auth: &Alibi<S>,
    query: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::users_endpoint().with_query(query)?,
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
fn key(parts: &[&str]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(parts).unwrap()))
}
async fn scim_user_list_filters_email_indexes_and_validates_only_returned_rows<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(list(&auth, &json!({}), None).await?.status, 401);
    let owner = body(&signup(&auth, "user-list-owner@example.com").await);
    let uid = owner["user"]["id"].as_str().unwrap();
    for (id, cid, name, order) in [
        ("carol", "conn-a", "Carol", "3"),
        ("alice", "conn-a", "Alice", "1"),
        ("bob", "conn-a", "Bob", "2"),
        ("foreign", "conn-b", "Foreign", "0"),
    ] {
        let work = format!("work-{id}@example.com");
        let home = format!("home-{id}@example.com");
        let external = format!("external-{id}");
        let name_key = key(&["scim-user-name", cid, &name.to_lowercase()]);
        let external_key = key(&["scim-user-external-id", cid, &external]);
        let work_key = key(&["scim-email-value", &work]);
        let home_key = key(&["scim-email-value", &home]);
        let mut tokens = [work_key.clone(), home_key];
        tokens.sort();
        let all = format!("|{}|", tokens.join("|"));
        let work_index = format!("|{work_key}|");
        let emails=json!([{"value":work,"type":"work","primary":true},{"value":home,"type":"home","primary":false}]).to_string();
        _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"externalId\",\"externalIdKey\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,'tenant-a',$3,$1,$4,$5,$6,$7,$8,$4,$4,$9,$10,$11,true,$12,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,uid,name,&name_key,&work,&work_index,&all,&emails,&external,&external_key,order]).await?;
    }
    let page = list(
        &auth,
        &json!({"startIndex":2,"count":1,"attributes":"userName"}),
        Some("users-reader"),
    )
    .await?;
    assert_eq!(page.status, 200);
    assert_eq!(
        body(&page),
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"startIndex":2,"itemsPerPage":1,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"bob","userName":"Bob"}]})
    );
    for (filter, total, id) in [
        ("userName eq \"ALICE\"", 1, Some("alice")),
        ("userName eq \" Alice \"", 0, None),
        ("externalId eq \"external-bob\"", 1, Some("bob")),
        (
            "emails.value eq \" HOME-ALICE@EXAMPLE.COM \"",
            1,
            Some("alice"),
        ),
        (
            "emails[type eq \"work\"].value eq \"work-bob@example.com\" and userName eq \"BOB\"",
            1,
            Some("bob"),
        ),
        (
            "emails[type eq \"work\"].value eq \"home-bob@example.com\"",
            0,
            None,
        ),
        ("id eq \"foreign\"", 0, None),
    ] {
        let response = list(
            &auth,
            &json!({"filter":filter,"attributes":"userName"}),
            Some("users-reader"),
        )
        .await?;
        assert_eq!(response.status, 200);
        let data = body(&response);
        assert_eq!(data["totalResults"], total);
        if let Some(id) = id {
            assert_eq!(data["Resources"][0]["id"], id);
        }
    }
    let bom = list(
        &auth,
        &json!({"filter":"emails[\u{FEFF}type eq \"work\"].value eq \"work-bob@example.com\"","attributes":"id"}),
        Some("users-reader"),
    ).await?;
    assert_eq!(bom.status, 200);
    assert_eq!(body(&bom)["Resources"][0]["id"], "bob");
    let nel = list(
        &auth,
        &json!({"filter":"emails[\u{0085}type eq \"work\"].value eq \"work-bob@example.com\""}),
        Some("users-reader"),
    )
    .await?;
    assert_eq!(nel.status, 400);
    let unsupported = list(
        &auth,
        &json!({"filter":"emails.work.value eq \"work-bob@example.com\""}),
        Some("users-reader"),
    )
    .await?;
    assert_eq!(unsupported.status, 400);
    assert_eq!(
        body(&unsupported)["detail"],
        "filter attribute emails.work.value is not supported for User"
    );
    let mut req = request("/scim/v2/Users", None, "");
    _ = req
        .headers
        .insert("authorization".into(), "Bearer users-reader".into());
    let http = call(&auth, req, 200).await;
    assert_eq!(body(&http)["itemsPerPage"], 3);
    _ = db
        .execute(
            "UPDATE \"scimUser\" SET \"serializedAttributes\"='not-json' WHERE \"id\"='carol'",
            &[],
        )
        .await?;
    let invalid = list(&auth, &json!({"attributes":"id"}), Some("users-reader")).await?;
    assert_eq!(invalid.status, 500);
    assert_eq!(
        body(&invalid)["detail"],
        "Stored SCIM User attribute state is invalid"
    );
    let count = list(&auth, &json!({"count":0}), Some("users-reader")).await?;
    assert_eq!(count.status, 200);
    assert_eq!(body(&count)["totalResults"], 3);
    assert_eq!(body(&count)["Resources"], json!([]));
    let skipped = list(
        &auth,
        &json!({"count":1,"attributes":"id"}),
        Some("users-reader"),
    )
    .await?;
    assert_eq!(skipped.status, 200);
    assert_eq!(body(&skipped)["Resources"][0]["id"], "alice");
    _ = db
        .execute(
            "UPDATE \"scimUser\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"='carol'",
            &[],
        )
        .await?;
    assert_eq!(
        list(&auth, &json!({"count":"bad"}), Some("users-reader"))
            .await?
            .status,
        409
    );
    Ok(())
}
