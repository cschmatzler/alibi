//! Group deletion removes canonical memberships and rolls back application failures.
use super::scim_group_create::{GroupProjection, create, seed};
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(scim_group_delete_reconciles_members_and_rolls_back_callback_failure);
postgres_tests!(scim_group_delete_reconciles_members_and_rolls_back_callback_failure);
async fn delete<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::delete_group_endpoint(id)?.with_query(&json!({"attributes":1}))?,
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
async fn scim_group_delete_reconciles_members_and_rolls_back_callback_failure<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(delete(&auth, "missing", None).await?.status, 401);
    seed(&db, &auth).await?;
    let schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    let input = json!({"schemas":[schema],"displayName":"Delete me","members":[{"value":"member-a"},{"value":"member-c"}]});
    let resource = body(&create(&auth, &input, &json!({}), Some("group-reader")).await?);
    let id = resource["id"].as_str().unwrap();
    assert_eq!(delete(&auth, id, Some("users-reader")).await?.status, 403);
    assert_eq!(delete(&auth, id, Some("other-reader")).await?.status, 404);
    let fail = Arc::new(AtomicBool::new(true));
    let configured = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(GroupProjection(fail.clone()))),
        )
        .build()
        .await?;
    let groups = db.table("scimGroup").await?;
    let members = db.table("scimGroupMember").await?;
    let subjects = db.table("scimSubject").await?;
    let users = db.table("user").await?;
    let bindings = db.table("scimConnectionBinding").await?;
    let sources = db.table("scimUser").await?;
    let failure = delete(&configured, id, Some("group-reader")).await?;
    assert_eq!(failure.status, 500);
    assert_eq!(
        body(&failure)["detail"],
        "SCIM projection reconciliation failed"
    );
    for (table, expected) in [
        ("scimGroup", groups),
        ("scimGroupMember", members),
        ("scimSubject", subjects),
        ("user", users),
        ("scimConnectionBinding", bindings),
    ] {
        assert_eq!(db.table(table).await?, expected);
    }
    fail.store(false, Ordering::SeqCst);
    let removed = delete(&configured, id, Some("group-reader")).await?;
    assert_eq!(removed.status, 204);
    assert!(removed.body.is_empty());
    assert_eq!(
        removed.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(db.table("scimGroup").await?, "[]");
    assert_eq!(db.table("scimGroupMember").await?, "[]");
    assert_eq!(db.table("scimUser").await?, sources);
    assert!(db.table("user").await?.contains("Projected inactive"));
    assert_eq!(
        delete(&configured, id, Some("group-reader")).await?.status,
        404
    );
    let empty = json!({"schemas":[schema],"displayName":"HTTP delete"});
    let resource = body(&create(&configured, &empty, &json!({}), Some("group-reader")).await?);
    let http_id = resource["id"].as_str().unwrap();
    let mut req = request(&format!("/scim/v2/Groups/{http_id}"), None, "");
    req.method = HttpMethod::Delete;
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    let http = call(&configured, req, 204).await;
    assert!(http.body.is_empty());
    assert_eq!(
        http.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let resource = body(
        &create(
            &configured,
            &json!({"schemas":[schema],"displayName":"Drift"}),
            &json!({}),
            Some("group-reader"),
        )
        .await?,
    );
    let drift = resource["id"].as_str().unwrap();
    _ = db
        .execute(
            "UPDATE \"scimGroup\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"=$1",
            &[drift],
        )
        .await?;
    assert_eq!(
        delete(&configured, drift, Some("group-reader"))
            .await?
            .status,
        409
    );
    Ok(())
}
