//! Group PATCH distinguishes no-ops, null removals, member deltas, and transactional failures.
use super::scim_group_create::{GroupProjection, create, seed};
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(
    scim_group_patch_handles_noops_nulls_and_transactional_member_changes,
    scim_group_patch_treats_pathless_sdk_dates_as_empty_records
);
postgres_tests!(
    scim_group_patch_handles_noops_nulls_and_transactional_member_changes,
    scim_group_patch_treats_pathless_sdk_dates_as_empty_records
);
async fn patch<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    operations: Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    patch_input(auth, id, json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":operations}).into(), token).await
}
async fn patch_input<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    input: alibi::utils::json::JsValue,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::patch_group_endpoint(id)?.with_body_value(input),
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
async fn scim_group_patch_handles_noops_nulls_and_transactional_member_changes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(patch(&auth, "missing", json!([]), None).await?.status, 401);
    seed(&db, &auth).await?;
    let initial=body(&create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original","externalId":"old-external","members":[{"value":"member-a"},{"value":"member-c"}]}),&json!({}),Some("group-reader")).await?);
    let id = initial["id"].as_str().unwrap();
    assert_eq!(
        patch(&auth, id, json!([]), Some("users-reader"))
            .await?
            .status,
        403
    );
    assert_eq!(
        patch(&auth, id, json!([]), Some("other-reader"))
            .await?
            .status,
        404
    );
    let fail = Arc::new(AtomicBool::new(true));
    let configured = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(GroupProjection(fail.clone()))),
        )
        .build()
        .await?;
    for operations in [
        json!([]),
        json!([{"op":"ADD","path":"members","value":[{"value":"member-a"}]},{"op":"remove","path":"members[value eq \"missing-member\"]"}]),
    ] {
        let noop = patch(&configured, id, operations, Some("group-reader")).await?;
        assert_eq!(noop.status, 200);
        assert_eq!(body(&noop), initial);
    }
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 2);
    let groups = db.table("scimGroup").await?;
    let members = db.table("scimGroupMember").await?;
    let subjects = db.table("scimSubject").await?;
    let users = db.table("user").await?;
    let bindings = db.table("scimConnectionBinding").await?;
    let contradictory=patch(&configured,id,json!([{"op":"add","path":"members","value":[{"value":"member-b"}]},{"op":"remove","path":"members","value":[{"value":"member-b"}]}]),Some("group-reader")).await?;
    assert_eq!(contradictory.status, 400);
    assert_eq!(
        body(&contradictory)["detail"],
        "One or more Group members are invalid"
    );
    let mixed = json!([{"value":{"id":id,"schemas":[],"meta":null,"displayName":[" Renamed "],"members":[{"value":"member-a","type":123}]}},{"op":"remove","path":"externalId"}]);
    let failed = patch(&configured, id, mixed.clone(), Some("group-reader")).await?;
    assert_eq!(failed.status, 500);
    assert_eq!(
        body(&failed)["detail"],
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
    let changed = patch(&configured, id, mixed, Some("group-reader")).await?;
    assert_eq!(changed.status, 200);
    let changed = body(&changed);
    assert_eq!(changed["displayName"], "Renamed");
    assert!(changed.get("externalId").is_none());
    assert_eq!(changed["members"].as_array().unwrap().len(), 1);
    assert_eq!(changed["members"][0]["value"], "member-a");
    for (operations, detail, kind) in [
        (
            json!([{"op":"remove","path":"displayName"}]),
            "displayName is required and cannot be removed",
            "mutability",
        ),
        (
            json!([{"op":"replace","path":"id","value":"other"}]),
            "id is read-only",
            "mutability",
        ),
        (
            json!([{"op":"remove"}]),
            "A pathless remove operation has no target",
            "noTarget",
        ),
        (
            json!([{"value":12}]),
            "A pathless Group PATCH value must be an object",
            "invalidValue",
        ),
        (
            json!([{"path":"unknown","value":"value"}]),
            "Unsupported Group PATCH path",
            "invalidPath",
        ),
        (
            json!([{"op":"remove","path":"memberſ[value eq \"member-a\"]"}]),
            "Unsupported Group PATCH path",
            "invalidPath",
        ),
        (
            json!([{"path":"externalId","value":null}]),
            "externalId must be a non-empty string",
            "invalidValue",
        ),
        (
            json!([{"path":"members","value":null}]),
            "members must be an array",
            "invalidValue",
        ),
    ] {
        let denied = patch(&configured, id, operations, Some("group-reader")).await?;
        assert_eq!(denied.status, 400);
        assert_eq!(body(&denied)["detail"], detail);
        assert_eq!(body(&denied)["scimType"], kind);
    }
    let removed=patch(&configured,id,json!([{"op":"remove","path":"urn:ietf:params:scim:schemas:core:2.0:Group:members\u{FEFF}[ value eq \"member-a\"]"}]),Some("group-reader")).await?;
    assert_eq!(removed.status, 200);
    assert_eq!(body(&removed)["members"], json!([]));
    let mut req = request(
        &format!("/scim/v2/Groups/{id}"),
        Some(
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"ADD","path":"members","value":[{"value":"member-a"}]}]}),
        ),
        "",
    );
    req.method = HttpMethod::Patch;
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    _ = req
        .headers
        .insert("content-type".into(), "application/scim+json".into());
    let http = call(&configured, req, 200).await;
    assert_eq!(body(&http)["members"][0]["value"], "member-a");
    let cleared = patch(
        &configured,
        id,
        json!([{"op":"remove","path":"members"}]),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(cleared.status, 200);
    assert_eq!(body(&cleared)["members"], json!([]));
    _ = db
        .execute(
            "UPDATE \"scimGroup\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"=$1",
            &[id],
        )
        .await?;
    assert_eq!(
        patch(&configured, id, json!([]), Some("group-reader"))
            .await?
            .status,
        409
    );
    Ok(())
}

async fn scim_group_patch_treats_pathless_sdk_dates_as_empty_records<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::utils::json::JsValue;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let initial = body(&create(&auth, &json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Date Group"}), &json!({}), Some("group-reader")).await?);
    let id = initial["id"].as_str().unwrap();
    let initial_members = db.table("scimGroupMember").await?;
    for (op, path, expected) in [
        ("replace", None, 200),
        ("add", None, 200),
        ("remove", None, 400),
        ("replace", Some("displayName"), 400),
    ] {
        let mut operation = JsValue::from(json!({"op":op}));
        if let JsValue::Object(fields) = &mut operation {
            _ = fields.insert(
                "value".into(),
                JsValue::Date(
                    chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")?.to_utc(),
                ),
            );
            if let Some(path) = path {
                _ = fields.insert("path".into(), JsValue::String(path.into()));
            }
        }
        let mut input =
            JsValue::from(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}));
        if let JsValue::Object(fields) = &mut input {
            _ = fields.insert("Operations".into(), JsValue::Array(vec![operation]));
        }
        let before: Value = serde_json::from_str(&db.table("scimGroup").await?)?;
        let response = patch_input(&auth, id, input, Some("group-reader")).await?;
        assert_eq!(response.status, expected);
        if expected == 200 {
            assert_eq!(body(&response), initial);
        } else {
            assert_eq!(
                body(&response)["detail"],
                if op == "remove" {
                    "A pathless remove operation has no target"
                } else {
                    "displayName must be a non-empty string"
                }
            );
        }
        let mut after: Value = serde_json::from_str(&db.table("scimGroup").await?)?;
        assert_eq!(
            after[0]["revision"].as_i64().unwrap(),
            before[0]["revision"].as_i64().unwrap() + i64::from(expected == 200)
        );
        after[0]["revision"] = before[0]["revision"].clone();
        assert_eq!(after, before);
        assert_eq!(db.table("scimGroupMember").await?, initial_members);
    }
    B::close(connection).await
}
