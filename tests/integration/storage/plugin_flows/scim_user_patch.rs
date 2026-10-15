//! User PATCH applies ordered changes and fences no-ops without projection callbacks.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(
    scim_user_patch_handles_noops_and_ordered_canonical_changes,
    scim_user_patch_clones_sdk_dates_as_own_property_records,
    scim_user_patch_reports_first_invalid_profile_attribute,
    scim_user_patch_preserves_nonfinite_sdk_values_until_final_validation,
    scim_user_patch_size_limit_measures_final_normalized_document
);
postgres_tests!(
    scim_user_patch_handles_noops_and_ordered_canonical_changes,
    scim_user_patch_clones_sdk_dates_as_own_property_records,
    scim_user_patch_reports_first_invalid_profile_attribute,
    scim_user_patch_preserves_nonfinite_sdk_values_until_final_validation,
    scim_user_patch_size_limit_measures_final_normalized_document
);
async fn patch<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    operations: Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    patch_input(auth,id,alibi::utils::json::JsValue::from(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":operations})),token).await
}
async fn patch_input<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    input: alibi::utils::json::JsValue,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::patch_user_endpoint(id)?.with_body_value(input),
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
async fn scim_user_patch_handles_noops_and_ordered_canonical_changes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(patch(&auth, "missing", json!([]), None).await?.status, 401);
    let initial=super::scim_user_create::create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","externalId":"old-external","name":{"givenName":"Alice","familyName":"Example"},"emails":[{"value":"work@example.com","type":"work"},{"value":"home@example.com","type":"home"}]}),Some("group-reader")).await?;
    assert_eq!(initial.status, 201);
    let initial = body(&initial);
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
    for operations in [json!([]), json!([{"path":"active","value":true}])] {
        let noop = patch(&configured, id, operations, Some("group-reader")).await?;
        assert_eq!(noop.status, 200);
        assert_eq!(body(&noop), initial);
    }
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 4);
    let changed = json!([{"path":"emails[type eq \"work\"].value","value":"new-work@example.com"},{"op":"add","path":"name","value":{"givenName":["New"]}},{"path":"name.formatted","value":"New Name"},{"op":"add","path":"roles","value":[{"value":"admin","type":"access","primary":true}]},{"path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":[{"value":"manager-id"}]},{"path":"active","value":[false]},{"op":"remove","path":"externalId"},{"path":"title","value":[" Principal "]}]);
    let mut before = Vec::new();
    for table in ["user", "scimUser", "scimSubject", "scimConnectionBinding"] {
        before.push((table, db.table(table).await?));
    }
    let failed = patch(&configured, id, changed.clone(), Some("group-reader")).await?;
    assert_eq!(failed.status, 500);
    for (table, expected) in &before {
        assert_eq!(db.table(table).await?, *expected);
    }
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let updated = patch(&configured, id, changed, Some("group-reader")).await?;
    assert_eq!(updated.status, 200);
    let value = body(&updated);
    assert_eq!(value["displayName"], "New Name");
    assert_eq!(value["name"]["givenName"], "New");
    assert_eq!(value["title"], "Principal");
    assert_eq!(value["roles"][0]["value"], "admin");
    assert_eq!(
        value["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["manager"],
        json!({"value":"manager-id"})
    );
    assert_eq!(value["active"], false);
    assert!(value.get("externalId").is_none());
    let extras = json!([{"op":"replace","path":"roles[type eq \"access\"]","value":{"value":"editor"}},{"path":"roles[primary eq true].display","value":"Editor"},{"op":"add","path":"phoneNumbers","value":{"value":"+1","type":"work","primary":true}},{"op":"add","path":"phoneNumbers[type eq \"home\"].value","value":"+2"},{"path":"phoneNumbers[type eq \"home\"].primary","value":true},{"op":"remove","path":"phoneNumbers[type eq \"work\"]"},{"op":"remove","path":"roles[type eq \"missing\"]"},{"op":"add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","value":{"employeeNumber":["42"],"manager":{"displayName":"Ignored","$ref":"https://idp.example/manager"}}},{"op":"remove","path":"manager.value"},{"op":"remove","path":"active"},{"op":"add","path":"emails","value":[{"value":"primary@example.com","type":"other","primary":true}]},{"path":"emails[primary eq \"true\"].value","value":"promoted@example.com"},{"op":"remove","path":"emails[type eq \"home\"].value"}]);
    let complex = patch(&configured, id, extras, Some("group-reader")).await?;
    assert_eq!(complex.status, 200);
    let updated = body(&complex);
    assert_eq!(
        updated["roles"],
        json!([{"value":"editor","display":"Editor","type":"access","primary":true}])
    );
    assert_eq!(
        updated["phoneNumbers"],
        json!([{"value":"+2","type":"home","primary":true}])
    );
    assert_eq!(
        updated["emails"],
        json!([{"value":"new-work@example.com","type":"work","primary":false},{"value":"promoted@example.com","type":"other","primary":true}])
    );
    assert_eq!(updated["active"], true);
    assert_eq!(
        updated["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
        json!({"employeeNumber":"42","manager":{"$ref":"https://idp.example/manager"}})
    );
    for (operations, detail, kind) in [
        (
            json!([{"op":"remove","path":"emails"}]),
            "emails cannot be removed",
            "invalidValue",
        ),
        (
            json!([{"op":"remove"}]),
            "A remove User PATCH operation requires a path",
            "noTarget",
        ),
        (
            json!([{"path":"id","value":"other"}]),
            "id is read-only",
            "mutability",
        ),
        (
            json!([{"path":"unsupported","value":1}]),
            "User PATCH path unsupported is not supported",
            "invalidPath",
        ),
        (
            json!([{"path":"active","value":"false"}]),
            "active must be a boolean",
            "invalidValue",
        ),
    ] {
        let rejected = patch(&configured, id, operations, Some("group-reader")).await?;
        assert_eq!(rejected.status, 400);
        assert_eq!(body(&rejected)["detail"], detail);
        assert_eq!(body(&rejected)["scimType"], kind);
    }
    let mut req = request(
        &format!("/scim/v2/Users/{id}"),
        Some(
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"path":"active","value":false}]}),
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
    assert_eq!(body(&http)["active"], false);
    Ok(())
}

async fn scim_user_patch_clones_sdk_dates_as_own_property_records<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::utils::json::JsValue;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let initial=super::scim_user_create::create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"patch-date-owner@example.com"}),Some("group-reader")).await?;
    let initial = body(&initial);
    let id = initial["id"].as_str().unwrap();
    let before = db.tables(&["user", "scimUser"]).await?;
    for (path, shape) in [
        (Some("userName"), "direct"),
        (Some("userName"), "array"),
        (None, "object"),
        (None, "direct"),
    ] {
        let mut operation = JsValue::from(json!({"op":"replace"}));
        if let JsValue::Object(fields) = &mut operation {
            if let Some(path) = path {
                _ = fields.insert("path".into(), JsValue::String(path.into()));
            }
            let date = JsValue::Date(
                chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")?.to_utc(),
            );
            let value = match shape {
                "array" => JsValue::Array(vec![date]),
                "object" => JsValue::Object([("userName".into(), date)].into_iter().collect()),
                _ => date,
            };
            _ = fields.insert("value".into(), value);
        }
        let mut input =
            JsValue::from(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}));
        if let JsValue::Object(fields) = &mut input {
            _ = fields.insert("Operations".into(), JsValue::Array(vec![operation]));
        }
        let subject_before = db.table("scimSubject").await?;
        let result = patch_input(&auth, id, input, Some("group-reader")).await?;
        if path.is_some() || shape == "object" {
            assert_eq!(result.status, 400);
            assert_eq!(db.table("scimSubject").await?, subject_before);
            assert_eq!(
                body(&result)["detail"],
                "userName must be a non-empty string"
            );
        } else {
            assert_eq!(result.status, 200);
            assert_eq!(body(&result), initial);
        }
        assert_eq!(db.tables(&["user", "scimUser"]).await?, before);
    }
    let text = "2026-01-02T03:04:05.000Z";
    let updated = patch(
        &auth,
        id,
        json!([{"op":"replace","path":"userName","value":text}]),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(updated.status, 200);
    assert_eq!(body(&updated)["userName"], text);
    B::close(connection).await
}

async fn scim_user_patch_reports_first_invalid_profile_attribute<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let created = super::scim_user_create::create(&auth, &json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"patch-invalid-owner@example.com"}), Some("group-reader")).await?;
    let initial = body(&created);
    let id = initial["id"].as_str().unwrap();
    let before = db.tables(&["user", "scimUser", "scimSubject"]).await?;
    for (operations, detail) in [
        (
            json!([{"path":"title","value":{}}]),
            "title: Invalid input: expected string, received object",
        ),
        (
            json!([{"path":"roles","value":[{"value":{}}]}]),
            "roles.0.value: Invalid input: expected string, received object",
        ),
        (
            json!([{"path":"roles","value":[{"value":{}}]},{"path":"title","value":42}]),
            "title: Invalid input: expected string, received number",
        ),
    ] {
        let result = patch(&auth, id, operations, Some("group-reader")).await?;
        assert_eq!(result.status, 400);
        assert_eq!(body(&result)["scimType"], "invalidValue");
        assert_eq!(body(&result)["detail"], detail);
        assert_eq!(
            db.tables(&["user", "scimUser", "scimSubject"]).await?,
            before
        );
    }
    B::close(connection).await
}

async fn scim_user_patch_preserves_nonfinite_sdk_values_until_final_validation<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::utils::json::JsValue;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let initial=body(&super::scim_user_create::create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"patch-number-owner@example.com"}),Some("group-reader")).await?);
    let id = initial["id"].as_str().unwrap();
    let before = db.tables(&["user", "scimUser", "scimSubject"]).await?;
    for (number, kind) in [
        (f64::NAN, "NaN"),
        (f64::INFINITY, "Infinity"),
        (f64::NEG_INFINITY, "-Infinity"),
    ] {
        for (path, nested, field) in [
            ("title", false, "title"),
            ("roles", true, "roles.0.value"),
            ("roles[type eq \"access\"].value", false, "roles.0.value"),
        ] {
            let mut operation = JsValue::from(json!({"path":path}));
            let value = JsValue::Number(number);
            let value = if nested {
                JsValue::Array(vec![JsValue::Object(
                    [("value".into(), value)].into_iter().collect(),
                )])
            } else {
                value
            };
            if let JsValue::Object(fields) = &mut operation {
                _ = fields.insert("value".into(), value);
            }
            let mut input =
                JsValue::from(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}));
            if let JsValue::Object(fields) = &mut input {
                _ = fields.insert("Operations".into(), JsValue::Array(vec![operation]));
            }
            let result = patch_input(&auth, id, input, Some("group-reader")).await?;
            assert_eq!(result.status, 400);
            assert_eq!(
                body(&result)["detail"],
                format!("{field}: Invalid input: expected string, received {kind}")
            );
            assert_eq!(
                db.tables(&["user", "scimUser", "scimSubject"]).await?,
                before
            );
        }
    }
    let mut invalid = JsValue::from(json!({"path":"title"}));
    if let JsValue::Object(fields) = &mut invalid {
        _ = fields.insert("value".into(), JsValue::Number(f64::NAN));
    }
    for (last, expected, detail) in [
        (
            json!({"path":"unknown","value":null}),
            400,
            Some("User PATCH path unknown is not supported"),
        ),
        (json!({"path":"title","value":"Safe"}), 200, None),
    ] {
        let mut input =
            JsValue::from(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}));
        if let JsValue::Object(fields) = &mut input {
            _ = fields.insert(
                "Operations".into(),
                JsValue::Array(vec![invalid.clone(), JsValue::from(last)]),
            );
        }
        let result = patch_input(&auth, id, input, Some("group-reader")).await?;
        assert_eq!(result.status, expected);
        if let Some(detail) = detail {
            assert_eq!(body(&result)["detail"], detail);
            assert_eq!(
                db.tables(&["user", "scimUser", "scimSubject"]).await?,
                before
            );
        } else {
            assert_eq!(body(&result)["title"], "Safe");
        }
    }
    B::close(connection).await
}

fn sized_patch(initial: &Value, size: usize) -> TestResult<Value> {
    let value = "x".repeat(1024);
    let mut patch = json!({"roles":vec![json!({"value":value,"display":value});10],"entitlements":vec![json!({"value":value,"display":value});10],"addresses":vec![json!({"formatted":value,"streetAddress":value});10],"phoneNumbers":vec![json!({"value":"x".repeat(250)});10]});
    patch["phoneNumbers"][9]["value"] = json!("");
    let mut document = json!({"schemas":initial["schemas"],"userName":initial["userName"],"displayName":initial["displayName"],"active":initial["active"],"name":initial["name"],"emails":initial["emails"]});
    document
        .as_object_mut()
        .unwrap()
        .extend(patch.as_object().unwrap().clone());
    let length = serde_json::to_string(&document)?.encode_utf16().count();
    patch["phoneNumbers"][9]["value"] = json!("x".repeat(size - length));
    Ok(patch)
}
async fn scim_user_patch_size_limit_measures_final_normalized_document<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    for (size, variant) in [
        (65535, "plain"),
        (65536, "plain"),
        (65535, "unknown"),
        (65535, "padded"),
        (65535, "unicode"),
    ] {
        let initial = body(&super::scim_user_create::create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":format!("patch-size-{size}-{variant}@example.com")}),Some("group-reader")).await?);
        let id = initial["id"].as_str().unwrap();
        let mut changes = sized_patch(&initial, size)?;
        match variant {
            "unknown" => changes["roles"][0]["ignored"] = json!("x".repeat(70000)),
            "padded" => changes["roles"][0]["value"] = json!(format!(" {} ", "x".repeat(1024))),
            "unicode" => changes["roles"][0]["value"] = json!("🦀".repeat(512)),
            _ => {}
        }
        let before = db.tables(&["user", "scimUser", "scimSubject"]).await?;
        let response = patch(&auth, id, json!([{"value":changes}]), Some("group-reader")).await?;
        assert_eq!(response.status, if size <= 65535 { 200 } else { 400 });
        let value = body(&response);
        if size > 65535 {
            assert_eq!(
                value["detail"],
                "User: SCIM User attributes exceed the supported serialized size"
            );
            assert_eq!(value["scimType"], "invalidValue");
            assert_eq!(
                db.tables(&["user", "scimUser", "scimSubject"]).await?,
                before
            );
        } else {
            assert_eq!(value["id"], id);
            assert_eq!(value["roles"].as_array().unwrap().len(), 10);
            assert!(value["roles"][0].get("ignored").is_none());
            assert_eq!(
                value["roles"][0]["value"],
                if variant == "unicode" {
                    "🦀".repeat(512)
                } else {
                    "x".repeat(1024)
                }
            );
            assert!(serde_json::to_string(&value)?.encode_utf16().count() > size);
        }
        let read = super::scim_user_read::read(&auth, id, &json!({}), Some("group-reader")).await?;
        assert_eq!(read.status, 200);
        assert_eq!(body(&read), if size <= 65535 { value } else { initial });
    }
    B::close(connection).await
}
