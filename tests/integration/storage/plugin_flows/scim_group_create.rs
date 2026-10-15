//! Group creation persists isolated resources and rolls back invalid memberships.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(
    scim_group_create_persists_members_and_rolls_back_invalid_ownership,
    scim_group_input_preserves_schema_order_and_member_type_diagnostics,
    scim_group_sdk_nan_preserves_diagnostic_type
);
postgres_tests!(
    scim_group_create_persists_members_and_rolls_back_invalid_ownership,
    scim_group_input_preserves_schema_order_and_member_type_diagnostics,
    scim_group_sdk_nan_preserves_diagnostic_type
);
pub(super) async fn create<S: AuthSchema>(
    auth: &Alibi<S>,
    value: &Value,
    query: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(
        auth.dispatch_endpoint(
            ScimPlugin::create_group_endpoint()
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
async fn scim_group_create_persists_members_and_rolls_back_invalid_ownership<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    let input = json!({"schemas":[schema],"displayName":" Staff ","externalId":"external-staff","members":[{"value":"member-a"},{"value":"member-a","type":"USER"},{"value":"member-c"}]});
    for input in [json!({}), json!({"schemas":[schema],"displayName":" "})] {
        assert_eq!(create(&auth, &input, &json!({}), None).await?.status, 400);
    }
    let whitespace =
        json!({"schemas":[schema],"displayName":"Whitespace","members":[{"value":" "}]});
    assert_eq!(
        create(&auth, &whitespace, &json!({}), None).await?.status,
        401
    );
    assert_eq!(create(&auth, &input, &json!({}), None).await?.status, 401);
    assert_eq!(
        create(&auth, &input, &json!({}), Some("users-reader"))
            .await?
            .status,
        403
    );

    assert_eq!(db.table("scimConnectionBinding").await?, "[]");
    let denied = create(&auth, &whitespace, &json!({}), Some("group-reader")).await?;
    assert_eq!(denied.status, 400);
    assert_eq!(
        body(&denied)["detail"],
        "Group members must reference a SCIM User"
    );
    seed(&db, &auth).await?;
    let response = create(&auth, &input, &json!({}), Some("group-reader")).await?;
    assert_eq!(response.status, 201);
    let resource = body(&response);
    let id = resource["id"].as_str().unwrap();
    assert_eq!(resource["displayName"], "Staff");
    assert_eq!(resource["externalId"], "external-staff");
    assert_eq!(
        resource["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["value"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["member-a", "member-c"]
    );
    assert_eq!(
        response.headers.get("location").map(String::as_str),
        Some(format!("{ORIGIN}/api/auth/scim/v2/Groups/{id}").as_str())
    );
    assert_eq!(
        response.headers.get("content-location"),
        response.headers.get("location")
    );
    let before = db.table("scimGroup").await?;
    let members = db.table("scimGroupMember").await?;
    let subjects = db.table("scimSubject").await?;
    for (value, detail) in [
        (
            json!({"schemas":[schema],"displayName":"STAFF"}),
            "SCIM Group displayName already exists",
        ),
        (
            json!({"schemas":[schema],"displayName":"Second","externalId":"external-staff"}),
            "SCIM Group externalId already exists",
        ),
        (
            json!({"schemas":[schema],"displayName":"Invalid","members":[{"value":"member-b"}]}),
            "One or more Group members are invalid",
        ),
    ] {
        let result = create(&auth, &value, &json!({}), Some("group-reader")).await?;
        assert_eq!(
            result.status,
            if detail.starts_with("One") { 400 } else { 409 }
        );
        assert_eq!(body(&result)["detail"], detail);
        assert_eq!(db.table("scimGroup").await?, before);
        assert_eq!(db.table("scimGroupMember").await?, members);
        assert_eq!(db.table("scimSubject").await?, subjects);
    }
    let foreign = create(
        &auth,
        &json!({"schemas":[schema],"displayName":"Staff","externalId":"external-staff"}),
        &json!({}),
        Some("other-reader"),
    )
    .await?;
    assert_eq!(foreign.status, 201);
    assert_eq!(body(&foreign)["members"], json!([]));
    let projected = create(
        &auth,
        &json!({"schemas":[schema],"displayName":"Projected","members":[{"value":"member-a"}]}),
        &json!({"attributes":"displayName"}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(projected.status, 201);
    assert!(body(&projected).get("members").is_none());
    assert!(body(&projected).get("meta").is_none());
    let projected_id = body(&projected)["id"].as_str().unwrap().to_owned();
    assert_eq!(
        body(
            &super::scim_group_read::read(&auth, &projected_id, &json!({}), Some("group-reader"))
                .await?
        )["members"][0]["value"],
        "member-a"
    );
    let mut req = request(
        "/scim/v2/Groups",
        Some(json!({"schemas":[schema],"displayName":"HTTP group"})),
        "",
    );
    req.method = HttpMethod::Post;
    _ = req
        .headers
        .insert("content-type".into(), "application/scim+json".into());
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    let http = call(&auth, req, 201).await;
    assert_eq!(body(&http)["displayName"], "HTTP group");
    assert_eq!(
        http.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let configured = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(GroupProjection(fail.clone()))),
        )
        .build()
        .await?;
    let callback_body = json!({"schemas":[schema],"displayName":"Callback success","members":[{"value":"member-a"}]});
    assert_eq!(
        create(
            &configured,
            &callback_body,
            &json!({}),
            Some("group-reader")
        )
        .await?
        .status,
        201
    );
    let users = db.table("user").await?;
    assert!(users.contains("Projected inactive"));
    let groups = db.table("scimGroup").await?;
    let memberships = db.table("scimGroupMember").await?;
    let subjects = db.table("scimSubject").await?;
    let bindings = db.table("scimConnectionBinding").await?;
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut callback_body = callback_body;
    callback_body["displayName"] = json!("Callback failure");
    let failure = create(
        &configured,
        &callback_body,
        &json!({}),
        Some("group-reader"),
    )
    .await?;
    assert_eq!(failure.status, 500);
    assert_eq!(
        body(&failure)["detail"],
        "SCIM projection reconciliation failed"
    );
    assert_eq!(db.table("user").await?, users);
    assert_eq!(db.table("scimGroup").await?, groups);
    assert_eq!(db.table("scimGroupMember").await?, memberships);
    assert_eq!(db.table("scimSubject").await?, subjects);
    assert_eq!(db.table("scimConnectionBinding").await?, bindings);
    _ = db
        .execute(
            "UPDATE \"scimGroup\" SET \"provisioningDomainId\"='drifted' WHERE \"id\"=$1",
            &[id],
        )
        .await?;
    assert_eq!(
        create(
            &auth,
            &json!({"schemas":[schema],"displayName":"After drift"}),
            &json!({}),
            Some("group-reader")
        )
        .await?
        .status,
        409
    );
    Ok(())
}

pub(super) struct GroupProjection(pub(super) Arc<std::sync::atomic::AtomicBool>);
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::plugins::scim::ScimProjection<S> for GroupProjection {
    async fn reconcile_user(
        &self,
        input: &alibi::plugins::scim::ScimProjectedUserState,
        database: &dyn alibi::store::AuthTransaction<S>,
    ) -> alibi::AuthResult<()> {
        let fail = self.0.load(std::sync::atomic::Ordering::SeqCst);
        _ = database
            .update_user(
                &input.user_id,
                alibi::UpdateUser {
                    name: Some(
                        if fail {
                            "Should roll back"
                        } else if input.active {
                            "Projected active"
                        } else {
                            "Projected inactive"
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
            )
            .await?;
        if fail {
            return Err(alibi::AuthError::internal(
                "application rejected projection",
            ));
        }
        Ok(())
    }
}

pub(super) async fn seed<S: AuthSchema>(db: &Db, auth: &Alibi<S>) -> TestResult {
    let signed = body(&signup(auth, "group-create-owner@example.com").await);
    let uid = signed["user"]["id"].as_str().unwrap();
    _=db.execute("INSERT INTO \"scimSubject\" (\"id\",\"userId\",\"revision\",\"createdAt\",\"updatedAt\") VALUES ('group-create-subject',$1,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[uid]).await?;
    for (id, cid, domain, display) in [
        ("member-a", "conn-a", "tenant-a", "Inactive member"),
        ("member-b", "conn-b", "tenant-a", "Foreign member"),
        ("member-c", "conn-a", "tenant-b", "Other domain member"),
    ] {
        _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,$4,$1,$1,$1,'group-create-owner@example.com','[]','[]',$5,$5,'[]',false,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain,uid,display]).await?;
    }
    Ok(())
}

async fn scim_group_input_preserves_schema_order_and_member_type_diagnostics<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    let mut cases = vec![
        (json!({"schemas":[schema],"externalId":false,"displayName":0}), "[body.externalId] Invalid input: expected string, received boolean; [body.displayName] Invalid input: expected string, received number".to_owned()),
        (json!({"schemas":[schema],"externalId":"","displayName":" "}), "[body.externalId] Too small: expected string to have >=1 characters; [body.displayName] Too small: expected string to have >=1 characters".to_owned()),
    ];
    for (value, kind) in [
        (json!(42), "number"),
        (json!(null), "null"),
        (json!(false), "boolean"),
        (json!([]), "array"),
        (json!({}), "object"),
    ] {
        cases.push((json!({"schemas":[schema],"displayName":"Group","members":[{"value":"member","type":value}]}), format!("[body.members.0.type] Invalid input: expected string, received {kind}")));
    }
    for (input, detail) in cases {
        for response in [
            create(&auth, &input, &json!({}), None).await?,
            super::scim_group_replace::replace(&auth, "missing", &input, &json!({}), None).await?,
        ] {
            assert_eq!(response.status, 400);
            assert_eq!(body(&response)["detail"], detail);
            assert_eq!(body(&response)["scimType"], "invalidValue");
        }
    }
    let valid = json!({"schemas":[schema],"displayName":"Group","members":[{"value":"member","type":"USER"}]});
    assert_eq!(create(&auth, &valid, &json!({}), None).await?.status, 401);
    assert_eq!(
        super::scim_group_replace::replace(&auth, "missing", &valid, &json!({}), None)
            .await?
            .status,
        401
    );
    for table in [
        "user",
        "scimGroup",
        "scimGroupMember",
        "scimConnectionBinding",
    ] {
        assert_eq!(db.table(table).await?, "[]");
    }
    B::close(connection).await
}

async fn scim_group_sdk_nan_preserves_diagnostic_type<B: Backend>(db: Db) -> TestResult {
    use alibi::utils::json::JsValue;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    for (number, kind) in [
        (f64::NAN, "NaN"),
        (f64::INFINITY, "Infinity"),
        (f64::NEG_INFINITY, "-Infinity"),
        (42.0, "number"),
    ] {
        for (extra, path, field) in [
            (
                json!({"externalId":null}),
                vec!["externalId"],
                Some("externalId"),
            ),
            (
                json!({"displayName":null}),
                vec!["displayName"],
                Some("displayName"),
            ),
            (
                json!({"members":[{"value":null}]}),
                vec!["members", "0", "value"],
                Some("members.0.value"),
            ),
            (
                json!({"members":[{"value":"member","type":null}]}),
                vec!["members", "0", "type"],
                Some("members.0.type"),
            ),
            (json!({"ignored":null}), vec!["ignored"], None),
        ] {
            let mut input = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Group"});
            input
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let mut input = JsValue::from(input);
            let mut target = &mut input;
            for key in path {
                target = match target {
                    JsValue::Object(values) => values.get_mut(key).unwrap(),
                    JsValue::Array(values) => &mut values[key.parse::<usize>().unwrap()],
                    _ => panic!("trusted numeric path"),
                };
            }
            *target = JsValue::Number(number);
            for endpoint in [
                ScimPlugin::create_group_endpoint(),
                ScimPlugin::replace_group_endpoint("missing")?,
            ] {
                let rejected = auth
                    .dispatch_endpoint(
                        endpoint.with_body_value(input.clone()),
                        EndpointOptions::default(),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    rejected.error.status_code(),
                    if field.is_some() { 400 } else { 401 }
                );
                if let Some(field) = field {
                    assert_eq!(
                        rejected
                            .body
                            .as_deref()
                            .unwrap()
                            .get("detail")
                            .and_then(JsValue::as_str),
                        Some(
                            format!(
                                "[body.{field}] Invalid input: expected string, received {kind}"
                            )
                            .as_str()
                        )
                    );
                }
            }
        }
    }
    for table in [
        "user",
        "scimGroup",
        "scimGroupMember",
        "scimConnectionBinding",
    ] {
        assert_eq!(db.count(table).await?, 0);
    }
    B::close(connection).await
}
