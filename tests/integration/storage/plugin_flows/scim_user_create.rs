//! User provisioning persists canonical profiles and rejects duplicate identities.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
backend_tests!(scim_user_create_persists_canonical_identity_and_reuses_tombstones);
postgres_tests!(scim_user_create_persists_canonical_identity_and_reuses_tombstones);
pub(super) async fn create<S: AuthSchema>(
    auth: &Alibi<S>,
    value: &Value,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::create_user_endpoint().with_body(value)?,
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
async fn scim_user_create_persists_canonical_identity_and_reuses_tombstones<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    let input = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":" Alice@example.com ","externalId":"directory-alice","name":{"givenName":" Alice ","familyName":" Example "},"emails":[{"value":"personal@example.com","type":"home"},{"value":"Work@example.com","type":"WORK"}],"title":[" Engineer "]});
    assert_eq!(create(&auth, &input, None).await?.status, 401);
    assert_eq!(
        create(&auth, &input, Some("users-reader")).await?.status,
        403
    );
    let response = create(&auth, &input, Some("group-reader")).await?;
    assert_eq!(response.status, 201);
    let resource = body(&response);
    assert_eq!(resource["userName"], "Alice@example.com");
    assert_eq!(resource["displayName"], "Alice Example");
    assert_eq!(resource["emails"][1]["primary"], true);
    assert_eq!(resource["title"], "Engineer");
    assert_eq!(resource["active"], true);
    let rows: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["email"], "work@example.com");
    assert_eq!(rows[0]["name"], "Alice Example");
    assert!(rows[0]["emailVerified"] == false || rows[0]["emailVerified"] == 0);
    let source: Value = serde_json::from_str(&db.table("scimUser").await?)?;
    assert_eq!(source[0]["userId"], rows[0]["id"]);
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["profileSourceId"], resource["id"]);
    assert_eq!(subject[0]["revision"], 2);
    let duplicate = create(&auth, &input, Some("group-reader")).await?;
    assert_eq!(duplicate.status, 409);
    assert_eq!(body(&duplicate)["scimType"], "uniqueness");
    for candidate in [
        json!({"schemas":input["schemas"],"userName":"Other","externalId":"directory-alice","emails":[{"value":"other@example.com"}]}),
        json!({"schemas":input["schemas"],"userName":"Other","externalId":"other","emails":input["emails"]}),
    ] {
        let collision = create(&auth, &candidate, Some("group-reader")).await?;
        assert_eq!(collision.status, 409);
        assert_eq!(body(&collision)["scimType"], "uniqueness");
    }
    let mut before = Vec::new();
    for table in [
        "user",
        "scimUser",
        "scimSubject",
        "scimIdentityTombstone",
        "scimConnectionBinding",
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
    assert_eq!(
        create(
            &configured,
            &json!({"schemas":input["schemas"],"userName":"rolled-back@example.com"}),
            Some("group-reader")
        )
        .await?
        .status,
        500
    );
    for (table, expected) in &before {
        assert_eq!(db.table(table).await?, *expected);
    }
    let id = resource["id"].as_str().unwrap();
    assert_eq!(
        super::scim_user_delete::delete(&configured, id, Some("group-reader"))
            .await?
            .status,
        500
    );
    for (table, expected) in &before {
        assert_eq!(db.table(table).await?, *expected);
    }
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        super::scim_user_delete::delete(&configured, id, Some("group-reader"))
            .await?
            .status,
        204
    );
    let tombstones: Value = serde_json::from_str(&db.table("scimIdentityTombstone").await?)?;
    assert_eq!(tombstones.as_array().unwrap().len(), 1);
    assert_eq!(tombstones[0]["profile"], "manage");
    let mut restored_input = input.clone();
    restored_input["emails"] = json!([{"value":"new-work@example.com","type":"work"}]);
    let restored = create(&configured, &restored_input, Some("group-reader")).await?;
    assert_eq!(restored.status, 201);
    assert_ne!(body(&restored)["id"], resource["id"]);
    let revived: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(revived.as_array().unwrap().len(), 1);
    assert_eq!(revived[0]["id"], rows[0]["id"]);
    assert_eq!(revived[0]["email"], "new-work@example.com");
    assert_eq!(revived[0]["name"], "Projected active");
    assert_eq!(db.table("scimIdentityTombstone").await?, "[]");
    let mut req = request(
        "/scim/v2/Users",
        Some(json!({"schemas":input["schemas"],"userName":"http@example.com","active":false})),
        "",
    );
    req.method = HttpMethod::Post;
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    _ = req
        .headers
        .insert("content-type".into(), "application/scim+json".into());
    let http = call(&configured, req, 201).await;
    assert_eq!(body(&http)["active"], false);
    let resolved = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(super::scim_group_create::GroupProjection(fail)))
                .identity(Arc::new(CreateIdentity)),
        )
        .build()
        .await?;
    let alias = json!({"schemas":input["schemas"],"userName":" Alias ","emails":[{"value":"Alias@example.com"}]});
    let mut before = Vec::new();
    for table in ["user", "scimUser", "scimSubject"] {
        before.push((table, db.table(table).await?));
    }
    for (external, status, detail) in [
        ("resolve-fails", 500, "SCIM identity resolution failed"),
        (
            "link-missing",
            409,
            "The resolved Better Auth User does not exist",
        ),
        (
            "link-manage",
            409,
            "Another SCIM source already manages this User profile",
        ),
    ] {
        let mut value = alias.clone();
        value["externalId"] = json!(external);
        let denied = create(&resolved, &value, Some("other-reader")).await?;
        assert_eq!(denied.status, status);
        assert_eq!(body(&denied)["detail"], detail);
        for (table, expected) in &before {
            assert_eq!(db.table(table).await?, *expected);
        }
    }
    let mut value = alias;
    value["externalId"] = json!("link-preserve");
    let linked = create(&resolved, &value, Some("other-reader")).await?;
    assert_eq!(linked.status, 201);
    assert_eq!(body(&linked)["userName"], "Alias");
    let linked_sources: Value = serde_json::from_str(&db.table("scimUser").await?)?;
    assert_eq!(linked_sources.as_array().unwrap().len(), 3);
    let linked_source = linked_sources
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["connectionId"] == "conn-b")
        .unwrap();
    assert_eq!(linked_source["userId"], rows[0]["id"]);
    let linked_users: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(linked_users.as_array().unwrap().len(), 2);
    assert!(
        linked_users
            .as_array()
            .unwrap()
            .iter()
            .any(|user| user["id"] == rows[0]["id"] && user["email"] == "new-work@example.com")
    );
    value["userName"] = json!("Alias2");
    value["externalId"] = json!("link-preserve-2");
    let repeated = create(&resolved, &value, Some("other-reader")).await?;
    assert_eq!(repeated.status, 409);
    assert_eq!(
        body(&repeated)["detail"],
        "This connection already provisions the resolved Better Auth User"
    );
    Ok(())
}

struct CreateIdentity;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::plugins::scim::ScimIdentity<S> for CreateIdentity {
    async fn resolve_user(
        &self,
        input: &alibi::plugins::scim::ScimIdentityResolutionInput,
        database: &dyn alibi::store::AuthStore<S>,
    ) -> alibi::AuthResult<alibi::plugins::scim::ScimIdentityResolution> {
        use alibi::plugins::scim::ScimIdentityResolution as Resolution;
        use alibi::{AuthError, AuthUser};
        let external = input.resource["externalId"].as_str().unwrap_or("");
        if external == "resolve-fails" {
            return Err(AuthError::internal("application rejected resolution"));
        }
        if external == "link-missing" {
            return Ok(Resolution::Link {
                user_id: "missing-user".into(),
                manage_profile: false,
            });
        }
        if !matches!(
            input.resource["userName"].as_str(),
            Some("Alias" | "Alias2")
        ) || input.resource["primaryEmail"] != "alias@example.com"
        {
            return Err(AuthError::internal("incorrect resolver resource"));
        }
        let user = database
            .get_user_by_email("new-work@example.com")
            .await?
            .ok_or_else(|| AuthError::internal("resolver target missing"))?;
        Ok(Resolution::Link {
            user_id: user.id().to_string(),
            manage_profile: external == "link-manage",
        })
    }
    async fn reconcile_user(
        &self,
        _input: &alibi::plugins::scim::ScimIdentityState,
        _database: &dyn alibi::store::AuthTransaction<S>,
    ) -> alibi::AuthResult<()> {
        Ok(())
    }
}
