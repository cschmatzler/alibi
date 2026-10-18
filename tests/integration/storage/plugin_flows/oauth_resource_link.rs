//! Durable resource membership admits the linked client under the default provider policy.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
#[path = "../../../fixtures/oauth/resource-privileges.rs"]
mod resource_privileges;

backend_tests!(
    oauth_resource_privileges_gate_catalog_and_links,
    oauth_resource_link_persists_unique_membership_and_admits_linked_client
);
async fn oauth_resource_privileges_gate_catalog_and_links<B: Backend>(db: Db) -> TestResult {
    use alibi::AuthSession as _;
    use alibi::plugins::OAuthProviderConfig;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(resource_privileges::ResourcePrivileges::default());
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                resource_privileges: Some(policy.clone()),
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    let owner = signup(&auth, "resource-policy-owner@example.test").await;
    let other = signup(&auth, "resource-policy-other@example.test").await;
    let options = |cookie: String, decision: &str| EndpointOptions {
        headers: Some(
            [
                ("cookie".into(), cookie),
                ("x-resource-decision".into(), decision.into()),
                ("x-policy-caller".into(), "native".into()),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    };
    let identifier = "https://api.fixture.test/privileges";
    let created = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":identifier,"allowedScopes":["email"]}),
        )?,
        options(cookies(&owner), "true"),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&created)["identifier"], identifier);
    let client = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "createOAuthClient").with_body(&json!({"client_name":"Resource policy client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,
        options(cookies(&owner), "false"),
    )).await?.into_response()?;
    let id = body(&client)["client_id"].as_str().unwrap().to_owned();
    let _ = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_link_client_resource_endpoint(identifier, &id)?,
        options(cookies(&other), "true"),
    ))
    .await?;
    policy.calls.lock().unwrap().clear();
    let params = json!({"identifier":"https%3A%2F%2Fapi.fixture.test%2Fprivileges","client_id":id});
    let operations = [
        (
            "adminCreateOAuthResource",
            "create",
            json!({"identifier":"urn:fixture:new-policy"}),
            None,
        ),
        ("adminListOAuthResources", "list", json!({}), None),
        (
            "adminGetOAuthResource",
            "read",
            json!({}),
            Some(params.clone()),
        ),
        (
            "adminUpdateOAuthResource",
            "update",
            json!({"name":"Allowed","identifier":"urn:fixture:ignored","unknown":"filtered"}),
            Some(params.clone()),
        ),
        (
            "adminDeleteOAuthResource",
            "delete",
            json!({}),
            Some(params.clone()),
        ),
        (
            "adminLinkClientResource",
            "link",
            json!({}),
            Some(params.clone()),
        ),
        (
            "adminUnlinkClientResource",
            "unlink",
            json!({}),
            Some(params.clone()),
        ),
    ];
    let tables = ["oauthResource", "oauthClientResource", "oauthClient"];
    let before = db.tables(&tables).await?;
    for (operation, action, input, params) in &operations {
        for (decision, status, api) in [
            ("false", 401, true),
            ("native-error", 403, true),
            ("api-error", 403, true),
            ("upstream-error", 503, true),
            ("ordinary-error", 500, false),
        ] {
            let mut endpoint =
                ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(input)?;
            if let Some(params) = params {
                endpoint = endpoint.with_params(params)?;
            }
            let error =
                Box::pin(auth.dispatch_endpoint(endpoint, options(cookies(&other), decision)))
                    .await
                    .unwrap_err();
            assert_eq!(error.error.status_code(), status, "{operation}/{decision}");
            assert_eq!(alibi::endpoint::is_endpoint_api_error(&error.error), api);
            if decision == "false" {
                assert!(error.body_absent);
            }
            let calls = std::mem::take(&mut *policy.calls.lock().unwrap());
            assert_eq!(calls.len(), 1);
            let call = &calls[0];
            assert_eq!(call["action"], *action);
            assert_eq!(
                call["resourceId"],
                if params.is_some() {
                    json!(identifier)
                } else {
                    Value::Null
                }
            );
            assert_eq!(call["decision"], decision);
            assert_eq!(call["caller"], "native");
            assert_eq!(call["user"]["id"], body(&other)["user"]["id"]);
            assert_eq!(call["user"]["email"], "resource-policy-other@example.test");
            assert_eq!(call["session"]["userId"], call["user"]["id"]);
            let session = auth
                .store()
                .get_session(call["session"]["token"].as_str().unwrap())
                .await?
                .unwrap();
            assert_eq!(json!(session.id()), call["session"]["id"]);
            assert_eq!(db.tables(&tables).await?, before);
        }
    }
    // Schema and session checks precede the callback; URI validation and lookups follow it.
    for (operation, input, params, cookie, decision, status, called) in [
        (
            "adminCreateOAuthResource",
            json!({"identifier":42}),
            json!({}),
            cookies(&other),
            "false",
            400,
            false,
        ),
        (
            "adminCreateOAuthResource",
            json!({"identifier":"urn:fixture:new","accessTokenTtl":0}),
            json!({}),
            cookies(&other),
            "false",
            400,
            false,
        ),
        (
            "adminUpdateOAuthResource",
            json!({"name":42}),
            params.clone(),
            cookies(&other),
            "false",
            400,
            false,
        ),
        (
            "adminGetOAuthResource",
            json!({}),
            params.clone(),
            String::new(),
            "false",
            401,
            false,
        ),
        (
            "adminCreateOAuthResource",
            json!({"identifier":"/relative"}),
            json!({}),
            cookies(&other),
            "false",
            401,
            true,
        ),
        (
            "adminCreateOAuthResource",
            json!({"identifier":identifier}),
            json!({}),
            cookies(&other),
            "false",
            401,
            true,
        ),
        (
            "adminGetOAuthResource",
            json!({}),
            json!({"identifier":"urn:fixture:missing"}),
            cookies(&other),
            "false",
            401,
            true,
        ),
        (
            "adminLinkClientResource",
            json!({}),
            json!({"identifier":"urn:fixture:missing","client_id":"missing"}),
            cookies(&other),
            "false",
            401,
            true,
        ),
        (
            "adminLinkClientResource",
            json!({}),
            json!({"identifier":identifier,"client_id":"missing"}),
            cookies(&other),
            "false",
            401,
            true,
        ),
        (
            "adminCreateOAuthResource",
            json!({"identifier":"/relative"}),
            json!({}),
            cookies(&other),
            "true",
            400,
            true,
        ),
        (
            "adminCreateOAuthResource",
            json!({"identifier":identifier}),
            json!({}),
            cookies(&other),
            "true",
            400,
            true,
        ),
        (
            "adminGetOAuthResource",
            json!({}),
            json!({"identifier":"bad%XX"}),
            cookies(&other),
            "true",
            404,
            true,
        ),
        (
            "adminLinkClientResource",
            json!({}),
            json!({"identifier":"urn:fixture:missing","client_id":"missing"}),
            cookies(&other),
            "true",
            404,
            true,
        ),
        (
            "adminLinkClientResource",
            json!({}),
            json!({"identifier":identifier,"client_id":"missing"}),
            cookies(&other),
            "true",
            404,
            true,
        ),
    ] {
        let error = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", operation)
                    .with_body(&input)?
                    .with_params(&params)?,
                options(cookie, decision),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), status, "{operation}/{decision}");
        assert_eq!(policy.calls.lock().unwrap().len(), usize::from(called));
        policy.calls.lock().unwrap().clear();
        assert_eq!(db.tables(&tables).await?, before);
    }
    // Physical cookies do not fabricate a logical session when endpoint headers are absent.
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_list_oauth_resources_endpoint(),
        EndpointOptions {
            request: Some(request("/admin/oauth2/resources", None, &cookies(&other))),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert!(policy.calls.lock().unwrap().is_empty());
    let row = auth.store().get_oauth_resource(identifier).await?.unwrap();
    let link = auth
        .store()
        .list_oauth_client_resources(&id)
        .await?
        .remove(0);
    // The operator does not add ownership rules: the other authenticated user can manage this catalog.
    for (operation, action, input, params) in &operations {
        let mut endpoint =
            ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(input)?;
        if let Some(params) = params {
            endpoint = endpoint.with_params(params)?;
        }
        // Delete last so reads/updates/link validation use a real row.
        if *action == "delete" {
            continue;
        }
        let output = Box::pin(auth.dispatch_endpoint(endpoint, options(cookies(&other), "true")))
            .await?
            .into_response()?;
        assert_eq!(output.status, 200);
        assert_eq!(
            policy.calls.lock().unwrap().pop().unwrap()["action"],
            *action
        );
        match *action {
            "create" => assert!(
                auth.store()
                    .get_oauth_resource("urn:fixture:new-policy")
                    .await?
                    .is_some()
            ),
            "list" => assert_eq!(body(&output).as_array().unwrap().len(), 2),
            "read" => assert_eq!(body(&output)["id"], row.id),
            "update" => {
                let updated = auth.store().get_oauth_resource(identifier).await?.unwrap();
                assert_eq!(updated.id, row.id);
                assert_eq!(updated.identifier, identifier);
                assert_eq!(updated.metadata["name"], "Allowed");
                assert!(updated.metadata.get("unknown").is_none());
                assert_eq!(updated.metadata["allowedScopes"], json!(["email"]));
            }
            "link" => {
                assert_eq!(body(&output), json!({"linked":true,"alreadyLinked":true}));
                assert_eq!(
                    auth.store().list_oauth_client_resources(&id).await?[0].id,
                    link.id
                );
            }
            "unlink" => assert!(
                auth.store()
                    .list_oauth_client_resources(&id)
                    .await?
                    .is_empty()
            ),
            other => return Err(format!("unexpected resource action {other}").into()),
        }
    }
    for _ in 0..2 {
        let output = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_unlink_client_resource_endpoint(
                "urn:fixture:missing",
                "missing",
            )?,
            options(cookies(&other), "true"),
        ))
        .await?
        .into_response()?;
        assert_eq!(body(&output), json!({"unlinked":true}));
    }
    let _ = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_link_client_resource_endpoint(identifier, &id)?,
        options(cookies(&other), "true"),
    ))
    .await?;
    let _ = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_delete_oauth_resource_endpoint(identifier)?,
        options(cookies(&other), "true"),
    ))
    .await?;
    assert!(auth.store().get_oauth_resource(identifier).await?.is_none());
    assert!(
        auth.store()
            .list_oauth_client_resources(&id)
            .await?
            .is_empty()
    );
    assert!(auth.store().get_oauth_client(&id).await?.is_some());
    Ok(())
}
async fn oauth_resource_link_persists_unique_membership_and_admits_linked_client<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "resource-link-owner@example.test").await;
    let resource = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":"https://api.fixture.test/link","allowedScopes":["email"]}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(resource.status, 200);
    let client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Linked client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&client)["client_id"].as_str().unwrap().to_owned();
    let other = signup(&auth, "resource-link-other@example.test").await;
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":"https://api.fixture.test/link","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let denied = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&denied)["url"].as_str().unwrap())?;
    assert_eq!(
        url.query_pairs()
            .find(|(name, _)| name == "error")
            .unwrap()
            .1,
        "invalid_target"
    );
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource",
        ])
        .await?;
    for (identifier, client_id, cookie, status, error) in [
        (
            "urn:fixture:missing",
            id.as_str(),
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            "https://api.fixture.test/link",
            "unknown-client",
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            "https://api.fixture.test/link",
            id.as_str(),
            String::new(),
            401,
            "",
        ),
    ] {
        let rejected = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_link_client_resource_endpoint(identifier, client_id)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), status);
        if !error.is_empty() {
            assert_eq!(
                rejected
                    .body
                    .as_ref()
                    .unwrap()
                    .get("error")
                    .unwrap()
                    .as_str(),
                Some(error)
            );
        }
        assert_eq!(
            before,
            db.tables(&[
                "user",
                "account",
                "session",
                "verification",
                "jwks",
                "oauthClient",
                "oauthConsent",
                "oauthResource",
                "oauthClientResource"
            ])
            .await?
        );
    }
    let mut http = request(
        &format!("/admin/oauth2/resources/https%3A%2F%2Fapi.fixture.test%2Flink/clients/{id}"),
        None,
        &cookies(&owner),
    );
    http.method = alibi::HttpMethod::Post;
    assert_eq!(Box::pin(auth.handle_request(http)).await?.status, 404);
    let start = chrono::Utc::now().timestamp_millis();
    let result = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "adminLinkClientResource").with_params(
            &json!({"identifier":"https%3A%2F%2Fapi.fixture.test%2Flink","client_id":id}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&other))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200, "resource linking must be registered");
    assert_eq!(body(&response), json!({"linked":true}));
    let rows = auth.store().list_oauth_client_resources(&id).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].client_id, id);
    assert_eq!(rows[0].resource_id, "https://api.fixture.test/link");
    assert_eq!(rows[0].metadata, Value::Null);
    let created = rows[0].created_at.unwrap().timestamp_millis();
    assert!(created >= start);
    assert!(created <= chrono::Utc::now().timestamp_millis());
    let row_id = rows[0].id.clone();
    let linked_state = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource",
        ])
        .await?;
    let duplicate = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_link_client_resource_endpoint(
            "https://api.fixture.test/link",
            &id,
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(duplicate.status, 200);
    assert_eq!(
        body(&duplicate),
        json!({"linked":true,"alreadyLinked":true})
    );
    assert_eq!(
        auth.store().list_oauth_client_resources(&id).await?[0].id,
        row_id
    );
    let admitted = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&admitted)["url"].as_str().unwrap())?;
    assert_eq!(url.path(), "/login");
    assert_eq!(
        linked_state,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource"
        ])
        .await?
    );
    let removed = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_delete_oauth_resource_endpoint("https://api.fixture.test/link")?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&removed), json!({"deleted":true}));
    assert!(
        auth.store()
            .list_oauth_client_resources(&id)
            .await?
            .is_empty()
    );
    assert_eq!(db.count("oauthClientResource").await?, 0);
    assert!(auth.store().get_oauth_client(&id).await?.is_some());
    Ok(())
}
