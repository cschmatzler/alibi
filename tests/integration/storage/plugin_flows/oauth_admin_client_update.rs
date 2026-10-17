//! Server-only administrative patches retain ownership and replace opaque metadata.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
#[path = "../../../fixtures/oauth/client-privileges.rs"]
mod client_privileges;
backend_tests!(
    oauth_client_privileges_gate_management_before_lookup_and_writes,
    oauth_admin_update_replaces_operator_metadata_and_preserves_secret
);
async fn oauth_client_privileges_gate_management_before_lookup_and_writes<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession as _;
    use alibi::plugins::OAuthProviderConfig;
    use std::sync::Arc;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(client_privileges::ClientPrivileges::default());
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_privileges: Some(policy.clone()),
                scopes: vec!["api:read".into(), "api:write".into()],
                cached_trusted_clients: ["cached-client".into()].into(),
                allow_dynamic_client_registration: true,
                allow_unauthenticated_client_registration: true,
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    let owner = signup(&auth, "client-policy-owner@example.test").await;
    let other = signup(&auth, "client-policy-other@example.test").await;
    let options = |cookie: String, decision: &str| EndpointOptions {
        headers: Some(
            [
                ("cookie".into(), cookie),
                ("x-client-decision".into(), decision.into()),
                ("x-policy-caller".into(), "native".into()),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    };
    let metadata = json!({"client_name":"Original","grant_types":["client_credentials"]});
    let created = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_client_endpoint(&metadata)?,
        options(cookies(&owner), "true"),
    ))
    .await?
    .into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let initial = auth.store().get_oauth_client(&id).await?.unwrap();
    let before = db.tables(&["oauthClient"]).await?;
    policy.calls.lock().unwrap().clear();
    let operations = [
        ("createOAuthClient", "create", metadata.clone(), None),
        ("adminCreateOAuthClient", "create", metadata.clone(), None),
        ("registerOAuthClient", "create", metadata.clone(), None),
        (
            "getOAuthClient",
            "read",
            json!({}),
            Some(json!({"client_id":id})),
        ),
        ("getOAuthClients", "list", json!({}), None),
        (
            "updateOAuthClient",
            "update",
            json!({"client_id":id,"update":{"client_name":"Changed"}}),
            None,
        ),
        (
            "adminUpdateOAuthClient",
            "update",
            json!({"client_id":id,"update":{"client_name":"Changed"}}),
            None,
        ),
        (
            "rotateClientSecret",
            "rotate",
            json!({"client_id":id}),
            None,
        ),
        ("deleteOAuthClient", "delete", json!({"client_id":id}), None),
    ];
    for (operation, action, input, query) in &operations {
        for (decision, status, api) in [
            ("false", 401, true),
            ("native-error", 403, true),
            ("api-error", 403, true),
            ("upstream-error", 503, true),
            ("ordinary-error", 500, false),
        ] {
            let mut endpoint =
                ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(input)?;
            if let Some(query) = query {
                endpoint = endpoint.with_query(query)?;
            }
            let error =
                Box::pin(auth.dispatch_endpoint(endpoint, options(cookies(&owner), decision)))
                    .await
                    .unwrap_err();
            assert_eq!(error.error.status_code(), status, "{operation}/{decision}");
            assert_eq!(alibi::endpoint::is_endpoint_api_error(&error.error), api);
            if decision == "false" {
                assert!(error.body_absent);
            }
            let call = policy
                .calls
                .lock()
                .unwrap()
                .pop()
                .expect("policy was called");
            assert_eq!(call["action"], *action);
            assert_eq!(call["decision"], decision);
            assert_eq!(call["caller"], "native");
            assert_eq!(call["user"]["id"], body(&owner)["user"]["id"]);
            assert_eq!(call["user"]["email"], "client-policy-owner@example.test");
            assert_eq!(call["session"]["userId"], call["user"]["id"]);
            let session = auth
                .store()
                .get_session(call["session"]["token"].as_str().unwrap())
                .await?
                .unwrap();
            assert_eq!(json!(session.id()), call["session"]["id"]);
            assert_eq!(db.tables(&["oauthClient"]).await?, before);
            assert_eq!(db.count("oauthClient").await?, 1);
        }
    }
    // Schema/session middleware precedes the policy; lookup, cache, and ownership follow it.
    for (operation, input, cookie, decision, status, called) in [
        (
            "adminUpdateOAuthClient",
            json!({"client_id":id,"update":{"client_name":42}}),
            cookies(&owner),
            "false",
            400,
            false,
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":id,"update":{}}),
            String::new(),
            "false",
            401,
            false,
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":"missing","update":{}}),
            cookies(&owner),
            "false",
            401,
            true,
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":"cached-client","update":{}}),
            cookies(&owner),
            "false",
            401,
            true,
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":"cached-client","update":{}}),
            cookies(&owner),
            "true",
            500,
            true,
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":id,"update":{"client_name":"foreign"}}),
            cookies(&other),
            "true",
            401,
            true,
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":id,"update":{"client_credentials_scopes":["email"]}}),
            cookies(&owner),
            "true",
            400,
            true,
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(&input)?,
            options(cookie, decision),
        ))
        .await
        .unwrap_err();
        assert!(alibi::endpoint::is_endpoint_api_error(&error.error));
        assert_eq!(error.error.status_code(), status);
        assert_eq!(!policy.calls.lock().unwrap().is_empty(), called);
        policy.calls.lock().unwrap().clear();
        assert_eq!(db.tables(&["oauthClient"]).await?, before);
    }
    for (operation, input, expected_actions) in [
        (
            "adminCreateOAuthClient",
            json!({"grant_types":["client_credentials"],"client_credentials_scopes":["api:read"]}),
            vec!["create", "configure-client-credentials-scopes"],
        ),
        (
            "adminUpdateOAuthClient",
            json!({"client_id":id,"update":{"client_name":"Forbidden","client_credentials_scopes":["api:read"]}}),
            vec!["update", "configure-client-credentials-scopes"],
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(&input)?,
            options(cookies(&owner), "deny-scopes"),
        ))
        .await
        .unwrap_err();
        assert!(alibi::endpoint::is_endpoint_api_error(&error.error));
        assert_eq!(error.error.status_code(), 401);
        assert_eq!(
            policy
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|v| v["action"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected_actions
        );
        policy.calls.lock().unwrap().clear();
        assert_eq!(db.tables(&["oauthClient"]).await?, before);
    }
    for (patch, decision, status, actions) in [
        (
            json!({"client_name":"foreign","client_credentials_scopes":["api:read"]}),
            "true",
            401,
            vec!["update"],
        ),
        (
            json!({"client_credentials_scopes":["email"]}),
            "deny-scopes",
            401,
            vec!["update", "configure-client-credentials-scopes"],
        ),
        (
            json!({"client_credentials_scopes":["email"]}),
            "true",
            400,
            vec!["update", "configure-client-credentials-scopes"],
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_update_oauth_client_endpoint(&id, &patch)?,
            options(cookies(&other), decision),
        ))
        .await
        .unwrap_err();
        assert!(alibi::endpoint::is_endpoint_api_error(&error.error));
        assert_eq!(error.error.status_code(), status);
        assert_eq!(
            policy
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|v| v["action"].as_str().unwrap())
                .collect::<Vec<_>>(),
            actions
        );
        policy.calls.lock().unwrap().clear();
        assert_eq!(db.tables(&["oauthClient"]).await?, before);
    }
    let narrow_auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_credentials_scope_privileges: Some(policy.clone()),
                scopes: vec!["api:read".into()],
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    let unchanged = Box::pin(narrow_auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_update_oauth_client_endpoint(&id, &json!({}))?,
        options(cookies(&owner), "false"),
    ))
    .await?
    .into_response()?;
    assert_eq!(unchanged.status, 200);
    let denied = Box::pin(narrow_auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_update_oauth_client_endpoint(
            &id,
            &json!({"client_credentials_scopes":["api:read"]}),
        )?,
        options(cookies(&other), "true"),
    ))
    .await
    .unwrap_err();
    assert!(alibi::endpoint::is_endpoint_api_error(&denied.error));
    assert_eq!(denied.error.status_code(), 401);
    assert!(policy.calls.lock().unwrap().is_empty());
    assert_eq!(db.tables(&["oauthClient"]).await?, before);
    let cached_auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_privileges: Some(policy.clone()),
                cached_trusted_clients: [id.clone()].into(),
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    for operation in [
        "updateOAuthClient",
        "adminUpdateOAuthClient",
        "rotateClientSecret",
        "deleteOAuthClient",
    ] {
        for (decision, status) in [("false", 401), ("true", 500)] {
            let error = Box::pin(
                cached_auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", operation)
                        .with_body(&json!({"client_id":id,"update":{"client_name":"Forbidden"}}))?,
                    options(cookies(&owner), decision),
                ),
            )
            .await
            .unwrap_err();
            assert!(alibi::endpoint::is_endpoint_api_error(&error.error));
            assert_eq!(error.error.status_code(), status);
            assert_eq!(policy.calls.lock().unwrap().len(), 1);
            policy.calls.lock().unwrap().clear();
            assert_eq!(db.tables(&["oauthClient"]).await?, before);
        }
    }
    for scopes in [json!(["api:write"]), json!([])] {
        let output = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_update_oauth_client_endpoint(
                &id,
                &json!({"client_credentials_scopes":scopes}),
            )?,
            options(cookies(&other), "true"),
        ))
        .await?
        .into_response()?;
        assert_eq!(body(&output)["client_credentials_scopes"], scopes);
        assert_eq!(
            policy
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|v| v["action"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["update", "configure-client-credentials-scopes"]
        );
        policy.calls.lock().unwrap().clear();
        let row = auth.store().get_oauth_client(&id).await?.unwrap();
        assert_eq!(row.metadata["client_credentials_scopes"], scopes);
        assert_eq!(row.metadata["client_name"], "Original");
        assert_eq!(row.user_id, initial.user_id);
        assert_eq!(row.client_secret, initial.client_secret);
    }
    let updated = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_update_oauth_client_endpoint(
            &id,
            &json!({"client_name":"Allowed","client_credentials_scopes":["api:read"]}),
        )?,
        options(cookies(&owner), "true"),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&updated)["client_name"], "Allowed");
    assert_eq!(
        policy
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|v| v["action"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["update", "configure-client-credentials-scopes"]
    );
    let stored = auth.store().get_oauth_client(&id).await?.unwrap();
    assert_eq!(stored.metadata["client_name"], "Allowed");
    assert_eq!(
        stored.metadata["client_credentials_scopes"],
        json!(["api:read"])
    );
    assert_eq!(stored.client_secret, initial.client_secret);
    policy.calls.lock().unwrap().clear();
    for (operation, action, input, query) in &operations[3..] {
        let mut endpoint =
            ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(input)?;
        if let Some(query) = query {
            endpoint = endpoint.with_query(query)?;
        }
        let output = Box::pin(auth.dispatch_endpoint(endpoint, options(cookies(&owner), "true")))
            .await?
            .into_response()?;
        assert_eq!(output.status, 200);
        assert_eq!(
            policy.calls.lock().unwrap().pop().unwrap()["action"],
            *action
        );
        let stored = auth.store().get_oauth_client(&id).await?;
        match *action {
            "read" => assert!(body(&output).get("client_secret").is_none()),
            "list" => assert_eq!(body(&output).as_array().unwrap().len(), 1),
            "update" => assert_eq!(stored.unwrap().metadata["client_name"], "Changed"),
            "rotate" => assert_ne!(stored.unwrap().client_secret, initial.client_secret),
            "delete" => assert!(stored.is_none()),
            other => return Err(format!("unexpected management action {other}").into()),
        }
    }
    let created = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "createOAuthClient").with_body(&metadata)?,
        options(cookies(&owner), "true"),
    ))
    .await?
    .into_response()?;
    let public_id = body(&created)["client_id"].as_str().unwrap().to_owned();
    assert_eq!(
        policy.calls.lock().unwrap().pop().unwrap()["action"],
        "create"
    );
    let public = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_client_public_endpoint(&public_id)?,
        options(cookies(&other), "false"),
    ))
    .await?
    .into_response()?;
    assert_eq!(public.status, 200);
    let anonymous = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                .with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"]}))?,
            options(String::new(), "false"),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(anonymous.status, 201);
    assert!(policy.calls.lock().unwrap().is_empty());
    let anonymous_id = body(&anonymous)["client_id"].as_str().unwrap().to_owned();
    assert!(
        auth.store()
            .get_oauth_client(&anonymous_id)
            .await?
            .unwrap()
            .user_id
            .is_none()
    );
    Ok(())
}
async fn oauth_admin_update_replaces_operator_metadata_and_preserves_secret<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-admin-update-owner@example.test").await;
    let other = signup(&auth, "oauth-admin-update-other@example.test").await;
    let created=auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({"client_name":"Before operator update","redirect_uris":["https://app.fixture.test/callback"],"skip_consent":true,"enable_end_session":true,"metadata":{"old_label":"old"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let original = body(&created);
    let id = original["client_id"].as_str().unwrap();
    let old = auth.store().get_oauth_client(id).await?.unwrap();
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
        ])
        .await?;
    for (id, patch, cookie, status) in [
        (id, json!({"skip_consent":"yes"}), cookies(&owner), 400),
        (id, json!({"client_name":"foreign"}), cookies(&other), 401),
        (id, json!({"client_name":"guest"}), String::new(), 401),
        (
            id,
            json!({"client_credentials_scopes":["email"]}),
            cookies(&owner),
            400,
        ),
        ("missing-client", json!({}), cookies(&owner), 404),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthClient")
                    .with_body(&json!({"client_id":id,"update":patch}))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(alibi::endpoint::is_endpoint_api_error(&error.error));
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        }
        assert_eq!(
            db.tables(&[
                "user",
                "account",
                "session",
                "verification",
                "jwks",
                "oauthClient"
            ])
            .await?,
            before
        );
    }
    let unchanged=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminUpdateOAuthClient").with_body(&json!({"client_id":id,"update":{"user_id":"forged","token_endpoint_auth_method":"none"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let mut expected = original.clone();
    _ = expected.as_object_mut().unwrap().remove("client_secret");
    assert_eq!(body(&unchanged), expected);
    assert_eq!(
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient"
        ])
        .await?,
        before
    );
    let patch = json!({"client_name":"After operator update","skip_consent":false,"enable_end_session":false,"dpop_bound_access_tokens":true,"client_secret_expires_at":"1893456000","metadata":{"new_label":"new","client_id":"forged","client_secret":"forged","user_id":"forged"}});
    let start = chrono::Utc::now().timestamp();
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthClient")
                .with_body(&json!({"client_id":id,"update":patch}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(output.status, 200);
    expected["client_name"] = json!("After operator update");
    expected["skip_consent"] = json!(false);
    expected["enable_end_session"] = json!(false);
    expected["dpop_bound_access_tokens"] = json!(true);
    expected["client_secret_expires_at"] = json!(0);
    _ = expected.as_object_mut().unwrap().remove("old_label");
    expected["new_label"] = json!("new");
    assert_eq!(body(&output), expected);
    let stored = auth.store().get_oauth_client(id).await?.unwrap();
    assert_eq!(stored.id, old.id);
    assert_eq!(stored.user_id, old.user_id);
    assert_eq!(stored.client_secret, old.client_secret);
    assert_eq!(stored.created_at, old.created_at);
    assert!(stored.updated_at.expect("client timestamp").timestamp() >= start);
    assert!(
        stored.updated_at.expect("client timestamp").timestamp() <= chrono::Utc::now().timestamp()
    );
    assert!(stored.metadata.get("old_label").is_none());
    assert_eq!(stored.metadata["new_label"], "new");
    assert_eq!(stored.metadata["skip_consent"], false);
    let mut physical = request(
        "/admin/oauth2/update-client",
        Some(json!({"client_id":id,"update":patch})),
        &cookies(&owner),
    );
    physical.method = HttpMethod::Patch;
    let denied = auth.handle_request(physical).await?;
    assert_eq!(denied.status, 404);
    assert_eq!(db.count("oauthClient").await?, 1);
    Ok(())
}
