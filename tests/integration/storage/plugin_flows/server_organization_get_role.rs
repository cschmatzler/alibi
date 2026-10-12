//! Role reads expose parsed durable permissions while preserving organization authority.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig, default_organization_statements,
    types::RoleQuery,
};
use alibi::utils::json::JsValue;
backend_tests!(server_org_role_lifecycle_preserves_member_authority);
async fn server_org_role_lifecycle_preserves_member_authority<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: true,
                ..Default::default()
            },
            access_control: Some(default_organization_statements()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "role-read-owner@example.test").await;
    let member = signup(&auth, "role-read-member@example.test").await;
    let outsider = signup(&auth, "role-read-outsider@example.test").await;
    let first = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"First role organization","slug":"first-read-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let first_id = body(&first)["id"].as_str().unwrap().to_owned();
    let first_role = call(
        &auth,
        request(
            "/organization/create-role",
            Some(json!({"role":"FirstReader","permission":{"ac":["read"]}})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let first_role = body(&first_role)["roleData"].clone();
    let invitation = call(
        &auth,
        request(
            "/organization/invite-member",
            Some(json!({"email":"role-read-member@example.test","role":"member"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let accepted = call(
        &auth,
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId":body(&invitation)["id"]})),
            &cookies(&member),
        ),
        200,
    )
    .await;
    let denied_role = call(
        &auth,
        request(
            "/organization/create-role",
            Some(json!({"role":"TeamOnly","permission":{"team":["create"]}})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let _assigned = call(
        &auth,
        request(
            "/organization/update-member-role",
            Some(json!({"memberId":body(&accepted)["member"]["id"],"role":"teamonly"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let second = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Second role organization","slug":"second-read-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let second_id = body(&second)["id"].as_str().unwrap().to_owned();
    let second_role = call(
        &auth,
        request(
            "/organization/create-role",
            Some(json!({"role":"SecondReader","permission":{"team":["create"]}})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let second_role = body(&second_role)["roleData"].clone();
    let empty_organization = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Empty role organization","slug":"empty-role-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let _active = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId":second_id})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let before = db
        .tables(&[
            "users",
            "sessions",
            "organization",
            "member",
            "organization_role",
        ])
        .await?;
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = || ServerEndpoint::<JsValue>::new("organization", "getOrgRole");
    for (query, expected) in [
        (
            json!({"organizationId":first_id,"roleId":first_role["id"]}),
            &first_role,
        ),
        (
            json!({"organizationId":first_id,"roleName":"firstreader"}),
            &first_role,
        ),
        (json!({"roleName":"secondreader"}), &second_role),
        (
            json!({"organizationId":first_id,"roleName":"firstreader","roleId":"wrong-id"}),
            &first_role,
        ),
        (
            json!({"organizationId":first_id,"roleName":"","roleId":first_role["id"]}),
            &first_role,
        ),
    ] {
        let output =
            Box::pin(auth.dispatch_endpoint(endpoint().with_query(&query)?, options(&owner)))
                .await?;
        assert_eq!(&serde_json::to_value(output.value())?, expected);
    }
    for (query, credentials, status, code) in [
        (
            json!({"roleId":first_role["id"]}),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"roleId":first_role["id"]}),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            json!({"organizationId":first_id,"roleId":first_role["id"]}),
            options(&outsider),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            json!({"organizationId":first_id,"roleId":first_role["id"]}),
            options(&member),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
        ),
        (
            json!({"organizationId":second_id,"roleId":first_role["id"]}),
            options(&owner),
            400,
            "ROLE_NOT_FOUND",
        ),
        (
            json!({"roleName":"missing-role"}),
            options(&owner),
            400,
            "ROLE_NOT_FOUND",
        ),
        (
            json!({"roleName":"SecondReader"}),
            options(&owner),
            400,
            "ROLE_NOT_FOUND",
        ),
        (
            json!({"organizationId":first_id,"roleName":"missing-role","roleId":first_role["id"]}),
            options(&owner),
            400,
            "ROLE_NOT_FOUND",
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(endpoint().with_query(&query)?, credentials))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    let listing = || ServerEndpoint::<JsValue>::new("organization", "listOrgRoles");
    for (query, expected) in [
        (
            Some(json!({"organizationId":first_id,"roleName":7,"roleId":["ignored"]})),
            json!([first_role, body(&denied_role)["roleData"]]),
        ),
        (None, json!([second_role])),
        (Some(json!({})), json!([second_role])),
        (
            Some(json!({"organizationId":body(&empty_organization)["id"]})),
            json!([]),
        ),
    ] {
        let mut endpoint = listing();
        if let Some(query) = query {
            endpoint = endpoint.with_query(&query)?;
        }
        let output = Box::pin(auth.dispatch_endpoint(endpoint, options(&owner))).await?;
        assert_eq!(serde_json::to_value(output.value())?, expected);
    }
    for (query, credentials, status, code) in [
        (
            Some(json!({"organizationId":first_id})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            None,
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (None, options(&outsider), 400, "NO_ACTIVE_ORGANIZATION"),
        (
            Some(json!({"organizationId":first_id})),
            options(&outsider),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            Some(json!({"organizationId":first_id})),
            options(&member),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
        ),
        (
            Some(json!({"organizationId":""})),
            options(&owner),
            400,
            "NO_ACTIVE_ORGANIZATION",
        ),
    ] {
        let mut endpoint = listing();
        if let Some(query) = query {
            endpoint = endpoint.with_query(&query)?;
        }
        let error = Box::pin(auth.dispatch_endpoint(endpoint, credentials))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    let typed_list = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::list_org_roles_endpoint(&RoleQuery {
            organization_id: Some(first_id.clone()),
            ..Default::default()
        })?,
        options(&owner),
    ))
    .await?;
    assert_eq!(
        typed_list
            .decode()?
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        vec!["firstreader", "teamonly"]
    );
    let typed = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::get_org_role_endpoint(&RoleQuery {
            organization_id: Some(first_id.clone()),
            role_id: Some(first_role["id"].as_str().unwrap().to_owned()),
            ..Default::default()
        })?,
        options(&owner),
    ))
    .await?;
    assert_eq!(typed.decode()?.role, "firstreader");
    assert_eq!(
        db.tables(&[
            "users",
            "sessions",
            "organization",
            "member",
            "organization_role"
        ])
        .await?,
        before
    );
    let deletion = || ServerEndpoint::<JsValue>::new("organization", "deleteOrgRole");
    for (input, credentials, status, code) in [
        (
            json!({"roleId":first_role["id"]}),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"roleId":first_role["id"]}),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            json!({"organizationId":first_id,"roleId":first_role["id"]}),
            options(&outsider),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            json!({"organizationId":first_id,"roleId":first_role["id"]}),
            options(&member),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
        ),
        (
            json!({"organizationId":first_id,"roleId":body(&denied_role)["roleData"]["id"]}),
            options(&owner),
            400,
            "ROLE_IS_ASSIGNED_TO_MEMBERS",
        ),
        (
            json!({"roleName":"owner"}),
            options(&owner),
            400,
            "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
        ),
        (
            json!({"organizationId":second_id,"roleId":first_role["id"]}),
            options(&owner),
            400,
            "ROLE_NOT_FOUND",
        ),
        (
            json!({"organizationId":first_id,"roleName":"missing-role","roleId":first_role["id"]}),
            options(&owner),
            400,
            "ROLE_NOT_FOUND",
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(deletion().with_body(&input)?, credentials))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(
        db.tables(&[
            "users",
            "sessions",
            "organization",
            "member",
            "organization_role"
        ])
        .await?,
        before
    );
    let deleted = Box::pin(auth.dispatch_endpoint(
        deletion().with_body(
            &json!({"organizationId":first_id,"roleId":first_role["id"],"id":"forged"}),
        )?,
        options(&owner),
    ))
    .await?;
    assert_eq!(
        serde_json::to_value(deleted.value())?,
        json!({"success":true})
    );
    let missing = Box::pin(auth.dispatch_endpoint(
        endpoint().with_query(&json!({"organizationId":first_id,"roleId":first_role["id"]}))?,
        options(&owner),
    ))
    .await
    .unwrap_err();
    assert_eq!(missing.error.status_code(), 400);
    assert_eq!(
        body(&missing.error.to_auth_response())["code"],
        "ROLE_NOT_FOUND"
    );
    let deleted = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::delete_org_role_endpoint(&RoleQuery {
            role_name: Some("secondreader".into()),
            ..Default::default()
        })?,
        options(&owner),
    ))
    .await?;
    assert!(deleted.decode()?.success);
    let repeated = Box::pin(auth.dispatch_endpoint(
        deletion().with_body(&json!({"roleName":"secondreader"}))?,
        options(&owner),
    ))
    .await
    .unwrap_err();
    assert_eq!(repeated.error.status_code(), 400);
    assert_eq!(
        body(&repeated.error.to_auth_response())["code"],
        "ROLE_NOT_FOUND"
    );
    let final_state = db
        .tables(&[
            "users",
            "sessions",
            "organization",
            "member",
            "organization_role",
        ])
        .await?;
    assert_eq!(final_state[..4], before[..4]);
    let mut expected_roles = serde_json::from_str::<Vec<Value>>(&before[4])?;
    expected_roles.retain(|row| row["id"] != first_role["id"] && row["id"] != second_role["id"]);
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&final_state[4])?,
        expected_roles
    );
    B::close(connection).await
}
