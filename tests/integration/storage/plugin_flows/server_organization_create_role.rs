//! Canonical role creation uses genuine logical authority and durable permission data.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig, default_organization_statements,
};
use alibi::utils::json::JsValue;
backend_tests!(server_create_org_role_persists_normalized_permissions_without_request);
async fn server_create_org_role_persists_normalized_permissions_without_request<B: Backend>(
    db: Db,
) -> TestResult {
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
    let owner = signup(&auth, "role-server-owner@example.test").await;
    let outsider = signup(&auth, "role-server-outsider@example.test").await;
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Server role organization","slug":"server-role-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let organization_id = body(&created)["id"].as_str().unwrap().to_owned();
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let permission = json!({"team":["create","update"],"member":["update"]});
    let input = json!({"organizationId":organization_id,"role":"TeamEditor","permission":permission,"id":"forged-role","createdAt":"2000-01-01"});
    let before = db
        .tables(&["user", "session", "organization", "member"])
        .await?;
    let endpoint = || ServerEndpoint::<JsValue>::new("organization", "createOrgRole");
    let output = auth
        .dispatch_endpoint(endpoint().with_body(&input)?, options(&owner))
        .await?;
    let result = serde_json::to_value(output.value())?;
    assert_eq!(result["success"], true);
    assert_eq!(result["roleData"]["role"], "teameditor");
    assert_eq!(result["roleData"]["permission"], permission);
    assert_ne!(result["roleData"]["id"], "forged-role");
    let role_id = result["roleData"]["id"].as_str().unwrap();
    let stored = auth
        .store()
        .get_organization_role(
            &organization_id,
            &alibi::types::OrganizationRoleSelector::Id(role_id.to_owned()),
        )
        .await?
        .unwrap();
    assert_eq!(stored.organization_id, organization_id);
    assert_eq!(stored.role, "teameditor");
    assert_eq!(
        serde_json::from_str::<Value>(stored.permission.as_str())?,
        permission
    );
    let after = db.tables(&["organizationRole"]).await?;
    for (input, credentials, status, code) in [
        (
            json!({"role":"missing-headers","permission":permission}),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"role":"empty-headers","permission":permission}),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            json!({"organizationId":organization_id,"role":"outside","permission":permission}),
            options(&outsider),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            json!({"role":"TeamEditor","permission":permission}),
            options(&owner),
            400,
            "ROLE_NAME_IS_ALREADY_TAKEN",
        ),
        (
            json!({"role":"OWNER","permission":{}}),
            options(&owner),
            400,
            "ROLE_NAME_IS_ALREADY_TAKEN",
        ),
        (
            json!({"role":"invalid-resource","permission":{"invented":["read"]}}),
            options(&owner),
            400,
            "INVALID_RESOURCE",
        ),
    ] {
        let error = auth
            .dispatch_endpoint(endpoint().with_body(&input)?, credentials)
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(db.tables(&["organizationRole"]).await?, after);
    assert_eq!(
        db.tables(&["user", "session", "organization", "member"])
            .await?,
        before
    );
    let active_input =
        serde_json::from_value(json!({"role":"ActiveReader","permission":{"ac":["read"]}}))?;
    let active = auth
        .dispatch_endpoint(
            OrganizationPlugin::create_org_role_endpoint(&active_input)?,
            options(&owner),
        )
        .await?;
    let active = active.decode()?;
    assert!(active.success);
    assert_eq!(active.role_data.organization_id, organization_id);
    assert_eq!(active.role_data.role, "activereader");
    B::close(connection).await
}
