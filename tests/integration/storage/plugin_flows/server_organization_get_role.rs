//! Role reads expose parsed durable permissions while preserving organization authority.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig, default_organization_statements,
    types::RoleQuery,
};
use alibi::utils::json::JsValue;
backend_tests!(server_get_org_role_reads_persisted_permissions_with_member_authority);
async fn server_get_org_role_reads_persisted_permissions_with_member_authority<B: Backend>(
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
    let _denied_role = call(
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
        let output = auth
            .dispatch_endpoint(endpoint().with_query(&query)?, options(&owner))
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
        let error = auth
            .dispatch_endpoint(endpoint().with_query(&query)?, credentials)
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    let typed = auth
        .dispatch_endpoint(
            OrganizationPlugin::get_org_role_endpoint(&RoleQuery {
                organization_id: Some(first_id),
                role_id: Some(first_role["id"].as_str().unwrap().to_owned()),
                ..Default::default()
            })?,
            options(&owner),
        )
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
    B::close(connection).await
}
