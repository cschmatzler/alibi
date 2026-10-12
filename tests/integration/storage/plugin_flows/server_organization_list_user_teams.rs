//! Server user team selection spans memberships without mutating stored state.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig, types::TeamQuery};
use alibi::utils::json::JsValue;

backend_tests!(server_list_user_teams_preserves_scope_and_member_authority);
async fn server_list_user_teams_preserves_scope_and_member_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = Box::pin(
        AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                teams: TeamsConfig {
                    enabled: true,
                    create_default_team: false,
                    ..Default::default()
                },
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "user-teams-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "user-teams-outsider@example.test")).await;
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let outsider_id = body(&outsider)["user"]["id"].as_str().unwrap().to_owned();
    let mut organizations = Vec::new();
    let mut expected = Vec::new();
    for name in ["first", "second"] {
        let organization = Box::pin(call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":name,"slug":name})),
                &cookies(&owner),
            ),
            200,
        ))
        .await;
        let id = body(&organization)["id"].as_str().unwrap().to_owned();
        let team = Box::pin(call(
            &auth,
            request(
                "/organization/create-team",
                Some(json!({"name":name,"organizationId":id})),
                &cookies(&owner),
            ),
            200,
        ))
        .await;
        let _ = Box::pin(call(
            &auth,
            request(
                "/organization/add-team-member",
                Some(json!({"teamId":body(&team)["id"],"userId":user_id,"organizationId":id})),
                &cookies(&owner),
            ),
            200,
        ))
        .await;
        organizations.push(id);
        expected.push(body(&team));
    }
    let credentials = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = || ServerEndpoint::<JsValue>::new("organization", "listUserTeams");
    let before = db
        .tables(&["users", "sessions", "member", "team", "team_member"])
        .await?;
    for (query, options, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            None,
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            Some(json!({"organizationId":organizations[0]})),
            credentials(&outsider),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            Some(json!({"userId":outsider_id,"organizationId":organizations[0]})),
            credentials(&owner),
            400,
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        ),
        (
            Some(json!({"userId":user_id,"organizationId":organizations[0]})),
            credentials(&outsider),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            Some(json!({"userId":user_id})),
            credentials(&outsider),
            400,
            "NO_ACTIVE_ORGANIZATION",
        ),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let error = Box::pin(auth.dispatch_endpoint(call, options))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    for query in [
        None,
        Some(json!({})),
        Some(json!({"organizationId":"","userId":""})),
        Some(json!({"teamId":42,"ignored":{"nested":true}})),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let output = Box::pin(auth.dispatch_endpoint(call, credentials(&owner))).await?;
        assert_eq!(serde_json::to_value(output.value())?, json!(expected));
    }
    let scoped = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::list_user_teams_endpoint(&TeamQuery {
            organization_id: Some(organizations[0].clone()),
            ..Default::default()
        })?,
        credentials(&owner),
    ))
    .await?;
    assert_eq!(serde_json::to_value(scoped.value())?, json!([expected[0]]));
    let other = Box::pin(auth.dispatch_endpoint(endpoint(), credentials(&outsider))).await?;
    assert_eq!(serde_json::to_value(other.value())?, json!([]));
    assert_eq!(
        db.tables(&["users", "sessions", "member", "team", "team_member"])
            .await?,
        before
    );
    B::close(connection).await
}
