//! Server team member listing owns optional selection and actual team membership.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig, types::TeamQuery};
use alibi::utils::json::JsValue;

backend_tests!(server_list_team_members_preserves_active_selection_and_seat_authority);
async fn server_list_team_members_preserves_active_selection_and_seat_authority<B: Backend>(
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
    let owner = Box::pin(signup(&auth, "team-read-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "team-read-outsider@example.test")).await;
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let mut organizations = Vec::new();
    let mut teams = Vec::new();
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
        organizations.push(id);
        teams.push(body(&team)["id"].as_str().unwrap().to_owned());
    }
    let admitted = Box::pin(call(
        &auth,
        request(
            "/organization/add-team-member",
            Some(json!({"teamId":teams[0],"userId":user_id,"organizationId":organizations[0]})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let _ = Box::pin(call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId":organizations[0]})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let _ = Box::pin(call(
        &auth,
        request(
            "/organization/set-active-team",
            Some(json!({"teamId":teams[0]})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let credentials = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = || ServerEndpoint::<JsValue>::new("organization", "listTeamMembers");
    let before = db
        .tables(&["user", "session", "member", "team", "teamMember"])
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
            Some(json!({"teamId":teams[0]})),
            credentials(&outsider),
            400,
            "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
        ),
        (
            Some(json!({"teamId":teams[1]})),
            credentials(&owner),
            400,
            "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
        ),
        (
            Some(json!({"teamId":"missing-team"})),
            credentials(&owner),
            400,
            "TEAM_NOT_FOUND",
        ),
        (
            None,
            credentials(&outsider),
            400,
            "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM",
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
        Some(json!({"teamId":""})),
        Some(json!({"organizationId":42,"userId":{},"ignored":true})),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let output = Box::pin(auth.dispatch_endpoint(call, credentials(&owner))).await?;
        assert_eq!(
            serde_json::to_value(output.value())?,
            json!([body(&admitted)])
        );
    }
    let explicit = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::list_team_members_endpoint(&TeamQuery {
            team_id: Some(teams[0].clone()),
            ..Default::default()
        })?,
        credentials(&owner),
    ))
    .await?;
    assert_eq!(
        serde_json::to_value(explicit.value())?,
        json!([body(&admitted)])
    );
    assert_eq!(
        db.tables(&["user", "session", "member", "team", "teamMember"])
            .await?,
        before
    );
    B::close(connection).await
}
