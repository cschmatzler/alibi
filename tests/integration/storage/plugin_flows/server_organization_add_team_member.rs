//! Server team membership admission and removal preserve authority and stored counts.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig, types::TeamMemberRequest};
use alibi::utils::json::JsValue;

backend_tests!(server_team_membership_lifecycle_enforces_headers_and_admission);
async fn server_team_membership_lifecycle_enforces_headers_and_admission<B: Backend>(
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
    let owner = Box::pin(signup(&auth, "team-admission-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "team-admission-outsider@example.test")).await;
    let organization = Box::pin(call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Team admission","slug":"team-admission"})),
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
            Some(json!({"name":"Admission","organizationId":id})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let team_id = body(&team)["id"].as_str().unwrap().to_owned();
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let outsider_id = body(&outsider)["user"]["id"].as_str().unwrap().to_owned();
    let credentials = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let input =
        |team_id: String, user_id: String, organization_id: Option<String>| TeamMemberRequest {
            team_id,
            user_id,
            organization_id,
        };
    let before = db
        .tables(&["user", "session", "member", "team", "teamMember"])
        .await?;
    for operation in ["addTeamMember", "removeTeamMember"] {
        for (input, options, status, code) in [
            (
                input(team_id.clone(), user_id.clone(), Some(id.clone())),
                EndpointOptions::default(),
                400,
                "VALIDATION_ERROR",
            ),
            (
                input(team_id.clone(), user_id.clone(), Some(id.clone())),
                EndpointOptions {
                    headers: Some(Default::default()),
                    ..Default::default()
                },
                401,
                "UNAUTHORIZED",
            ),
            (
                input(team_id.clone(), user_id.clone(), Some(id.clone())),
                credentials(&outsider),
                400,
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
            ),
            (
                input(team_id.clone(), outsider_id.clone(), Some(id.clone())),
                credentials(&owner),
                400,
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
            ),
            (
                input("missing-team".into(), user_id.clone(), Some(id.clone())),
                credentials(&owner),
                400,
                "TEAM_NOT_FOUND",
            ),
        ] {
            let error = Box::pin(auth.dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("organization", operation).with_body(&input)?,
                options,
            ))
            .await
            .unwrap_err();
            assert_eq!(error.error.status_code(), status);
            assert_eq!(body(&error.error.to_auth_response())["code"], code);
        }
    }
    assert_eq!(
        db.tables(&["user", "session", "member", "team", "teamMember"])
            .await?,
        before
    );
    let output = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::add_team_member_endpoint(&input(
            team_id.clone(),
            user_id.clone(),
            None,
        ))?,
        credentials(&owner),
    ))
    .await?;
    let member = output.decode()?;
    assert_eq!(member.team_id, team_id);
    assert_eq!(member.user_id, user_id);
    let added = db
        .tables(&["user", "session", "member", "team", "teamMember"])
        .await?;
    assert_eq!(&added[..3], &before[..3]);
    let mut expected_teams: Vec<Value> = serde_json::from_str(&before[3])?;
    expected_teams[0]["memberCount"] = json!(1);
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&added[3])?,
        expected_teams
    );
    let rows: Vec<Value> = serde_json::from_str(&added[4])?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], member.id);
    assert_eq!(rows[0]["teamId"], team_id);
    assert_eq!(rows[0]["userId"], user_id);
    let repeated = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::add_team_member_endpoint(&input(
            team_id.clone(),
            user_id.clone(),
            None,
        ))?,
        credentials(&owner),
    ))
    .await?;
    assert_eq!(
        serde_json::to_value(repeated.value())?,
        serde_json::to_value(output.value())?
    );
    assert_eq!(
        db.tables(&["user", "session", "member", "team", "teamMember"])
            .await?,
        added
    );
    let endpoint = || {
        OrganizationPlugin::remove_team_member_endpoint(&input(
            team_id.clone(),
            user_id.clone(),
            None,
        ))
    };
    let removed = Box::pin(auth.dispatch_endpoint(endpoint()?, credentials(&owner))).await?;
    assert_eq!(
        serde_json::to_value(removed.value())?,
        json!({"message":"Team member removed successfully."})
    );
    assert_eq!(
        db.tables(&["user", "session", "member", "team", "teamMember"])
            .await?,
        before
    );
    let replay = Box::pin(auth.dispatch_endpoint(endpoint()?, credentials(&owner)))
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        body(&replay.error.to_auth_response())["code"],
        "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"
    );
    assert_eq!(
        db.tables(&["user", "session", "member", "team", "teamMember"])
            .await?,
        before
    );
    B::close(connection).await
}
