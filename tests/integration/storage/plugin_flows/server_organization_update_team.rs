//! Server updates require headers and retain active/explicit organization scope.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    OrganizationConfig, TeamsConfig,
    types::{UpdateTeamData, UpdateTeamRequest},
};
use alibi::utils::json::JsValue;

backend_tests!(server_update_team_enforces_headers_and_organization_scope);
async fn server_update_team_enforces_headers_and_organization_scope<B: Backend>(
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
    let owner = Box::pin(signup(&auth, "team-update-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "team-update-outsider@example.test")).await;
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
    let before = db
        .tables(&["users", "sessions", "member", "team", "team_member"])
        .await?;
    let credentials = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    for (input, options, status, code) in [
        (
            json!({"teamId":teams[0],"data":{"name":"Rejected","organizationId":organizations[0]}}),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"teamId":teams[0],"data":{"name":"Rejected","organizationId":organizations[0]}}),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            json!({"teamId":teams[0],"data":{"name":"Rejected","organizationId":organizations[0]}}),
            credentials(&outsider),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
        ),
        (
            json!({"teamId":teams[0],"data":{"name":"Rejected","organizationId":organizations[1]}}),
            credentials(&owner),
            400,
            "TEAM_NOT_FOUND",
        ),
        (
            json!({"teamId":teams[0],"data":{"name":"","organizationId":organizations[0]}}),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
    ] {
        let endpoint =
            ServerEndpoint::<JsValue>::new("organization", "updateTeam").with_body(&input)?;
        let error = Box::pin(auth.dispatch_endpoint(endpoint, options))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(
        db.tables(&["users", "sessions", "member", "team", "team_member"])
            .await?,
        before
    );
    for (index, organization_id) in [(0, Some(organizations[0].clone())), (1, None)] {
        let name = format!("Updated {index}");
        let output = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::update_team_endpoint(&UpdateTeamRequest {
                team_id: teams[index].clone(),
                data: UpdateTeamData {
                    name: Some(name.clone()),
                    organization_id,
                },
            })?,
            credentials(&owner),
        ))
        .await?;
        let team = output.decode()?;
        assert_eq!(team.id, teams[index]);
        assert_eq!(team.organization_id, organizations[index]);
        assert_eq!(team.name, name);
    }
    let after = db
        .tables(&["users", "sessions", "member", "team", "team_member"])
        .await?;
    assert_eq!(&after[..3], &before[..3]);
    assert_eq!(after[4], before[4]);
    let rows: Vec<Value> = serde_json::from_str(&after[3])?;
    assert_eq!(rows.len(), 2);
    for (index, id) in teams.iter().enumerate() {
        assert!(
            rows.iter()
                .any(|row| row["id"] == *id && row["name"] == format!("Updated {index}"))
        );
    }
    B::close(connection).await
}
