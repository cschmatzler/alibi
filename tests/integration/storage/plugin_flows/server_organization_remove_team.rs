//! Trusted server removal preserves last-team policy and prunes persisted links.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig, types::RemoveTeamRequest};

backend_tests!(server_remove_team_without_request_prunes_links_and_preserves_last_team);
async fn server_remove_team_without_request_prunes_links_and_preserves_last_team<B: Backend>(
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
    let owner = Box::pin(signup(&auth, "trusted-removal-owner@example.test")).await;
    let organization = Box::pin(call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Trusted removal","slug":"trusted-removal"})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let id = body(&organization)["id"].as_str().unwrap().to_owned();
    let mut teams = Vec::new();
    for name in ["Alpha", "Beta"] {
        let response = Box::pin(call(
            &auth,
            request(
                "/organization/create-team",
                Some(json!({"organizationId":id,"name":name})),
                &cookies(&owner),
            ),
            200,
        ))
        .await;
        teams.push(body(&response)["id"].as_str().unwrap().to_owned());
    }
    let _ = Box::pin(call(
        &auth,
        request(
            "/organization/add-team-member",
            Some(json!({"teamId":teams[0],"userId":body(&owner)["user"]["id"]})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let _ = Box::pin(call(&auth, request("/organization/invite-member", Some(json!({"organizationId":id,"email":"trusted-removal-invitee@example.test","role":"member","teamId":teams})), &cookies(&owner)), 200)).await;
    let before = db
        .tables(&[
            "users",
            "sessions",
            "member",
            "team",
            "team_member",
            "invitation",
        ])
        .await?;
    for (organization_id, team_id, code) in [
        (None, teams[0].clone(), "NO_ACTIVE_ORGANIZATION"),
        (
            Some(String::new()),
            teams[0].clone(),
            "NO_ACTIVE_ORGANIZATION",
        ),
        (
            Some("missing-organization".into()),
            teams[0].clone(),
            "TEAM_NOT_FOUND",
        ),
        (Some(id.clone()), "missing-team".into(), "TEAM_NOT_FOUND"),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::remove_team_endpoint(&RemoveTeamRequest {
                team_id,
                organization_id,
            })?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(
        db.tables(&[
            "users",
            "sessions",
            "member",
            "team",
            "team_member",
            "invitation"
        ])
        .await?,
        before
    );
    let output = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::remove_team_endpoint(&RemoveTeamRequest {
            team_id: teams[0].clone(),
            organization_id: Some(id.clone()),
        })?,
        EndpointOptions::default(),
    ))
    .await?;
    assert_eq!(
        serde_json::to_value(output.value())?,
        json!({"message":"Team removed successfully."})
    );
    let after = db
        .tables(&[
            "users",
            "sessions",
            "member",
            "team",
            "team_member",
            "invitation",
        ])
        .await?;
    assert_eq!(&after[..3], &before[..3]);
    let stored_teams: Vec<Value> = serde_json::from_str(&after[3])?;
    assert_eq!(stored_teams.len(), 1);
    assert_eq!(stored_teams[0]["id"], teams[1]);
    assert_eq!(after[4], "[]");
    let invitations: Vec<Value> = serde_json::from_str(&after[5])?;
    assert_eq!(invitations.len(), 1);
    assert_eq!(invitations[0]["team_id"], teams[1]);
    assert_eq!(invitations[0]["status"], "pending");
    for (team_id, code) in [
        (teams[0].clone(), "TEAM_NOT_FOUND"),
        (teams[1].clone(), "UNABLE_TO_REMOVE_LAST_TEAM"),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::remove_team_endpoint(&RemoveTeamRequest {
                team_id,
                organization_id: Some(id.clone()),
            })?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(
        db.tables(&[
            "users",
            "sessions",
            "member",
            "team",
            "team_member",
            "invitation"
        ])
        .await?,
        after
    );
    B::close(connection).await
}
