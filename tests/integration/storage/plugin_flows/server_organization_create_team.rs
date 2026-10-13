//! Trusted server team creation retains organization lookup and configured limits.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig, types::CreateTeamRequest};

backend_tests!(server_create_team_without_request_preserves_limits_and_storage);
async fn server_create_team_without_request_preserves_limits_and_storage<B: Backend>(
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
                    maximum_teams: Some(1.5),
                    ..Default::default()
                },
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "trusted-team-owner@example.test")).await;
    let organization = Box::pin(call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Trusted teams","slug":"trusted-teams"})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let id = body(&organization)["id"].as_str().unwrap().to_owned();
    let before = db
        .tables(&["user", "session", "member", "teamMember"])
        .await?;
    for (organization_id, code) in [
        (None, "NO_ACTIVE_ORGANIZATION"),
        (Some(String::new()), "NO_ACTIVE_ORGANIZATION"),
        (
            Some("missing-organization".into()),
            "ORGANIZATION_NOT_FOUND",
        ),
    ] {
        let endpoint = OrganizationPlugin::create_team_endpoint(&CreateTeamRequest {
            name: "Rejected".into(),
            organization_id,
        })?;
        let error = Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(db.tables(&["team"]).await?[0], "[]");
    let mut ids = Vec::new();
    for name in ["Alpha", "Beta"] {
        let output = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::create_team_endpoint(&CreateTeamRequest {
                name: name.into(),
                organization_id: Some(id.clone()),
            })?,
            EndpointOptions::default(),
        ))
        .await?;
        let team = output.decode()?;
        assert_eq!(team.name, name);
        assert_eq!(team.organization_id, id);
        ids.push(team.id);
    }
    let stored = db.tables(&["team"]).await?;
    let rows: Vec<Value> = serde_json::from_str(&stored[0])?;
    assert_eq!(rows.len(), 2);
    assert!(ids.iter().all(|id| rows.iter().any(|row| row["id"] == *id)));
    let error = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::create_team_endpoint(&CreateTeamRequest {
            name: "Over limit".into(),
            organization_id: Some(id),
        })?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.error.status_code(), 400);
    assert_eq!(
        body(&error.error.to_auth_response())["code"],
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"
    );
    assert_eq!(db.tables(&["team"]).await?, stored);
    assert_eq!(
        db.tables(&["user", "session", "member", "teamMember"])
            .await?,
        before
    );
    B::close(connection).await
}
