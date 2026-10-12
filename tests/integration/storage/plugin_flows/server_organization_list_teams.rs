//! Canonical server team listing owns selection and membership authorization.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{OrganizationConfig, TeamsConfig, types::TeamQuery};
use alibi::utils::json::JsValue;

backend_tests!(server_list_organization_teams_reads_owned_and_active_teams_without_request);
async fn server_list_organization_teams_reads_owned_and_active_teams_without_request<B: Backend>(
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
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "team-list-owner@example.test").await;
    let outsider = signup(&auth, "team-list-outsider@example.test").await;
    let first = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"First","slug":"first-team-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let first_id = body(&first)["id"].as_str().unwrap().to_owned();
    let mut expected = Vec::new();
    for name in ["Alpha", "Beta"] {
        let response = call(
            &auth,
            request(
                "/organization/create-team",
                Some(json!({"organizationId":first_id,"name":name})),
                &cookies(&owner),
            ),
            200,
        )
        .await;
        expected.push(body(&response));
    }
    let second = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Second","slug":"second-team-org"})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let gamma = call(
        &auth,
        request(
            "/organization/create-team",
            Some(json!({"organizationId":body(&second)["id"],"name":"Gamma"})),
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
            "team",
            "team_member",
        ])
        .await?;
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = || ServerEndpoint::<JsValue>::new("organization", "listOrganizationTeams");
    let explicit = auth
        .dispatch_endpoint(
            endpoint().with_query(&json!({"organizationId":first_id}))?,
            options(&owner),
        )
        .await?;
    assert_eq!(serde_json::to_value(explicit.value())?, json!(expected));
    for query in [None, Some(json!({"organizationId":""}))] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let output = auth.dispatch_endpoint(call, options(&owner)).await?;
        assert_eq!(serde_json::to_value(output.value())?, json!([body(&gamma)]));
    }
    for (query, credentials, status, code) in [
        (
            Some(json!({"organizationId":first_id})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"organizationId":first_id})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            Some(json!({"organizationId":first_id})),
            options(&outsider),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
        ),
        (None, options(&outsider), 400, "NO_ACTIVE_ORGANIZATION"),
        (
            Some(json!({"organizationId":"not-an-organization"})),
            options(&owner),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
        ),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let error = auth.dispatch_endpoint(call, credentials).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    let typed = auth
        .dispatch_endpoint(
            OrganizationPlugin::list_organization_teams_endpoint(&TeamQuery {
                organization_id: Some(first_id),
                ..Default::default()
            })?,
            options(&owner),
        )
        .await?;
    assert_eq!(
        typed
            .decode()?
            .iter()
            .map(|team| team.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Alpha", "Beta"]
    );
    assert_eq!(
        db.tables(&[
            "users",
            "sessions",
            "organization",
            "member",
            "team",
            "team_member"
        ])
        .await?,
        before
    );
    B::close(connection).await
}
