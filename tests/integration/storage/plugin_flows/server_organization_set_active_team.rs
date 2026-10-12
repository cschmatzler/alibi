//! Server active team selection publishes usable cookies and real session changes.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::OrganizationPlugin;
use alibi::plugins::organization::{
    OrganizationConfig, TeamsConfig,
    types::{NullableStringField, SetActiveTeamRequest},
};
use alibi::utils::json::JsValue;

backend_tests!(server_set_active_team_preserves_selection_and_usable_session_cookies);
async fn server_set_active_team_preserves_selection_and_usable_session_cookies<B: Backend>(
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
    let owner = Box::pin(signup(&auth, "team-selection-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "team-selection-outsider@example.test")).await;
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let organization = Box::pin(call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Team selection","slug":"team-selection"})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let id = body(&organization)["id"].as_str().unwrap().to_owned();
    let mut teams = Vec::new();
    for name in ["Alpha", "No seat"] {
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
        teams.push(body(&team));
    }
    let team_id = teams[0]["id"].as_str().unwrap().to_owned();
    let _ = Box::pin(call(
        &auth,
        request(
            "/organization/add-team-member",
            Some(json!({"teamId":team_id,"userId":user_id})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let credentials = |cookie: String| EndpointOptions {
        headers: Some([("cookie".into(), cookie)].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = |input: Value| {
        ServerEndpoint::<JsValue>::new("organization", "setActiveTeam").with_body(&input)
    };
    let before = db
        .tables(&["users", "sessions", "member", "team", "team_member"])
        .await?;
    for (input, options, status, code) in [
        (
            json!({"teamId":team_id}),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"teamId":team_id}),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "UNAUTHORIZED",
        ),
        (
            json!({"teamId":team_id}),
            credentials(cookies(&outsider)),
            400,
            "NO_ACTIVE_ORGANIZATION",
        ),
        (
            json!({"teamId":"missing-team"}),
            credentials(cookies(&owner)),
            400,
            "TEAM_NOT_FOUND",
        ),
        (
            json!({"teamId":teams[1]["id"]}),
            credentials(cookies(&owner)),
            403,
            "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(endpoint(input)?, options))
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
    let immutable = db
        .tables(&["users", "member", "team", "team_member"])
        .await?;
    let mut cookie = cookies(&owner);
    for (selection, active, emits_cookie) in [
        (NullableStringField::Missing, false, false),
        (NullableStringField::Null, false, false),
        (NullableStringField::Value(team_id.clone()), true, true),
        (NullableStringField::Missing, true, true),
        (NullableStringField::Value(String::new()), true, true),
        (NullableStringField::Null, false, true),
        (NullableStringField::Null, false, false),
    ] {
        let output = Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::set_active_team_endpoint(&SetActiveTeamRequest {
                team_id: selection,
            })?,
            credentials(cookie.clone()),
        ))
        .await?;
        assert_eq!(
            serde_json::to_value(output.value())?,
            if active {
                teams[0].clone()
            } else {
                Value::Null
            }
        );
        let wire = output.into_response()?;
        assert_eq!(
            wire.headers.get_all("set-cookie").count(),
            usize::from(emits_cookie)
        );
        if emits_cookie {
            cookie = cookies(&wire);
        }
        let observed = Box::pin(call(&auth, request("/get-session", None, &cookie), 200)).await;
        assert_eq!(body(&observed)["user"]["id"], user_id);
        assert_eq!(
            body(&observed)["session"]["activeTeamId"],
            if active { json!(team_id) } else { Value::Null }
        );
        let sessions: Vec<Value> = serde_json::from_str(&db.tables(&["sessions"]).await?[0])?;
        let stored = sessions
            .iter()
            .find(|session| session["user_id"] == user_id)
            .unwrap();
        assert_eq!(
            stored["active_team_id"],
            if active { json!(team_id) } else { Value::Null }
        );
        assert_eq!(
            db.tables(&["users", "member", "team", "team_member"])
                .await?,
            immutable
        );
    }
    B::close(connection).await
}
