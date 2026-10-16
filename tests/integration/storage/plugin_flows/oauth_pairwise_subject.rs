use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin,
};
use alibi::{AuthSession as _, AuthUser as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

backend_tests!(oauth_pairwise_presentation_preserves_internal_identity_and_retires_session);
postgres_tests!(oauth_pairwise_presentation_preserves_internal_identity_and_retires_session);

async fn oauth_pairwise_presentation_preserves_internal_identity_and_retires_session<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.advanced.database.generate_id = Some(alibi::config::DatabaseIdStrategy::Custom(
        Arc::new(|model: &str, _: Option<usize>| {
            Ok(Some(if model == "user" {
                "pairwise-owner".into()
            } else {
                uuid::Uuid::new_v4().to_string()
            }))
        }),
    ));
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        pairwise_secret: Some("fixture-pairwise-secret-at-least-32-characters".into()),
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "pairwise@example.test").await;
    assert_eq!(body(&owner)["user"]["id"], "pairwise-owner");
    let created = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthClient").with_body(&json!({
            "client_name":"Pairwise consumer","redirect_uris":["https://app.fixture.test/callback"],
            "subject_type":"pairwise","scope":"openid profile offline_access",
            "token_endpoint_auth_method":"client_secret_post",
            "grant_types":["authorization_code","refresh_token"],"enable_end_session":true
        }))?,
        EndpointOptions { headers:Some([("cookie".into(), cookies(&owner))].into_iter().collect()), ..Default::default() },
    )).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = provider
        .get_client(
            auth.context(),
            body(&created)["client_id"].as_str().unwrap(),
        )
        .await?
        .unwrap();
    let user = auth
        .store()
        .get_user_by_id("pairwise-owner")
        .await?
        .unwrap();
    let session = auth
        .store()
        .get_user_sessions(user.id().as_ref())
        .await?
        .pop()
        .unwrap();
    let mut params = OAuthTokenIssueParams::new(
        client.clone(),
        vec!["openid".into(), "profile".into(), "offline_access".into()],
    );
    params.user = Some(auth.context().trusted_user_view(&user));
    params.session_id = Some(session.id().as_ref().into());
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "pairwise",
            operation_id: "pairwise",
            path: Some("/fixture/pairwise".into()),
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let tokens = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:pairwise"), &params)
        .await?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(
            tokens["id_token"]
                .as_str()
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        )?,
    )?;
    let expected = "pXrBQW8RVZxizqoE0yPPjNWilWCkov57HwhsIQTIwdw=";
    assert_eq!(claims["sub"], expected);
    let access = tokens["access_token"].as_str().unwrap();
    let internal = provider
        .require_active_access_token(auth.context(), access, None)
        .await?;
    assert_eq!(internal["sub"], "pairwise-owner");
    let info = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_user_info_endpoint(),
            EndpointOptions {
                headers: Some(
                    [("authorization".into(), format!("Bearer {access}"))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(info.status, 200);
    assert_eq!(body(&info)["sub"], expected);
    assert_eq!(body(&info)["name"], "Native owner");
    for kind in ["access_token", "refresh_token"] {
        let inspected = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_introspect_endpoint(&json!({
                "client_id":client.client_id,"client_secret":body(&created)["client_secret"],
                "token":tokens[kind],"token_type_hint":kind,
            }))?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        assert_eq!(inspected.status, 200);
        assert_eq!(body(&inspected)["active"], true);
        assert_eq!(body(&inspected)["sub"], expected);
    }
    let ended = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_end_session_endpoint(&json!({
            "client_id":client.client_id,"id_token_hint":tokens["id_token"]
        }))?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(ended.status, 200);
    assert!(
        auth.store()
            .get_session_by_id(session.id().as_ref())
            .await?
            .is_none()
    );
    assert_eq!(
        auth.store()
            .get_user_by_id("pairwise-owner")
            .await?
            .unwrap()
            .id()
            .as_ref(),
        "pairwise-owner"
    );
    Ok(())
}
