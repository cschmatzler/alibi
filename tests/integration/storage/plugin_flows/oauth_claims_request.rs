//! OIDC claim requests survive real browser authorization and code redemption.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(oauth_claims_request_validates_and_captures_userinfo_names);
postgres_tests!(oauth_claims_request_validates_and_captures_userinfo_names);
async fn oauth_claims_request_validates_and_captures_userinfo_names<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "claims-request@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Claims request","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"none","skip_consent":true,"grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some(headers.clone()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    let id = client["client_id"].as_str().unwrap();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let authorization_options = || EndpointOptions {
        headers: Some(headers.clone()),
        request: Some(
            alibi::AuthRequest::new(
                alibi::HttpMethod::Get,
                format!("{}/oauth2/authorize", auth.config().base_path),
            )
            .with_url(
                format!(
                    "{}{}/oauth2/authorize",
                    auth.config().base_url.trim_end_matches('/'),
                    auth.config().base_path
                )
                .parse()
                .unwrap(),
            ),
        ),
        ..Default::default()
    };
    for claims in [
        json!({"userinfo":{"email":null}}),
        json!("{\"userinfo\":{\"email\":null}}"),
    ] {
        let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid offline_access","state":"claims-state","code_challenge":challenge,"code_challenge_method":"S256","claims":claims});
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            authorization_options(),
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let target = url::Url::parse(body(&response)["url"].as_str().unwrap())?;
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let issued=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"}))?,EndpointOptions::default())).await?.into_response()?;
        assert_eq!(issued.status, 200);
        let token = body(&issued)["access_token"].as_str().unwrap().to_owned();
        let info = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_user_info_endpoint(),
                EndpointOptions {
                    headers: Some(
                        [("authorization".into(), format!("Bearer {token}"))]
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
        assert_eq!(body(&info)["email"], "claims-request@example.test");
    }
    for (claims, scope, error, description) in [
        (
            json!("{"),
            "openid",
            "invalid_request",
            "claims must be a valid Claims request object",
        ),
        (
            json!({"userinfo":{"email":17}}),
            "openid",
            "invalid_request",
            "claims must be a valid Claims request object",
        ),
        (
            json!({"id_token":{"acr":{"essential":true,"value":"strong"}}}),
            "openid",
            "access_denied",
            "essential acr requirement cannot be met",
        ),
        (
            json!("{"),
            "email",
            "invalid_request",
            "openid scope must be requested when using the claims parameter",
        ),
    ] {
        let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":scope,"state":"claims-state","code_challenge":challenge,"code_challenge_method":"S256","claims":claims});
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            authorization_options(),
        ))
        .await?
        .into_response()?;
        let target = url::Url::parse(body(&response)["url"].as_str().unwrap())?;
        assert_eq!(
            target
                .query_pairs()
                .find(|(key, _)| key == "error")
                .unwrap()
                .1,
            error
        );
        assert_eq!(
            target
                .query_pairs()
                .find(|(key, _)| key == "error_description")
                .unwrap()
                .1,
            description
        );
        assert!(target.query_pairs().all(|(key, _)| key != "code"));
    }
    let updated = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthClient")
                .with_body(&json!({"client_id":id,"update":{"skip_consent":false}}))?,
            EndpointOptions {
                headers: Some(headers.clone()),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(updated.status, 200);
    let base_query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid","state":"claims-consent","code_challenge":challenge,"code_challenge_method":"S256"});
    let initial = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_authorize_endpoint(&base_query)?,
        authorization_options(),
    ))
    .await?
    .into_response()?;
    let consent_url = url::Url::parse(&format!(
        "{}{}",
        auth.config().base_url,
        body(&initial)["url"].as_str().unwrap()
    ))?;
    let consent_options = || EndpointOptions {
        headers: Some(headers.clone()),
        request: Some(
            alibi::AuthRequest::new(
                alibi::HttpMethod::Post,
                format!("{}/oauth2/consent", auth.config().base_path),
            )
            .with_url(
                format!(
                    "{}{}/oauth2/consent",
                    auth.config().base_url.trim_end_matches('/'),
                    auth.config().base_path
                )
                .parse()
                .unwrap(),
            ),
        ),
        ..Default::default()
    };
    let bootstrap = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, consent_url.query())?,
        consent_options(),
    ))
    .await?
    .into_response()?;
    assert_eq!(bootstrap.status, 200);
    let mut incremental = base_query.clone();
    incremental["claims"] = json!({"userinfo":{"email":null,"family_name":null}});
    incremental["prompt"] = json!("none");
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_authorize_endpoint(&incremental)?,
        authorization_options(),
    ))
    .await?
    .into_response()?;
    let target = url::Url::parse(body(&denied)["url"].as_str().unwrap())?;
    assert_eq!(
        target
            .query_pairs()
            .find(|(key, _)| key == "error")
            .unwrap()
            .1,
        "consent_required"
    );
    assert!(target.query_pairs().all(|(key, _)| key != "code"));
    _ = incremental.as_object_mut().unwrap().remove("prompt");
    let pending = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_authorize_endpoint(&incremental)?,
        authorization_options(),
    ))
    .await?
    .into_response()?;
    let target = url::Url::parse(&format!(
        "{}{}",
        auth.config().base_url,
        body(&pending)["url"].as_str().unwrap()
    ))?;
    let subset=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","oauth2Consent").with_body(&json!({"accept":true,"oauth_query":target.query().unwrap(),"claims":{"userinfo":{"email":null}}}))?,consent_options())).await?.into_response()?;
    assert_eq!(subset.status, 200);
    let records = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_consents_endpoint(),
        EndpointOptions {
            headers: Some(headers),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(
        body(&records)[0]["requestedUserInfoClaims"],
        json!(["email"])
    );
    Ok(())
}
