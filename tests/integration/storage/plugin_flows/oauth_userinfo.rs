//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_userinfo_resolves_scoped_claims_from_real_access_authority);
async fn oauth_userinfo_resolves_scoped_claims_from_real_access_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "userinfo-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile","token_endpoint_auth_method":"none","skip_consent":true}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email profile","state":"token-state","nonce":"oidc-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
    let grant = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("accept".into(), "application/json".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(grant.status, 200);
    let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
    assert_eq!(callback.path(), "/callback");
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let endpoint =
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?;
    let output = Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(output.status, 200);
    let token = body(&output);
    assert_eq!(token["scope"], "openid email profile");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    assert!(token.get("refresh_token").is_none());

    let expected = json!({"sub":body(&owner)["user"]["id"],"name":"Native owner","given_name":"Native","family_name":"owner","email":"userinfo-owner@example.test","email_verified":false});
    for (header, input, method, attach) in [
        (format!("Bearer {plaintext}"), None, HttpMethod::Get, true),
        (
            format!("bearer   {plaintext}  "),
            None,
            HttpMethod::Get,
            true,
        ),
        (plaintext.to_owned(), None, HttpMethod::Get, true),
        (format!("Bearer {plaintext}"), None, HttpMethod::Get, false),
        (
            String::new(),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Post,
            true,
        ),
    ] {
        let endpoint = ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo");
        let endpoint = if let Some(body) = &input {
            endpoint.with_body(body)?
        } else {
            endpoint
        };
        let mut physical = request("/oauth2/userinfo", input.clone(), "");
        physical.method = method.clone();
        let response = Box::pin(auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                headers: Some([("authorization".into(), header)].into_iter().collect()),
                request: attach.then_some(physical),
                method: Some(method),
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
        assert_eq!(body(&response), expected);
    }
    for (header, input, method, attach, status, error, description) in [
        (
            String::new(),
            None,
            HttpMethod::Get,
            true,
            401,
            "invalid_request",
            "access token not found",
        ),
        (
            String::new(),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Get,
            true,
            401,
            "invalid_request",
            "access token not found",
        ),
        (
            String::new(),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Post,
            false,
            401,
            "invalid_request",
            "access token not found",
        ),
        (
            format!("Bearer {plaintext}"),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Post,
            true,
            400,
            "invalid_request",
            "Multiple access token transport methods are not allowed",
        ),
        (
            "Bearer missing-token".into(),
            None,
            HttpMethod::Get,
            true,
            401,
            "invalid_token",
            "Invalid access token",
        ),
        (
            format!("DPoP {plaintext}"),
            None,
            HttpMethod::Get,
            true,
            401,
            "invalid_token",
            "DPoP authorization requires a DPoP-bound access token",
        ),
    ] {
        let endpoint = ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo");
        let endpoint = if let Some(body) = &input {
            endpoint.with_body(body)?
        } else {
            endpoint
        };
        let mut physical = request("/oauth2/userinfo", input, "");
        physical.method = method.clone();
        let denied = Box::pin(auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                headers: Some([("authorization".into(), header)].into_iter().collect()),
                request: attach.then_some(physical),
                method: Some(method),
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if description == "Invalid access token" {
            assert_eq!(
                denied
                    .headers
                    .as_ref()
                    .and_then(|headers| headers.get("www-authenticate"))
                    .map(String::as_str),
                Some("Bearer error=\"invalid_token\", error_description=\"Invalid access token\"")
            );
        }
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":error,"error_description":description})
        );
    }

    for scope in ["openid", "email"] {
        let mut query = query.clone();
        query["scope"] = json!(scope);
        if scope == "email" {
            _ = query.as_object_mut().unwrap().remove("nonce");
        }
        let grant = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
                EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), cookies(&owner)),
                            ("accept".into(), "application/json".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    request: Some(request("/oauth2/authorize", None, "")),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?;
        let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
        let issued = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        let scoped_token = body(&issued)["access_token"].as_str().unwrap().to_owned();
        let result = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo"),
                EndpointOptions {
                    headers: Some(
                        [("authorization".into(), format!("Bearer {scoped_token}"))]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await;
        if scope == "openid" {
            assert_eq!(
                body(&result?.into_response()?),
                json!({"sub":body(&owner)["user"]["id"]})
            );
            let input =
                json!({"client_id":id,"token":scoped_token,"token_type_hint":"access_token"});
            let retired = Box::pin(auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&input)?,
                EndpointOptions {
                    request: Some(request("/oauth2/revoke", Some(input), "")),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            assert_eq!(retired.status, 200);
            let denied = Box::pin(
                auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo"),
                    EndpointOptions {
                        headers: Some(
                            [("authorization".into(), format!("Bearer {scoped_token}"))]
                                .into_iter()
                                .collect(),
                        ),
                        ..Default::default()
                    },
                ),
            )
            .await
            .unwrap_err();
            assert_eq!(denied.error.status_code(), 401);
            assert_eq!(
                denied.body.unwrap().to_json_value()?,
                json!({"error":"invalid_token","error_description":"Invalid access token"})
            );
        } else {
            let denied = result.unwrap_err();
            assert_eq!(denied.error.status_code(), 400);
            assert_eq!(
                denied.body.unwrap().to_json_value()?,
                json!({"error":"invalid_scope","error_description":"Missing required scope"})
            );
        }
    }
    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    auth.store()
        .update_session_expiry(
            body(&observed)["session"]["token"].as_str().unwrap(),
            chrono::Utc::now() - chrono::Duration::seconds(1),
        )
        .await?;
    let denied = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo"),
            EndpointOptions {
                headers: Some(
                    [("authorization".into(), format!("Bearer {plaintext}"))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_token","error_description":"Invalid access token"})
    );
    Ok(())
}
