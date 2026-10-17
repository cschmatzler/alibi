//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
#[path = "../../../fixtures/oauth/token-response-fields.rs"]
pub(super) mod token_response_fields;
backend_tests!(
    oauth_token_exchanges_bound_code_and_revokes_on_replay,
    oauth_configured_token_response_fields_follow_real_grant_lifecycle
);

async fn oauth_configured_token_response_fields_follow_real_grant_lifecycle<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession as _;
    use alibi::plugins::{OAuthProviderConfig, OAuthTokenIssueParams};
    use alibi::store::OAuthTokenKind;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let fields = Arc::new(token_response_fields::TokenResponseFields::default());
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        custom_token_response_fields: Some(fields.clone()),
        disable_jwt_plugin: true,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "response-owner@example.test").await;
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let session = auth
        .store()
        .get_user_sessions(&user_id)
        .await?
        .pop()
        .unwrap();
    let options = || EndpointOptions {
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
    };
    let created = Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
        "client_name":"Response fields","redirect_uris":["https://app.fixture.test/callback"],
        "scope":"profile email offline_access","token_endpoint_auth_method":"none","skip_consent":true,
        "metadata":{"tenant":"application"}
    }))?, options())).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client_id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let resource = "https://api.fixture.test/response-fields";
    let registered = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthResource").with_body(
            &json!({"identifier":resource,"allowedScopes":["email","offline_access"]}),
        )?,
        options(),
    ))
    .await?
    .into_response()?;
    assert_eq!(registered.status, 200);
    let linked = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminLinkClientResource")
                .with_params(&json!({"identifier":resource,"client_id":client_id}))?,
            options(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(linked.status, 200);
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":client_id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback",
        "scope":"profile email offline_access","resource":resource,"state":"response-state","code_challenge":challenge,"code_challenge_method":"S256"});
    let mut issued = Value::Null;
    for mode in ["ordinary", "api", "success"] {
        *fields.mode.lock().unwrap() = mode.into();
        let grant = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            options(),
        ))
        .await?
        .into_response()?;
        assert_eq!(grant.status, 200);
        let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let input = json!({"grant_type":"authorization_code","client_id":client_id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
        let result = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
            EndpointOptions::default(),
        ))
        .await;
        if mode == "success" {
            issued = body(&result?.into_response()?);
            assert_eq!(
                issued["application_metadata"],
                json!({"service":"billing","plan":"pro"})
            );
        } else {
            let failure = result.unwrap_err();
            assert_eq!(
                failure.error.status_code(),
                if mode == "api" { 422 } else { 500 }
            );
            if mode == "api" {
                assert!(
                    matches!(failure.error, alibi::AuthError::Api {code:Some(ref code), ref message, ..} if code == "RESPONSE_REJECTED" && message == "Operator response denied")
                );
            }
            for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
                assert!(
                    auth.store()
                        .list_oauth_tokens_for_session(kind, session.id().as_ref())
                        .await?
                        .is_empty()
                );
            }
        }
    }
    let receipt = json!({"grant":"authorization_code","userId":user_id,"email":"response-owner@example.test",
        "scopes":["email","offline_access"],"metadata":{"tenant":"application"},
        "verification":{"type":"authorization_code","userId":user_id,"sessionId":session.id().as_ref(),
            "scope":"profile email offline_access","state":"response-state","clientId":client_id,"challenge":challenge}});
    assert_eq!(*fields.calls.lock().unwrap(), vec![receipt; 3]);
    let original = issued["refresh_token"].as_str().unwrap().to_owned();
    for mode in ["ordinary", "api", "success"] {
        *fields.mode.lock().unwrap() = mode.into();
        let input = json!({"grant_type":"refresh_token","client_id":client_id,"refresh_token":original,"scope":"email"});
        let result = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
            EndpointOptions::default(),
        ))
        .await;
        if mode == "success" {
            issued = body(&result?.into_response()?);
        } else {
            let failure = result.unwrap_err();
            assert_eq!(
                failure.error.status_code(),
                if mode == "api" { 422 } else { 500 }
            );
            if mode == "api" {
                assert!(
                    matches!(failure.error, alibi::AuthError::Api {code:Some(ref code), ref message, ..} if code == "RESPONSE_REJECTED" && message == "Operator response denied")
                );
            }
            for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
                assert_eq!(
                    auth.store()
                        .list_oauth_tokens_for_session(kind, session.id().as_ref())
                        .await?
                        .len(),
                    1
                );
            }
            let hash = provider.hash_token(&original, "refresh_token").await?;
            let row = auth
                .store()
                .get_oauth_token(OAuthTokenKind::Refresh, &hash)
                .await?
                .unwrap();
            assert!(row.metadata.get("revoked").is_none_or(Value::is_null));
        }
    }
    assert_eq!(
        &fields.calls.lock().unwrap()[3..],
        vec![
            json!({"grant":"refresh_token","userId":user_id,
        "email":"response-owner@example.test","scopes":["email"],"metadata":{"tenant":"application"},"verification":null});
            3
        ]
    );
    assert_eq!(issued["scope"], "email");
    assert_eq!(
        issued["application_metadata"],
        json!({"service":"billing","plan":"pro"})
    );
    assert_eq!(issued["per_request"], "global");
    assert_eq!(issued["toString"], "application-toString");
    assert_eq!(issued["__proto__"], json!({"applicationPrototype":true}));
    assert_eq!(issued["nullable"], Value::Null);
    assert_eq!(issued["token_type"], "Bearer");
    assert_eq!(issued["expires_in"], 3600);
    assert!(issued.get("id_token").is_none());
    assert_ne!(issued["refresh_token"], original);
    for (key, kind) in [
        ("access_token", OAuthTokenKind::Access),
        ("refresh_token", OAuthTokenKind::Refresh),
    ] {
        let token = issued[key].as_str().unwrap();
        let hash = provider.hash_token(token, key).await?;
        let row = auth.store().get_oauth_token(kind, &hash).await?.unwrap();
        assert_eq!(row.client_id, client_id);
        assert_eq!(row.user_id.as_deref(), Some(user_id.as_str()));
        assert_eq!(row.metadata["scopes"], json!(["email"]));
        if key == "access_token" {
            assert_eq!(
                row.expires_at.timestamp(),
                issued["expires_at"].as_i64().unwrap()
            );
        }
    }
    // Trusted per-issuance fields override global fields, never protocol fields,
    // including optional protocol fields that are absent for a machine token.
    let client = provider
        .get_client(auth.context(), &client_id)
        .await?
        .unwrap();
    let mut params = OAuthTokenIssueParams::new(client, vec!["email".into()]);
    params.token_response = Some(
        json!({"per_request":"native","access_token":"injected","refresh_token":"injected","id_token":"injected"}),
    );
    let call = alibi::endpoint::EndpointCall::new(
        &alibi::endpoint::EndpointDefinition {
            name: "nativeResponse",
            operation_id: "nativeResponse",
            path: None,
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let machine = provider
        .issue_tokens(auth.context(), &call, Some("urn:native:response"), &params)
        .await?;
    assert_eq!(machine["per_request"], "native");
    assert_eq!(
        machine["application_metadata"],
        json!({"service":"billing","plan":"pro"})
    );
    assert_eq!(machine["token_type"], "Bearer");
    assert_eq!(machine["scope"], "email");
    assert!(machine.get("refresh_token").is_none());
    assert!(machine.get("id_token").is_none());
    let hash = provider
        .hash_token(machine["access_token"].as_str().unwrap(), "access_token")
        .await?;
    assert!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Access, &hash)
            .await?
            .unwrap()
            .user_id
            .is_none()
    );
    assert_eq!(
        fields.calls.lock().unwrap().last(),
        Some(
            &json!({"grant":"urn:native:response","userId":null,"email":null,"scopes":["email"],"metadata":{"tenant":"application"},"verification":null})
        )
    );
    Ok(())
}
async fn oauth_token_exchanges_bound_code_and_revokes_on_replay<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "token-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none","skip_consent":true}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"token-state","code_challenge":challenge,"code_challenge_method":"S256"});
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
    assert_eq!(token["scope"], "email");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    assert!(token.get("refresh_token").is_none());
    assert!(token.get("id_token").is_none());
    let hashed =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(plaintext));
    let stored = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hashed)
        .await?
        .unwrap();
    assert_eq!(stored.client_id, id);
    assert_eq!(stored.metadata["scopes"], json!(["email"]));
    assert_eq!(
        stored.expires_at.timestamp() - stored.created_at.timestamp(),
        3600
    );
    assert_eq!(
        stored.expires_at.timestamp(),
        token["expires_at"].as_i64().unwrap()
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, plaintext)
            .await?
            .is_none()
    );
    let replay = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        replay.body.unwrap().to_json_value()?,
        json!({"error":"invalid_grant","error_description":"invalid code"})
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hashed)
            .await?
            .is_none()
    );

    for (field, wrong, status, description) in [
        (
            "code_verifier",
            "wrong-verifier",
            401,
            "code verification failed",
        ),
        (
            "redirect_uri",
            "https://app.fixture.test/other",
            400,
            "redirect_uri mismatch",
        ),
    ] {
        let produced = Box::pin(
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
        let callback = url::Url::parse(body(&produced)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let mut input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
        input[field] = json!(wrong);
        let denied = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input.clone()), "")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":if status==401{"invalid_request"}else{"invalid_grant"},"error_description":description})
        );
        input[field] = json!(if field == "code_verifier" {
            verifier
        } else {
            "https://app.fixture.test/callback"
        });
        let retry = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input), "")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(retry.error.status_code(), 400);
        assert_eq!(
            retry.body.unwrap().to_json_value()?,
            json!({"error":"invalid_grant","error_description":"invalid code"})
        );
    }
    Ok(())
}
