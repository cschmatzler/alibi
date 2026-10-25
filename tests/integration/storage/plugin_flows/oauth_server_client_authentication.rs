//! Trusted server client authentication binds proofs to the caller's real logical endpoint.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::oauth::{
    OAuthClientAssertionContext, OAuthPrivateKeyJwtOptions, OAuthTokenGrant,
};
use alibi::plugins::{OAuthClientAuthenticationOptions, OAuthProviderPlugin, jwt::JwtPlugin};
use alibi::utils::json::JsValue;
use base64::{Engine as _, engine::general_purpose::STANDARD};
backend_tests!(
    oauth_server_client_authentication_checks_credentials_scope_grant_and_endpoint_proofs
);
postgres_tests!(
    oauth_server_client_authentication_checks_credentials_scope_grant_and_endpoint_proofs
);
const PATH: &str = "/fixture/authenticate-client";
fn call(body: &Value, authorization: Option<&str>) -> EndpointCall {
    let mut physical = request(PATH, Some(body.clone()), "");
    _ = physical
        .headers
        .insert("content-type".into(), "application/json".into());
    if let Some(header) = authorization {
        _ = physical
            .headers
            .insert("authorization".into(), header.into());
    }
    let route = alibi::AuthRoute::post(PATH, "authenticateClientFixture");
    EndpointCall::new(
        &EndpointDefinition {
            name: "authenticateClientFixture",
            operation_id: "authenticateClientFixture",
            path: Some(PATH.into()),
            method: route.method,
        },
        Some(JsValue::from(body.clone())),
        None,
        EndpointOptions {
            headers: Some(physical.headers.clone()),
            request: Some(physical),
            ..Default::default()
        },
    )
}
async fn proof<S: AuthSchema>(
    auth: &Alibi<S>,
    client_id: &str,
    audience: &str,
    key: &Value,
) -> TestResult<String> {
    Ok(OAuthPrivateKeyJwtOptions {
        private_key_jwk: Some(key["privateJwk"].clone()),
        algorithm: Some("RS256".into()),
        kid: Some("first".into()),
        expires_in: Some(90.0),
        ..Default::default()
    }
    .into_assertion()?
    .0
    .get_client_assertion(OAuthClientAssertionContext {
        client_id: client_id.into(),
        token_endpoint: format!(
            "{}{}{audience}",
            auth.config().base_url,
            auth.config().base_path
        ),
        grant_type: OAuthTokenGrant::AuthorizationCode,
    })
    .await?)
}
async fn oauth_server_client_authentication_checks_credentials_scope_grant_and_endpoint_proofs<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "authentication-helper@example.test").await;
    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oauth/client-assertion-keys.json"
    )))?;
    let rsa = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "RSA")
        .unwrap();
    let mut public_key = rsa["publicJwk"].clone();
    public_key["alg"] = json!("RS256");
    public_key["kid"] = json!("first");
    let mut clients = std::collections::HashMap::new();
    for method in [
        "client_secret_post",
        "client_secret_basic",
        "none",
        "private_key_jwt",
    ] {
        let mut input = json!({"client_name":method,"scope":"email profile","grant_types":["authorization_code"],"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":method});
        if method == "private_key_jwt" {
            input["jwks"] = json!({"keys":[public_key]});
        }
        let created = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "createOAuthClient")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        assert_eq!(created.status, 201);
        _ = clients.insert(method, body(&created));
    }
    let post = &clients["client_secret_post"];
    let basic = &clients["client_secret_basic"];
    let public = &clients["none"];
    let pk = &clients["private_key_jwt"];
    let basic_header = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            basic["client_id"].as_str().unwrap(),
            basic["client_secret"].as_str().unwrap()
        ))
    );
    let wrong_basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:wrong", basic["client_id"].as_str().unwrap()))
    );
    let posted = || json!({"client_id":post["client_id"],"client_secret":post["client_secret"]});
    for (
        name,
        input,
        header,
        required,
        scopes,
        grant,
        status,
        code,
        description,
        method,
        expected_id,
    ) in [
        (
            "missing",
            json!({}),
            None,
            true,
            None,
            None,
            400,
            "invalid_request",
            "Missing required client_id",
            "",
            Value::Null,
        ),
        (
            "no-credentials",
            json!({"client_id":post["client_id"]}),
            None,
            true,
            None,
            None,
            400,
            "invalid_client",
            "Missing required client credentials",
            "",
            Value::Null,
        ),
        (
            "post",
            posted(),
            None,
            true,
            None,
            None,
            200,
            "",
            "",
            "client_secret_post",
            post["client_id"].clone(),
        ),
        (
            "wrong",
            json!({"client_id":post["client_id"],"client_secret":"wrong"}),
            None,
            true,
            None,
            None,
            400,
            "invalid_client",
            "invalid client_secret",
            "",
            Value::Null,
        ),
        (
            "unknown",
            json!({"client_id":"missing-client","client_secret":"secret"}),
            None,
            true,
            None,
            None,
            400,
            "invalid_client",
            "client not found",
            "",
            Value::Null,
        ),
        (
            "public-required",
            json!({"client_id":public["client_id"]}),
            None,
            true,
            None,
            None,
            400,
            "invalid_client",
            "Missing required client credentials",
            "",
            Value::Null,
        ),
        (
            "public-optional",
            json!({"client_id":public["client_id"]}),
            None,
            false,
            None,
            None,
            200,
            "",
            "",
            "none",
            public["client_id"].clone(),
        ),
        (
            "confidential-optional",
            json!({"client_id":post["client_id"]}),
            None,
            false,
            None,
            None,
            400,
            "invalid_client",
            "client registered for client_secret_post cannot use none",
            "",
            Value::Null,
        ),
        (
            "scope",
            posted(),
            None,
            true,
            Some(vec!["email", "bogus"]),
            None,
            400,
            "invalid_scope",
            "client does not allow scope bogus",
            "",
            Value::Null,
        ),
        (
            "scope-empty",
            posted(),
            None,
            true,
            Some(vec![""]),
            None,
            400,
            "invalid_scope",
            "client does not allow scope ",
            "",
            Value::Null,
        ),
        (
            "grant",
            posted(),
            None,
            true,
            None,
            Some("client_credentials"),
            400,
            "unauthorized_client",
            "client is not authorized to use grant type client_credentials",
            "",
            Value::Null,
        ),
        (
            "refresh-grant",
            posted(),
            None,
            true,
            None,
            Some("refresh_token"),
            200,
            "",
            "",
            "client_secret_post",
            post["client_id"].clone(),
        ),
        (
            "basic",
            json!({}),
            Some(basic_header.as_str()),
            true,
            None,
            None,
            200,
            "",
            "",
            "client_secret_basic",
            basic["client_id"].clone(),
        ),
        (
            "basic-wrong",
            json!({}),
            Some(wrong_basic.as_str()),
            true,
            None,
            None,
            401,
            "invalid_client",
            "invalid client_secret",
            "",
            Value::Null,
        ),
        (
            "mixed",
            posted(),
            Some(basic_header.as_str()),
            true,
            None,
            None,
            400,
            "invalid_request",
            "A request must use only one client authentication method",
            "",
            Value::Null,
        ),
    ] {
        let options = OAuthClientAuthenticationOptions {
            require_credentials: required,
            scopes: scopes.map(|values| values.into_iter().map(str::to_owned).collect()),
        };
        let before = db
            .tables(&[
                "oauthClient",
                "oauthClientAssertion",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let result = provider
            .authenticate_client(auth.context(), &call(&input, header), grant, &options)
            .await;
        if status == 200 {
            let authenticated = result?;
            assert_eq!(json!(authenticated.client_id), expected_id, "{name}");
            assert_eq!(authenticated.client.client_id, authenticated.client_id);
            assert_eq!(authenticated.method.as_deref(), Some(method));
            assert!(authenticated.confirmation.is_none());
            assert_eq!(authenticated.client.metadata["client_name"], method);
            assert_eq!(
                authenticated.client.user_id.as_deref(),
                body(&owner)["user"]["id"].as_str()
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.error.status_code(), status, "{name}");
            assert_eq!(
                error.body.unwrap().to_json_value()?,
                json!({"error":code,"error_description":description}),
                "{name}"
            );
            assert_eq!(
                error
                    .headers
                    .as_ref()
                    .and_then(|headers| headers.get("www-authenticate"))
                    .map(String::as_str),
                if name == "basic-wrong" {
                    Some("Basic")
                } else {
                    None
                }
            );
        }
        assert_eq!(
            db.tables(&[
                "oauthClient",
                "oauthClientAssertion",
                "oauthAccessToken",
                "oauthRefreshToken"
            ])
            .await?,
            before,
            "{name}"
        );
    }
    let id = pk["client_id"].as_str().unwrap();
    let valid = proof(&auth, id, PATH, rsa).await?;
    let input = |proof: &str| json!({"client_assertion":proof,"client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"});
    let authenticated = provider
        .authenticate_client(
            auth.context(),
            &call(&input(&valid), None),
            None,
            &OAuthClientAuthenticationOptions::default(),
        )
        .await?;
    assert_eq!(authenticated.client_id, id);
    assert_eq!(authenticated.method.as_deref(), Some("private_key_jwt"));
    let replay = provider
        .authenticate_client(
            auth.context(),
            &call(&input(&valid), None),
            None,
            &OAuthClientAuthenticationOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        replay.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"client assertion jti has already been used"})
    );
    let wrong_endpoint = proof(&auth, id, "/oauth2/introspect", rsa).await?;
    let before = db.table("oauthClientAssertion").await?;
    let denied = provider
        .authenticate_client(
            auth.context(),
            &call(&input(&wrong_endpoint), None),
            None,
            &OAuthClientAuthenticationOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"client assertion signature verification failed"})
    );
    assert_eq!(db.table("oauthClientAssertion").await?, before);
    let mut introspection = input(&wrong_endpoint);
    introspection["token"] = json!("not-issued");
    let result = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect")
                .with_body(&introspection)?,
            EndpointOptions {
                request: Some(request(
                    "/oauth2/introspect",
                    Some(introspection.clone()),
                    "",
                )),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(result.status, 200);
    assert_eq!(body(&result), json!({"active":false}));
    let scoped = proof(&auth, id, PATH, rsa).await?;
    let error = provider
        .authenticate_client(
            auth.context(),
            &call(&input(&scoped), None),
            None,
            &OAuthClientAuthenticationOptions {
                require_credentials: true,
                scopes: Some(vec!["bogus".into()]),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 400);
    assert_eq!(
        error.body.unwrap().to_json_value()?,
        json!({"error":"invalid_scope","error_description":"client does not allow scope bogus"})
    );
    let replay = provider
        .authenticate_client(
            auth.context(),
            &call(&input(&scoped), None),
            None,
            &OAuthClientAuthenticationOptions {
                require_credentials: true,
                scopes: Some(vec!["email".into()]),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        replay.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"client assertion jti has already been used"})
    );
    B::close(connection).await
}
