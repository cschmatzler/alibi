//! Registered asymmetric client keys authenticate assertions and claim durable replay receipts.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::oauth::{
    OAuthClientAssertionContext, OAuthPrivateKeyJwtOptions, OAuthTokenGrant,
};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(
    oauth_private_key_jwt_verifies_registered_algorithms_and_rejects_replay,
    oauth_private_key_jwt_redeems_code_without_secret_and_preserves_authority_on_assertion_replay,
    oauth_private_key_jwt_honors_configured_lifetime_including_reference_number_semantics
);
postgres_tests!(
    oauth_private_key_jwt_verifies_registered_algorithms_and_rejects_replay,
    oauth_private_key_jwt_redeems_code_without_secret_and_preserves_authority_on_assertion_replay,
    oauth_private_key_jwt_honors_configured_lifetime_including_reference_number_semantics
);
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
async fn introspect<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    assertion: &str,
) -> alibi::AuthResult<AuthResponse> {
    let input = json!({"token":"not-issued","client_id":id,"client_assertion":assertion,"client_assertion_type":ASSERTION_TYPE});
    protocol(auth, "oauth2Introspect", "/oauth2/introspect", &input).await
}
async fn oauth_private_key_jwt_verifies_registered_algorithms_and_rejects_replay<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "private-jwt-owner@example.test").await;
    let other = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;

    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oauth/client-assertion-keys.json"
    )))?;
    for (algorithm, family) in [
        ("RS256", "RSA"),
        ("RS384", "RSA"),
        ("RS512", "RSA"),
        ("PS256", "RSA"),
        ("PS384", "RSA"),
        ("PS512", "RSA"),
        ("ES256", "P-256"),
        ("ES384", "P-384"),
        ("ES512", "P-521"),
        ("EdDSA", "Ed25519"),
    ] {
        let key = keys["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["family"] == family)
            .unwrap();
        let mut public = key["publicJwk"].clone();
        public["alg"] = json!(algorithm);
        public["kid"] = json!("application-key");
        let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":algorithm,"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[public]}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
        assert_eq!(created.status, 201);
        let client = body(&created);
        assert!(client.get("client_secret").is_none());
        let id = client["client_id"].as_str().unwrap();
        let assertion = OAuthPrivateKeyJwtOptions {
            private_key_jwk: Some(key["privateJwk"].clone()),
            algorithm: Some(algorithm.into()),
            kid: Some("application-key".into()),
            expires_in: Some(90.0),
            ..Default::default()
        }
        .into_assertion()?
        .0
        .get_client_assertion(OAuthClientAssertionContext {
            client_id: id.into(),
            token_endpoint: format!(
                "{}{}{}",
                auth.config().base_url,
                auth.config().base_path,
                "/oauth2/introspect"
            ),
            grant_type: OAuthTokenGrant::AuthorizationCode,
        })
        .await?;
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(assertion.split('.').nth(1).unwrap())?)?;
        let response = introspect(&auth, id, &assertion).await?;
        assert_eq!(response.status, 200, "{algorithm}: {}", body(&response));
        assert_eq!(body(&response), json!({"active":false}));
        let digest = sha2::Sha256::digest(format!(
            "private_key_jwt:{id}:{}",
            claims["jti"].as_str().unwrap()
        ));
        let receipt_id = URL_SAFE_NO_PAD.encode(&digest[..24]);
        let rows: Vec<Value> = serde_json::from_str(&db.table("oauthClientAssertion").await?)?;
        let row = rows.iter().find(|row| row["id"] == receipt_id).unwrap();
        let expires = chrono::DateTime::parse_from_rfc3339(row["expiresAt"].as_str().unwrap())?;
        assert_eq!(expires.timestamp(), claims["exp"].as_f64().unwrap() as i64);
        if algorithm == "RS256" {
            claim_cases(&auth, &other, &db, id, key).await?;
        }
        let before = db
            .tables(&[
                "oauthClientAssertion",
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let replay = introspect(&other, id, &assertion).await?;
        assert_eq!(replay.status, 400);
        assert_eq!(
            replay.headers.get("Cache-Control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            replay.headers.get("Pragma").map(String::as_str),
            Some("no-cache")
        );

        assert_eq!(
            body(&replay),
            json!({"error":"invalid_client","error_description":"client assertion jti has already been used"})
        );
        assert_eq!(
            db.tables(&[
                "oauthClientAssertion",
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken"
            ])
            .await?,
            before
        );
    }
    B::close(connection).await
}

fn sign_claims(key: &Value, claims: &Value) -> TestResult<String> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("application-key".into());
    Ok(jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(key["privatePem"].as_str().unwrap().as_bytes())?,
    )?)
}
async fn claim_cases<S: AuthSchema>(
    auth: &Alibi<S>,
    other: &Alibi<S>,
    db: &Db,
    id: &str,
    key: &Value,
) -> TestResult {
    let now = chrono::Utc::now().timestamp();
    let endpoint = format!(
        "{}{}/oauth2/introspect",
        auth.config().base_url,
        auth.config().base_path
    );
    let issuer = format!("{}{}", auth.config().base_url, auth.config().base_path);
    for (name, field, value, status, detail) in [
        ("issuer audience", "aud", Some(json!(issuer)), 200, None),
        ("future iat", "iat", Some(json!(now + 600)), 200, None),
        ("whitespace jti", "jti", Some(json!(" ")), 200, None),
        (
            "missing exp",
            "exp",
            None,
            400,
            Some("client assertion must include exp claim"),
        ),
        (
            "long exp",
            "exp",
            Some(json!(now + 600)),
            400,
            Some("client assertion exp is too far in the future (max 300s)"),
        ),
        (
            "old iat",
            "iat",
            Some(json!(now - 600)),
            400,
            Some("client assertion iat is too far in the past (max 300s)"),
        ),
        (
            "missing jti",
            "jti",
            None,
            400,
            Some("client assertion must include jti claim"),
        ),
        (
            "empty jti",
            "jti",
            Some(json!("")),
            400,
            Some("client assertion must include jti claim"),
        ),
        ("expired", "exp", Some(json!(now - 60)), 401, None),
        (
            "wrong audience",
            "aud",
            Some(json!("https://other.example.test/")),
            401,
            None,
        ),
        (
            "wrong issuer",
            "iss",
            Some(json!("other-client")),
            401,
            None,
        ),
        ("future nbf", "nbf", Some(json!(now + 600)), 401, None),
        ("wrong exp type", "exp", Some(json!("future")), 401, None),
        ("wrong signature", "signature", Some(json!(true)), 401, None),
    ] {
        let original = json!({"iss":id,"sub":id,"aud":endpoint,"iat":now,"exp":now+90,"jti":uuid::Uuid::new_v4().to_string()});
        let mut claims = original.clone();
        if field != "signature" {
            if let Some(value) = value {
                claims[field] = value;
            } else {
                _ = claims.as_object_mut().unwrap().remove(field);
            }
        }
        let mut assertion = sign_claims(key, &claims)?;
        if field == "signature" {
            let (message, signature) = assertion.rsplit_once('.').unwrap();
            let mut bytes = URL_SAFE_NO_PAD.decode(signature)?;
            bytes[0] ^= 1;
            assertion = format!("{message}.{}", URL_SAFE_NO_PAD.encode(bytes));
        }
        let before = db
            .tables(&[
                "oauthClientAssertion",
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let result = introspect(auth, id, &assertion).await?;
        assert_eq!(result.status, status, "{name}: {}", body(&result));
        assert_eq!(
            body(&result),
            if status == 200 {
                json!({"active":false})
            } else {
                json!({"error":"invalid_client","error_description":detail.unwrap_or("client assertion signature verification failed")})
            },
            "{name}"
        );
        if status != 200 {
            assert_eq!(
                db.tables(&[
                    "oauthClientAssertion",
                    "oauthClient",
                    "oauthAccessToken",
                    "oauthRefreshToken"
                ])
                .await?,
                before,
                "{name}"
            );
            let repaired = introspect(other, id, &sign_claims(key, &original)?).await?;
            assert_eq!(repaired.status, 200, "{name} must not consume jti");
            assert_eq!(body(&repaired), json!({"active":false}));
        }
    }
    Ok(())
}

async fn protocol<S: AuthSchema>(
    auth: &Alibi<S>,
    operation: &'static str,
    path: &str,
    input: &Value,
) -> alibi::AuthResult<AuthResponse> {
    let outcome = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(input)?,
        EndpointOptions {
            request: Some(request(path, Some(input.clone()), "")),
            ..Default::default()
        },
    ))
    .await;
    match outcome {
        Ok(output) => output.into_response(),
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()
        }
    }
}
fn proof<S: AuthSchema>(
    auth: &Alibi<S>,
    key: &Value,
    id: &str,
    endpoint: &str,
) -> TestResult<String> {
    let now = chrono::Utc::now().timestamp();
    sign_claims(
        key,
        &json!({"iss":id,"sub":id,"aud":format!("{}{}/oauth2/{endpoint}",auth.config().base_url,auth.config().base_path),"iat":now,"exp":now+90,"jti":uuid::Uuid::new_v4().to_string()}),
    )
}
async fn oauth_private_key_jwt_redeems_code_without_secret_and_preserves_authority_on_assertion_replay<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "private-jwt-code-owner@example.test").await;
    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oauth/client-assertion-keys.json"
    )))?;
    let key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "RSA")
        .unwrap();
    let mut public = key["publicJwk"].clone();
    public["alg"] = json!("RS256");
    public["kid"] = json!("application-key");
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Signed code client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"private_key_jwt","scope":"email","skip_consent":true,"require_pkce":false,"jwks":{"keys":[public]}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    assert!(client.get("client_secret").is_none());
    let id = client["client_id"].as_str().unwrap();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"signed-state"});
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
    let code = callback
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let assertion = proof(&auth, key, id, "token")?;
    let mut input = json!({"grant_type":"authorization_code","code":code,"redirect_uri":"https://app.fixture.test/callback","client_assertion":assertion,"client_assertion_type":ASSERTION_TYPE});
    input["client_assertion"] = json!(proof(&auth, key, id, "introspect")?);
    let before = db
        .tables(&[
            "verification",
            "oauthAccessToken",
            "oauthRefreshToken",
            "oauthClientAssertion",
        ])
        .await?;
    let rejected = protocol(&auth, "oauth2Token", "/oauth2/token", &input).await?;
    assert_eq!(rejected.status, 401);
    assert_eq!(
        rejected.headers.get("Cache-Control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        rejected.headers.get("Pragma").map(String::as_str),
        Some("no-cache")
    );

    assert_eq!(
        body(&rejected),
        json!({"error":"invalid_client","error_description":"client assertion signature verification failed"})
    );
    assert_eq!(
        db.tables(&[
            "verification",
            "oauthAccessToken",
            "oauthRefreshToken",
            "oauthClientAssertion"
        ])
        .await?,
        before
    );
    input["client_assertion"] = json!(assertion);
    let response = protocol(&auth, "oauth2Token", "/oauth2/token", &input).await?;
    assert_eq!(response.status, 200, "{}", body(&response));
    let token = body(&response);
    assert_eq!(token["scope"], "email");
    assert_eq!(token["token_type"], "Bearer");
    let plaintext = token["access_token"].as_str().unwrap();
    let hash = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(plaintext));
    let stored = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
        .await?
        .unwrap();
    assert_eq!(stored.client_id, id);
    assert_eq!(
        stored.authorization_code_id.as_deref(),
        Some(URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&code)).as_str())
    );

    assert_eq!(stored.metadata["scopes"], json!(["email"]));
    let replay = protocol(&auth, "oauth2Token", "/oauth2/token", &input).await?;
    assert_eq!(replay.status, 400);
    assert_eq!(
        replay.headers.get("Cache-Control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        replay.headers.get("Pragma").map(String::as_str),
        Some("no-cache")
    );

    assert_eq!(
        body(&replay),
        json!({"error":"invalid_client","error_description":"client assertion jti has already been used"})
    );
    let inspect = json!({"token":plaintext,"client_assertion":proof(&auth,key,id,"introspect")?,"client_assertion_type":ASSERTION_TYPE});
    let active = protocol(&auth, "oauth2Introspect", "/oauth2/introspect", &inspect).await?;
    assert_eq!(active.status, 200);
    assert_eq!(body(&active)["active"], true);
    assert_eq!(body(&active)["client_id"], id);
    assert_eq!(body(&active)["azp"], id);
    assert_eq!(
        body(&active)["iss"],
        format!("{}{}", auth.config().base_url, auth.config().base_path)
    );
    assert_eq!(body(&active)["sub"], json!(stored.user_id));
    assert_eq!(body(&active)["sid"], json!(stored.session_id));
    assert_eq!(body(&active)["exp"], stored.expires_at.timestamp());
    assert_eq!(body(&active)["iat"], stored.created_at.timestamp());
    assert_eq!(body(&active)["scope"], "email");
    assert_eq!(body(&active)["token_type"], "Bearer");

    input["client_assertion"] = json!(proof(&auth, key, id, "token")?);
    let code_replay = protocol(&auth, "oauth2Token", "/oauth2/token", &input).await?;
    assert_eq!(code_replay.status, 400);
    assert_eq!(
        body(&code_replay),
        json!({"error":"invalid_grant","error_description":"invalid code"})
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
            .await?
            .is_none()
    );
    B::close(connection).await
}

async fn oauth_private_key_jwt_honors_configured_lifetime_including_reference_number_semantics<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let seed = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&seed, "assertion-lifetime-owner@example.test").await;
    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oauth/client-assertion-keys.json"
    )))?;
    let key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "RSA")
        .unwrap();
    let mut public = key["publicJwk"].clone();
    public["alg"] = json!("RS256");
    public["kid"] = json!("application-key");
    let created=Box::pin(seed.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Assertion lifetime","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[public]}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    let id = client["client_id"].as_str().unwrap();
    let unlimited = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(
            alibi::plugins::OAuthProviderConfig {
                assertion_max_lifetime: f64::INFINITY,
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let now = chrono::Utc::now().timestamp();
    for (name, max, exp, iat, status, detail) in [
        (
            "short",
            30.0,
            90,
            0,
            400,
            Some("client assertion exp is too far in the future (max 30s)"),
        ),
        (
            "short-past",
            30.0,
            20,
            -90,
            400,
            Some("client assertion iat is too far in the past (max 30s)"),
        ),
        ("short-future", 30.0, 20, 90, 200, None),
        (
            "zero",
            0.0,
            20,
            0,
            400,
            Some("client assertion exp is too far in the future (max 0s)"),
        ),
        (
            "negative",
            -1.0,
            20,
            0,
            400,
            Some("client assertion exp is too far in the future (max -1s)"),
        ),
        ("nan", f64::NAN, 600, -600, 200, None),
        ("infinite", f64::INFINITY, 600, -600, 200, None),
        (
            "negative-infinite",
            f64::NEG_INFINITY,
            20,
            0,
            400,
            Some("client assertion exp is too far in the future (max -Infinitys)"),
        ),
    ] {
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    assertion_max_lifetime: max,
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let claims = json!({"iss":id,"sub":id,"aud":format!("{}{}/oauth2/introspect",auth.config().base_url,auth.config().base_path),"exp":now+exp,"iat":now+iat,"jti":uuid::Uuid::new_v4().to_string()});
        let assertion = sign_claims(key, &claims)?;
        let before = db
            .tables(&[
                "oauthClientAssertion",
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let response = introspect(&auth, id, &assertion).await?;
        assert_eq!(response.status, status, "{name}: {}", body(&response));
        assert_eq!(
            body(&response),
            detail.map_or_else(
                || json!({"active":false}),
                |detail| json!({"error":"invalid_client","error_description":detail})
            ),
            "{name}"
        );
        if status != 200 {
            assert_eq!(
                db.tables(&[
                    "oauthClientAssertion",
                    "oauthClient",
                    "oauthAccessToken",
                    "oauthRefreshToken"
                ])
                .await?,
                before,
                "{name}"
            );
            let retry = introspect(&unlimited, id, &assertion).await?;
            assert_eq!(retry.status, 200, "{name} must not consume jti");
            assert_eq!(body(&retry), json!({"active":false}));
        }
    }
    B::close(connection).await
}
