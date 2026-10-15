//! Registered asymmetric client keys authenticate assertions and claim durable replay receipts.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::oauth::{
    OAuthClientAssertionContext, OAuthPrivateKeyJwtOptions, OAuthTokenGrant,
};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(oauth_private_key_jwt_verifies_registered_algorithms_and_rejects_replay);
postgres_tests!(oauth_private_key_jwt_verifies_registered_algorithms_and_rejects_replay);
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
async fn introspect<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    assertion: &str,
) -> alibi::AuthResult<AuthResponse> {
    let input = json!({"token":"not-issued","client_id":id,"client_assertion":assertion,"client_assertion_type":ASSERTION_TYPE});
    let outcome = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/introspect", Some(input), "")),
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
