//! Genuine DPoP proofs reserve one-time authority through each physical adapter.
use super::*;
use alibi::AuthVerification as _;
use alibi::plugins::oauth2::{
    AccessTokenAuthorization, DpopError, DpopReplayReservations, DpopVerificationReservation,
    EnforceDpopBindingParams, VerifyDpopProofOptions, create_dpop_replay_store,
    create_in_memory_dpop_replay_store, enforce_dpop_binding, get_dpop_jkt_from_payload,
    parse_access_token_authorization, strip_access_token_authorization_scheme, verify_dpop_proof,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(
    oauth_dpop_proof_verifies_external_signature_context_and_atomic_receipt,
    oauth_dpop_issuance_requires_proof_and_rotates_bound_refresh
);
postgres_tests!(
    oauth_dpop_proof_verifies_external_signature_context_and_atomic_receipt,
    oauth_dpop_issuance_requires_proof_and_rotates_bound_refresh
);
struct ForwardReservations<'a, S: alibi::AuthSchema> {
    context: &'a alibi::AuthContext<S>,
    observed: std::sync::Mutex<Option<DpopVerificationReservation>>,
}
#[async_trait::async_trait]
impl<S: alibi::AuthSchema> DpopReplayReservations for ForwardReservations<'_, S> {
    async fn reserve_verification_value(
        &self,
        data: DpopVerificationReservation,
    ) -> Result<bool, DpopError> {
        {
            *self.observed.lock().unwrap() = Some(data.clone());
        }
        DpopReplayReservations::reserve_verification_value(self.context, data).await
    }
}
async fn oauth_dpop_issuance_requires_proof_and_rotates_bound_refresh<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
    use alibi::plugins::{OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin};
    use alibi::store::OAuthTokenKind;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "dpop-issuer@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"DPoP issuer","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"],"dpop_bound_access_tokens":true}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let user = auth
        .store()
        .get_user_by_id(client.user_id.as_deref().unwrap())
        .await?
        .unwrap();
    let mut params =
        OAuthTokenIssueParams::new(client, vec!["email".into(), "offline_access".into()]);
    params.user = Some(auth.context().trusted_user_view(&user));
    let definition = EndpointDefinition {
        name: "issueTokensFixture",
        operation_id: "issueTokensFixture",
        path: Some("/fixture/issue-tokens".into()),
        method: alibi::HttpMethod::Post,
    };
    let call = |jwt: Option<&str>| {
        EndpointCall::new(
            &definition,
            None,
            None,
            EndpointOptions {
                headers: jwt.map(|value| [("DPoP".into(), value.into())].into_iter().collect()),
                ..Default::default()
            },
        )
    };
    let missing = provider
        .issue_tokens(
            auth.context(),
            &call(None),
            Some("urn:fixture:dpop"),
            &params,
        )
        .await
        .unwrap_err();
    assert_eq!(missing.error.status_code(), 400);
    assert_eq!(
        missing.body.unwrap().to_json_value()?,
        json!({"error":"invalid_dpop_proof","error_description":"DPoP proof header is required"})
    );
    let url = format!(
        "{}{}/oauth2/token",
        auth.config().base_url.trim_end_matches('/'),
        auth.config().base_path
    );
    let make_proof = |jti: &str| {
        proof(
            json!({"htm":"POST","htu":url,"jti":jti,"iat":chrono::Utc::now().timestamp()}),
            json!({}),
        )
    };
    let invalid = make_proof("native-corrupt")?;
    let parts = invalid.split('.').collect::<Vec<_>>();
    let mut signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    *signature.first_mut().unwrap() ^= 1;
    let invalid = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(signature)
    );
    let denied = provider
        .issue_tokens(
            auth.context(),
            &call(Some(&invalid)),
            Some("urn:fixture:dpop"),
            &params,
        )
        .await
        .unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?["error_description"],
        "signature verification failed"
    );
    let jwt = make_proof("native-issuance")?;
    let issued = provider
        .issue_tokens(
            auth.context(),
            &call(Some(&jwt)),
            Some("urn:fixture:dpop"),
            &params,
        )
        .await?;
    assert_eq!(issued["token_type"], "DPoP");
    let confirmation = json!({"jkt":"yAJQz9pEsZrW3t2ISLq2eQ2bDNmV0AHCGdbF-8RSbko"});
    assert_eq!(
        provider
            .validate_access_token(
                auth.context(),
                issued["access_token"].as_str().unwrap(),
                None
            )
            .await?["cnf"],
        confirmation
    );
    let replay = provider
        .issue_tokens(
            auth.context(),
            &call(Some(&jwt)),
            Some("urn:fixture:dpop"),
            &params,
        )
        .await
        .unwrap_err();
    assert_eq!(
        replay.body.unwrap().to_json_value()?["error_description"],
        "DPoP proof jti has already been used"
    );
    let hash = provider
        .hash_token(issued["refresh_token"].as_str().unwrap(), "refresh_token")
        .await?;
    params.refresh_token = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &hash)
        .await?;
    let missing = provider
        .issue_tokens(
            auth.context(),
            &call(None),
            Some("urn:fixture:dpop"),
            &params,
        )
        .await
        .unwrap_err();
    assert_eq!(missing.error.status_code(), 400);
    let jwt = make_proof("native-rotation")?;
    let rotated = provider
        .issue_tokens(
            auth.context(),
            &call(Some(&jwt)),
            Some("urn:fixture:dpop"),
            &params,
        )
        .await?;
    assert_eq!(rotated["token_type"], "DPoP");
    assert_ne!(rotated["refresh_token"], issued["refresh_token"]);
    let hash = provider
        .hash_token(rotated["refresh_token"].as_str().unwrap(), "refresh_token")
        .await?;
    assert_eq!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Refresh, &hash)
            .await?
            .unwrap()
            .metadata["confirmation"],
        confirmation
    );
    let refresh_body = json!({"grant_type":"refresh_token","client_id":id,"refresh_token":rotated["refresh_token"]});
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&refresh_body)?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(
        denied.body.unwrap().to_json_value()?["error_description"],
        "DPoP proof header is required"
    );
    let jwt = make_proof("native-protocol-refresh")?;
    let response = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&refresh_body)?,
        EndpointOptions {
            headers: Some([("dpop".into(), jwt)].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(response.status, 200);
    assert_eq!(body(&response)["token_type"], "DPoP");
    Ok(())
}
fn proof(payload: Value, extra: Value) -> TestResult<String> {
    use ed25519_dalek::Signer as _;
    let keys: Value = serde_json::from_str(include_str!(
        "../../../fixtures/oauth/client-assertion-keys.json"
    ))?;
    let key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "Ed25519")
        .unwrap();
    let mut header = json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":key["publicJwk"]});
    header
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    );
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key["privateJwk"]["d"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let signature = ed25519_dalek::SigningKey::from_bytes(&seed).sign(message.as_bytes());
    Ok(format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}
async fn oauth_dpop_proof_verifies_external_signature_context_and_atomic_receipt<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .build()
        .await?;
    let token = proof(
        json!({"htm":"post","htu":"https://api.fixture.test/resource?ignored=1","jti":"native-proof","iat":2000000000}),
        json!({}),
    )?;
    let store = create_dpop_replay_store(auth.context());
    let mut options =
        VerifyDpopProofOptions::new(&token, "POST", "https://api.fixture.test/resource?other=2");
    options.now_seconds = Some(2000000000.0);
    options.replay_store = Some(&store);
    let verified = verify_dpop_proof(&options).await?;
    assert_eq!(verified.htm, "post");
    assert_eq!(verified.htu, "https://api.fixture.test/resource");
    assert_eq!(verified.iat, 2000000000.0);
    let input = format!(
        "{}\nPOST\nhttps://api.fixture.test/resource\nnative-proof",
        verified.jkt
    );
    assert_eq!(
        verified.replay_key,
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input))
    );
    assert_eq!(verified.expires_at.unwrap().timestamp(), 2000000300);
    let row = auth
        .store()
        .get_verification_by_identifier(&format!("dpop-proof:{}", verified.replay_key))
        .await?
        .unwrap();
    assert_eq!(row.value(), verified.replay_key);
    assert_eq!(row.expires_at().timestamp(), 2000000300);
    let duplicate = verify_dpop_proof(&options).await.unwrap_err();
    assert_eq!(duplicate.code.as_deref(), Some("invalid_dpop_proof"));
    assert_eq!(duplicate.message, "DPoP proof jti has already been used");
    options.replay_store = None;
    options.method = "GET";
    assert_eq!(
        verify_dpop_proof(&options).await.unwrap_err().message,
        "DPoP proof htm does not match the request method"
    );
    let ath = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest("access"));
    let bound = proof(
        json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"bound","iat":2000000000,"ath":ath}),
        json!({}),
    )?;
    let mut options =
        VerifyDpopProofOptions::new(&bound, "POST", "https://api.fixture.test/resource");
    options.now_seconds = Some(2000000000.0);
    options.require_ath = true;
    options.access_token = Some("wrong");
    assert_eq!(
        verify_dpop_proof(&options).await.unwrap_err().message,
        "DPoP proof ath does not match the access token"
    );
    options.access_token = Some("access");
    options.expected_jkt = Some("wrong");
    assert_eq!(
        verify_dpop_proof(&options).await.unwrap_err().message,
        "DPoP proof key does not match the bound token"
    );
    let memory = create_in_memory_dpop_replay_store();
    options.expected_jkt = None;
    options.replay_store = Some(&memory);
    assert!(verify_dpop_proof(&options).await.is_ok());
    assert!(verify_dpop_proof(&options).await.is_err());
    let private = proof(
        json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"private","iat":2000000000}),
        json!({"jwk":{"kty":"OKP","crv":"Ed25519","x":"ignored","d":null}}),
    )?;
    let mut options =
        VerifyDpopProofOptions::new(&private, "POST", "https://api.fixture.test/resource");
    options.now_seconds = Some(2000000000.0);
    assert_eq!(
        verify_dpop_proof(&options).await.unwrap_err().message,
        "DPoP proof jwk must not contain private key material"
    );
    let unsupported = proof(
        json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"unsupported-native","iat":2000000000}),
        json!({"alg":"FOO"}),
    )?;
    let mut options =
        VerifyDpopProofOptions::new(&unsupported, "POST", "https://api.fixture.test/resource");
    options.now_seconds = Some(2000000000.0);
    options.signing_algorithms = Some(vec!["FOO".into()]);
    assert_eq!(
        verify_dpop_proof(&options).await.unwrap_err().message,
        "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value"
    );
    let keys: Value = serde_json::from_str(include_str!(
        "../../../fixtures/oauth/client-assertion-keys.json"
    ))?;
    let public_key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "Ed25519")
        .unwrap()["publicJwk"]
        .clone();
    for (extra, message) in [
        (
            json!({"key_ops":[]}),
            "CryptoKey does not support this operation, its usages must include verify.",
        ),
        (
            json!({"key_ops":["sign"]}),
            "Unsupported key usage for an Ed25519 key",
        ),
        (
            json!({"key_ops":["verify","verify"]}),
            "\"key_ops\" (Key Operations) Parameter must be an array of unique strings",
        ),
        (
            json!({"ext":0}),
            "\"ext\" (Extractable) Parameter must be a boolean",
        ),
        (
            json!({"priv":"extra"}),
            "Unsupported key usage for an Ed25519 key",
        ),
    ] {
        let mut jwk = public_key.clone();
        jwk.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let token = proof(
            json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"metadata-native","iat":2000000000}),
            json!({"jwk":jwk}),
        )?;
        let mut options =
            VerifyDpopProofOptions::new(&token, "POST", "https://api.fixture.test/resource");
        options.now_seconds = Some(2000000000.0);
        assert_eq!(
            verify_dpop_proof(&options).await.unwrap_err().message,
            message
        );
    }
    {
        use rsa::{
            signature::{SignatureEncoding as _, Signer as _},
            traits::PublicKeyParts as _,
        };
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024)?;
        let header = json!({"typ":"dpop+jwt","alg":"RS256","jwk":{"kty":"RSA","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}});
        let payload = json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"weak-rsa-native","iat":2000000000});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let signer = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key);
        let signature = signer.sign(message.as_bytes());
        let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let mut options =
            VerifyDpopProofOptions::new(&token, "POST", "https://api.fixture.test/resource");
        options.now_seconds = Some(2000000000.0);
        assert_eq!(
            verify_dpop_proof(&options).await.unwrap_err().message,
            "RS256 requires key modulusLength to be 2048 bits or larger"
        );
    }
    let forwarded = ForwardReservations {
        context: auth.context(),
        observed: std::sync::Mutex::new(None),
    };
    let replay = create_dpop_replay_store(&forwarded);
    let wrapped = proof(
        json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"wrapped-native","iat":2000000000}),
        json!({}),
    )?;
    let mut options =
        VerifyDpopProofOptions::new(&wrapped, "POST", "https://api.fixture.test/resource");
    options.now_seconds = Some(2000000000.0);
    options.replay_store = Some(&replay);
    let wrapped = verify_dpop_proof(&options).await?;
    let observed = forwarded.observed.lock().unwrap().clone().unwrap();
    assert_eq!(
        observed.identifier,
        format!("dpop-proof:{}", wrapped.replay_key)
    );
    assert_eq!(observed.value, wrapped.replay_key);
    assert_eq!(observed.expires_at, wrapped.expires_at);
    let binding = proof(
        json!({"htm":"post","htu":"https://api.fixture.test/resource","jti":"binding-native","iat":chrono::Utc::now().timestamp(),"ath":ath}),
        json!({}),
    )?;
    let bearer = AccessTokenAuthorization {
        scheme: "Bearer".into(),
        token: "access".into(),
    };
    let dpop = AccessTokenAuthorization {
        scheme: "DPoP".into(),
        token: "access".into(),
    };
    let unbound = json!({});
    let bound = json!({"cnf":{"jkt":verified.jkt}});
    let mut options = EnforceDpopBindingParams::new(
        &unbound,
        &bearer,
        "POST",
        "https://api.fixture.test/resource",
    );
    options.proof_jwt = Some(&binding);
    options.replay_store = Some(&memory);
    assert!(enforce_dpop_binding(&options).await.is_ok());
    options.payload = &bound;
    assert_eq!(
        enforce_dpop_binding(&options)
            .await
            .unwrap_err()
            .code
            .as_deref(),
        Some("invalid_token")
    );
    options.authorization = &dpop;
    options.proof_jwt = None;
    assert_eq!(
        enforce_dpop_binding(&options).await.unwrap_err().message,
        "DPoP proof header is required"
    );
    options.proof_jwt = Some(&binding);
    assert!(enforce_dpop_binding(&options).await.is_ok());
    assert_eq!(
        enforce_dpop_binding(&options).await.unwrap_err().message,
        "DPoP proof jti has already been used"
    );
    let parsed = parse_access_token_authorization(Some("  bEaReR\taccess  ")).unwrap();
    assert_eq!(parsed.scheme, "Bearer");
    assert_eq!(parsed.token, "access");
    assert_eq!(
        strip_access_token_authorization_scheme("Basic  access"),
        "Basic  access"
    );
    assert_eq!(strip_access_token_authorization_scheme("   "), "   ");
    assert_eq!(
        get_dpop_jkt_from_payload(&json!({"cnf":{"jkt":"bound"}}))?,
        Some("bound")
    );
    assert_eq!(
        get_dpop_jkt_from_payload(&json!({"cnf":[{"jkt":"bound"}]}))?,
        None
    );
    assert!(
        get_dpop_jkt_from_payload(&Value::Null)
            .unwrap_err()
            .code
            .is_none()
    );
    Ok(())
}
