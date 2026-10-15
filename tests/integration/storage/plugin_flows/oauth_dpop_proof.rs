//! Genuine DPoP proofs reserve one-time authority through each physical adapter.
use super::*;
use alibi::AuthVerification as _;
use alibi::plugins::oauth2::{
    AccessTokenAuthorization, DpopError, DpopReplayReservations, DpopVerificationReservation,
    EnforceDpopBindingParams, VerifyDpopProofOptions, create_dpop_replay_store,
    create_in_memory_dpop_replay_store, enforce_dpop_binding, parse_access_token_authorization,
    strip_access_token_authorization_scheme, verify_dpop_proof,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(oauth_dpop_proof_verifies_external_signature_context_and_atomic_receipt);
postgres_tests!(oauth_dpop_proof_verifies_external_signature_context_and_atomic_receipt);
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
    Ok(())
}
