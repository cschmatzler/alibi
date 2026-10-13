//! Server SIWE verification requires the caller's request and consumes a real signed proof.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::siwe::{
    Eip191Verifier, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiwePlugin,
};
use alibi::utils::json::JsValue;
use async_trait::async_trait;
use sha3::Digest;
use std::fmt::Write;
struct Nonce;
#[async_trait]
impl SiweNonceProvider for Nonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok("GoldenNonce0001".into())
    }
}
fn signature(message: &str, scalar: u8) -> String {
    let mut secret = [0_u8; 32];
    secret[31] = scalar;
    let key = k256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
    let mut digest = sha3::Keccak256::new();
    digest.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    digest.update(message.as_bytes());
    let (signed, recovery) = key.sign_digest_recoverable(digest);
    let mut bytes = signed.to_bytes().to_vec();
    bytes.push(recovery.to_byte() + 27);
    bytes.iter().fold(String::from("0x"), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}
backend_tests!(server_verify_siwe_message_requires_request_and_publishes_usable_session);
async fn server_verify_siwe_message_requires_request_and_publishes_usable_session<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = Box::pin(
        AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(SiwePlugin::new(SiweConfig::new(
                "fixture.example",
                Arc::new(Nonce),
                Arc::new(Eip191Verifier),
            )))
            .build(),
    )
    .await?;
    let issued =
        Box::pin(auth.dispatch_endpoint(SiwePlugin::get_siwe_nonce_endpoint(), Default::default()))
            .await?
            .decode()?;
    let message = format!(
        "fixture.example wants you to sign in with your Ethereum account:\n0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\n\nSign in\n\nURI: https://fixture.example/siwe\nVersion: 1\nChain ID: 1\nNonce: {}\nIssued At: 2026-01-01T00:00:00Z",
        issued.nonce
    );
    let input = json!({"message":message,"signature":signature(&message, 1)});
    let endpoint = || ServerEndpoint::<JsValue>::new("siwe", "verifySiweMessage");
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "walletAddress",
            "verification",
        ])
        .await?;
    for body_input in [
        None,
        Some(json!({})),
        Some(json!({"message":"","signature":""})),
        Some(json!({"message":"m","signature":"s","extra":true})),
        Some(input.clone()),
    ] {
        let mut call = endpoint();
        if let Some(body) = body_input {
            call = call.with_body(&body)?;
        }
        let error = Box::pin(auth.dispatch_endpoint(call, EndpointOptions::default()))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(
            body(&error.error.to_auth_response())["code"],
            "VALIDATION_ERROR"
        );
    }
    assert_eq!(
        db.tables(&[
            "user",
            "account",
            "session",
            "walletAddress",
            "verification"
        ])
        .await?,
        before
    );
    let mut original = request(
        "/siwe/verify",
        Some(json!({"original":"transport body"})),
        "",
    );
    _ = original
        .headers
        .insert("user-agent".into(), "siwe-server-sdk".into());
    _ = original
        .headers
        .insert("x-forwarded-for".into(), "198.51.100.19".into());
    let output = Box::pin(auth.dispatch_endpoint(
        SiwePlugin::verify_message_endpoint(&alibi::plugins::siwe::SiweVerificationInput {
            message: message.clone(),
            signature: signature(&message, 1),
            email: None,
        })?,
        EndpointOptions {
            request: Some(original.clone()),
            ..Default::default()
        },
    ))
    .await?;
    assert_eq!(output.value().get("success"), Some(&JsValue::Bool(true)));
    assert!(output.decode()?.success);
    let user_id = output
        .value()
        .get("user")
        .unwrap()
        .get("id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        output
            .value()
            .get("user")
            .unwrap()
            .get("walletAddress")
            .unwrap()
            .as_str(),
        Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
    );
    let cookie_response = output.into_response()?;
    assert!(
        cookie_response
            .headers
            .get_all("set-cookie")
            .next()
            .is_some()
    );
    let observed = Box::pin(call(
        &auth,
        request("/get-session", None, &cookies(&cookie_response)),
        200,
    ))
    .await;
    assert_eq!(body(&observed)["user"]["id"], user_id);
    assert_eq!(body(&observed)["session"]["ipAddress"], "198.51.100.19");
    assert_eq!(body(&observed)["session"]["userAgent"], "siwe-server-sdk");
    assert_eq!(db.count("user").await?, 1);
    assert_eq!(db.count("session").await?, 1);
    assert_eq!(db.count("account").await?, 1);
    assert_eq!(db.count("walletAddress").await?, 1);
    assert_eq!(db.count("verification").await?, 0);
    let after = db
        .tables(&[
            "user",
            "account",
            "session",
            "walletAddress",
            "verification",
        ])
        .await?;
    let replay = Box::pin(auth.dispatch_endpoint(
        endpoint().with_body(&input)?,
        EndpointOptions {
            request: Some(original.clone()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(replay.error.status_code(), 401);
    assert_eq!(
        body(&replay.error.to_auth_response())["code"],
        "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
    );
    assert_eq!(
        db.tables(&[
            "user",
            "account",
            "session",
            "walletAddress",
            "verification"
        ])
        .await?,
        after
    );
    let _ =
        Box::pin(auth.dispatch_endpoint(SiwePlugin::get_siwe_nonce_endpoint(), Default::default()))
            .await?;
    let rejected = Box::pin(auth.dispatch_endpoint(
        SiwePlugin::verify_message_endpoint(&alibi::plugins::siwe::SiweVerificationInput {
            message: message.clone(),
            signature: signature(&message, 2),
            email: None,
        })?,
        EndpointOptions {
            request: Some(original),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(rejected.error.status_code(), 401);
    assert_eq!(
        rejected
            .body
            .as_ref()
            .unwrap()
            .get("message")
            .unwrap()
            .as_str(),
        Some("Unauthorized: Invalid SIWE signature")
    );
    assert_eq!(
        db.tables(&[
            "user",
            "account",
            "session",
            "walletAddress",
            "verification"
        ])
        .await?,
        after
    );
    B::close(connection).await
}
