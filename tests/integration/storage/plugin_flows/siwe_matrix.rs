//! SIWE request framing and the signature encodings accepted at the HTTP boundary.
use super::auth_probe::Probe;
use super::*;
use alibi::plugins::siwe::{
    Eip191Verifier, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiwePlugin,
};
use async_trait::async_trait;
use sha3::Digest;
use std::fmt::Write;

backend_tests!(
    siwe_request_framing_matrix,
    siwe_accepts_each_standard_signature_encoding
);

struct Nonce;
#[async_trait]
impl SiweNonceProvider for Nonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok("GoldenNonce0001".into())
    }
}

const MESSAGE: &str = "fixture.example wants you to sign in with your Ethereum account:\n0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\n\nSign in to the deterministic fixture\n\nURI: https://fixture.example/siwe\nVersion: 1\nChain ID: 1\nNonce: GoldenNonce0001\nIssued At: 2026-01-01T00:00:00Z";

/// Public test scalar 1: the compact `r || s` signature and its recovery bit.
fn sign(message: &str) -> ([u8; 64], u8) {
    let mut secret = [0_u8; 32];
    secret[31] = 1;
    let key = k256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
    let mut digest = sha3::Keccak256::new();
    digest.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    digest.update(message.as_bytes());
    let (signature, recovery) = key.sign_digest_recoverable(digest);
    (signature.to_bytes().into(), recovery.to_byte())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::from("0x"), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}

fn plugin(anonymous: bool) -> SiwePlugin {
    let mut config = SiweConfig::new("fixture.example", Arc::new(Nonce), Arc::new(Eip191Verifier));
    config.anonymous = anonymous;
    SiwePlugin::new(config)
}

async fn siwe_request_framing_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(plugin(true))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for text in [
        "[]",
        "null",
        "7",
        "{",
        r#"{"unexpected":1}"#,
        r#"{"b":1,"2":1,"1":1}"#,
    ] {
        let _ = probe
            .post(&format!("nonce {text}"), "/siwe/nonce", text, "")
            .await;
    }
    for content_type in [
        "",
        "text/plain",
        "application/json; charset=utf-8",
        "x-application/json",
        "x-application/json image/png",
        "x-application/json application/octet-stream",
    ] {
        for path in ["/siwe/nonce", "/siwe/verify"] {
            let mut input = super::auth_probe::raw(path, r#"{"message":"m","signature":"s"}"#, "");
            if content_type.is_empty() {
                _ = input.headers.remove("content-type");
            } else {
                _ = input
                    .headers
                    .insert("content-type".into(), content_type.into());
            }
            let _ = probe
                .send(&format!("{path} as {content_type:?}"), input)
                .await;
        }
    }
    for text in [
        "[]",
        "null",
        "{}",
        r#"{"message":5,"signature":5,"email":5}"#,
        r#"{"message":"","signature":""}"#,
        r#"{"message":"m","signature":"s","email":"nope"}"#,
        r#"{"message":"m","signature":"s","extra":1,"10":2,"9":3}"#,
        r#"{"message":"m","signature":"s","extra":1}"#,
        r#"{"message":"m","signature":"s"}"#,
    ] {
        let _ = probe
            .post(&format!("verify {text}"), "/siwe/verify", text, "")
            .await;
    }
    probe.trace.assert("siwe/request-framing-matrix");
    B::close(connection).await?;

    let db = db.fresh().await?;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(plugin(false))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for text in [
        r#"{"message":"m","signature":"s"}"#,
        r#"{"message":"m","signature":"s","email":""}"#,
        r#"{"message":"m","signature":"s","email":"w@example.test","extra":1}"#,
    ] {
        let _ = probe
            .post(&format!("email required {text}"), "/siwe/verify", text, "")
            .await;
    }
    probe.trace.assert("siwe/email-required-matrix");
    B::close(connection).await
}

async fn siwe_accepts_each_standard_signature_encoding<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(plugin(true))
        .build()
        .await?;
    let recovery_one = (0..64)
        .map(|index| MESSAGE.replace("fixture\n", &format!("fixture {index}\n")))
        .find(|message| sign(message).1 == 1)
        .unwrap();
    let recovery_zero = (0..64)
        .map(|index| MESSAGE.replace("fixture\n", &format!("fixture {index}\n")))
        .find(|message| sign(message).1 == 0)
        .unwrap();
    let compact = |message: &str| {
        let (mut signature, recovery) = sign(message);
        signature[32] |= recovery << 7;
        hex(&signature)
    };
    let standard = |message: &str, offset: u8| {
        let (signature, recovery) = sign(message);
        let mut bytes = signature.to_vec();
        bytes.push(recovery + offset);
        hex(&bytes)
    };
    let short = |message: &str| hex(&sign(message).0[..40]);
    let cases = [
        (
            "standard 27/28",
            recovery_one.clone(),
            standard(&recovery_one, 27),
            true,
        ),
        (
            "standard 0/1",
            recovery_zero.clone(),
            standard(&recovery_zero, 0),
            true,
        ),
        (
            "compact odd parity",
            recovery_one.clone(),
            compact(&recovery_one),
            true,
        ),
        (
            "compact even parity",
            recovery_zero.clone(),
            compact(&recovery_zero),
            true,
        ),
        (
            "invalid recovery byte",
            recovery_one.clone(),
            standard(&recovery_one, 5),
            false,
        ),
        (
            "truncated",
            recovery_one.clone(),
            short(&recovery_one),
            false,
        ),
        (
            "not hexadecimal",
            recovery_one.clone(),
            "0xzz".to_owned(),
            false,
        ),
        (
            "wrong parity",
            recovery_one.clone(),
            compact(&recovery_zero),
            false,
        ),
    ];
    for (label, message, signature, accepted) in cases {
        let _ = call(&auth, request("/siwe/nonce", Some(json!({})), ""), 200).await;
        let response = call(
            &auth,
            request(
                "/siwe/verify",
                Some(json!({"message":message,"signature":signature})),
                "",
            ),
            if accepted { 200 } else { 401 },
        )
        .await;
        assert_eq!(
            body(&response).get("token").is_some(),
            accepted,
            "{label}: {}",
            String::from_utf8_lossy(&response.body)
        );
    }
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("wallet_address").await?, 1);
    B::close(connection).await
}
