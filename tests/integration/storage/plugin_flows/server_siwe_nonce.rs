//! Server nonce aliases validate before callbacks and persist consumable SIWE proofs.
use super::*;
use alibi::AuthVerification;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::siwe::{
    Eip191Verifier, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiwePlugin,
};
use alibi::utils::json::JsValue;
use async_trait::async_trait;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Nonces {
    counter: AtomicUsize,
    override_value: Mutex<Option<String>>,
}
#[async_trait]
impl SiweNonceProvider for Nonces {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok(self
            .override_value
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| {
                format!(
                    "SiweFixtureNonce{:016}",
                    self.counter.fetch_add(1, Ordering::SeqCst)
                )
            }))
    }
}

backend_tests!(server_siwe_nonce_aliases_preserve_validation_and_consumable_proofs);
async fn server_siwe_nonce_aliases_preserve_validation_and_consumable_proofs<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let provider = Arc::new(Nonces::default());
    let auth = Box::pin(
        AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(SiwePlugin::new(SiweConfig::new(
                "fixture.example",
                provider.clone(),
                Arc::new(Eip191Verifier),
            )))
            .build(),
    )
    .await?;
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "walletAddress",
            "verification",
        ])
        .await?;
    for operation in ["getSiweNonce", "getNonce"] {
        for input in [
            json!(null),
            json!([]),
            json!(false),
            json!({"walletAddress":"ignored"}),
            json!({"2":true,"1":false,"ordinary":1}),
        ] {
            let error = Box::pin(auth.dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("siwe", operation).with_body(&input)?,
                EndpointOptions::default(),
            ))
            .await
            .unwrap_err();
            assert_eq!(error.error.status_code(), 400);
            assert_eq!(
                body(&error.error.to_auth_response())["code"],
                "VALIDATION_ERROR"
            );
        }
    }
    assert_eq!(provider.counter.load(Ordering::SeqCst), 0);
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
    for (operation, input) in [
        ("getSiweNonce", None),
        ("getSiweNonce", Some(json!({}))),
        ("getNonce", None),
        ("getNonce", Some(json!({}))),
    ] {
        let mut endpoint = if operation == "getSiweNonce" {
            SiwePlugin::get_siwe_nonce_endpoint()
        } else {
            SiwePlugin::get_nonce_endpoint()
        };
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let start = chrono::Utc::now();
        let output = Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default())).await?;
        let nonce = output.decode()?.nonce;
        assert!(output.headers().get_all("set-cookie").next().is_none());
        let proof = auth
            .store()
            .get_verification_by_identifier(&format!("siwe:{nonce}"))
            .await?
            .unwrap();
        assert_eq!(proof.value(), nonce);
        assert!(proof.expires_at() >= start + chrono::Duration::seconds(899));
        assert!(proof.expires_at() <= chrono::Utc::now() + chrono::Duration::seconds(901));
        assert_eq!(db.count("verification").await?, 1);
        let message = format!(
            "wrong.example wants you to sign in with your Ethereum account:\n0x7e5f4552091a69125d5dfcb7b8c2659029395bdf\n\nSign in\n\nURI: https://wrong.example/siwe\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: 2026-01-01T00:00:00Z"
        );
        let response = Box::pin(call(
            &auth,
            request(
                "/siwe/verify",
                Some(json!({"message":message,"signature":"unused"})),
                "",
            ),
            401,
        ))
        .await;
        assert_eq!(
            body(&response)["code"],
            "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"
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
            before
        );
    }
    for nonce in [
        "short".to_owned(),
        "a".repeat(251),
        "invalid_nonce".to_owned(),
        "é".repeat(8),
    ] {
        *provider.override_value.lock().unwrap() = Some(nonce);
        let error = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("siwe", "getSiweNonce"),
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), 500);
        assert_eq!(
            error.body.as_ref().unwrap().get("code").unwrap().as_str(),
            Some("SIWE_INVALID_NONCE")
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
            before
        );
    }
    B::close(connection).await
}
