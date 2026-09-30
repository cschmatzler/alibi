#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "protocol tests assert concrete persisted and signed payloads"
)]

use super::*;
use async_trait::async_trait;
use better_auth_core::{AuthAccount, AuthPlugin, AuthVerification, HttpMethod};
use better_auth_seaorm::sea_orm::{EntityTrait, PaginatorTrait};
use better_auth_seaorm::store::entities::wallet_address;
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};
use k256::ecdsa::SigningKey;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use tokio::sync::Mutex;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
const ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

#[derive(Default)]
struct Nonces(AtomicU32);
#[async_trait]
impl SiweNonceProvider for Nonces {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok(format!(
            "FixtureNonce{:08}",
            self.0.fetch_add(1, Ordering::SeqCst)
        ))
    }
}
struct FixedNonce(&'static str);
#[async_trait]
impl SiweNonceProvider for FixedNonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok(self.0.to_owned())
    }
}

#[derive(Default)]
struct Verifier {
    inputs: Mutex<Vec<SiweVerification>>,
}
#[async_trait]
impl SiweVerifier for Verifier {
    async fn verify_message(&self, input: SiweVerification) -> SiweCallbackResult<bool> {
        self.inputs.lock().await.push(input.clone());
        Eip191Verifier.verify_message(input).await
    }
}

async fn context() -> (AuthContext<TestSchema>, DatabaseConnection) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let config = Arc::new(better_auth_core::AuthConfig::new(
        "siwe-native-context-secret-at-least-32-characters",
    ));
    let store = Arc::new(SeaOrmStore::<TestSchema>::new(
        config.clone(),
        database.clone(),
    ));
    (AuthContext::new(config, store), database)
}

fn plugin() -> (SiwePlugin, Arc<Verifier>) {
    let verifier = Arc::new(Verifier::default());
    let config = SiweConfig::new(
        "fixture.example",
        Arc::new(Nonces::default()),
        verifier.clone(),
    );
    (SiwePlugin::new(config), verifier)
}

fn request(path: &str, body: serde_json::Value) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    request.body = Some(serde_json::to_vec(&body).unwrap());
    _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    request
}
fn body(response: &AuthResponse) -> serde_json::Value {
    serde_json::from_slice(&response.body).unwrap()
}

async fn issue(plugin: &SiwePlugin, ctx: &AuthContext<TestSchema>, path: &str) -> String {
    let response = plugin
        .on_request(&request(path, json!({})), ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200, "{}", body(&response));
    body(&response)["nonce"].as_str().unwrap().to_owned()
}

fn message(nonce: &str, domain: &str, address: &str, chain: &str, extra: &str) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\nSign in — Ελληνικά\n\nURI: not-a-url\nVersion: 999\nChain ID: {chain}\nNonce: {nonce}\nIssued At: invalid date\n{extra}"
    )
}

fn sign(message: &str, scalar: u8) -> String {
    use sha3::{Digest, Keccak256};
    let mut secret = [0u8; 32];
    secret[31] = scalar;
    let key = SigningKey::from_slice(&secret).unwrap();
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut digest = Keccak256::new();
    digest.update(prefix.as_bytes());
    digest.update(message.as_bytes());
    let (signature, recovery) = key.sign_prehash_recoverable(&digest.finalize()).unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte() + 27);
    format!(
        "0x{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

async fn verify(
    plugin: &SiwePlugin,
    ctx: &AuthContext<TestSchema>,
    message: &str,
    scalar: u8,
    email: Option<&str>,
) -> AuthResponse {
    let mut body = json!({"message":message,"signature":sign(message, scalar)});
    if let Some(email) = email {
        body["email"] = json!(email);
    }
    plugin
        .on_request(&request("/siwe/verify", body), ctx)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn independent_unicode_signature_creates_an_authenticated_wallet_identity_and_rotates_only_sessions()
 {
    let (ctx, database) = context().await;
    let verifier = Arc::new(Verifier::default());
    let plugin = SiwePlugin::new(SiweConfig::new(
        "fixture.example",
        Arc::new(FixedNonce("GoldenNonce0001")),
        verifier.clone(),
    ));
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/eip191-noble-2.0.1.json")).unwrap();
    let nonce = issue(&plugin, &ctx, "/siwe/get-nonce").await;
    let proof = ctx
        .database
        .get_latest_verification_by_identifier(&format!("siwe:{nonce}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(proof.value(), nonce);
    assert!(((proof.expires_at() - proof.created_at()).num_milliseconds() - 900_000).abs() < 1_000);
    let response = plugin.on_request(&request("/siwe/verify", json!({"message":fixture["message"],"signature":fixture["signature"],"email":"ignored@fixture.test"})), &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 200, "{}", body(&response));
    let result = body(&response);
    assert_eq!(result.as_object().unwrap().len(), 3);
    assert_eq!(result["success"], true);
    assert_eq!(result["user"]["walletAddress"], ADDRESS);
    assert_eq!(result["user"]["chainId"].as_f64(), Some(1.0));
    let user_id = result["user"]["id"].as_str().unwrap();
    let user = ctx.database.get_user_by_id(user_id).await.unwrap().unwrap();
    assert_eq!(
        user.email.as_deref(),
        Some("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf@siwe.placeholder.invalid")
    );
    assert_eq!(user.name.as_deref(), Some(ADDRESS));
    assert_eq!(user.image.as_deref(), Some(""));
    assert!(!user.email_verified);
    let wallet = ctx
        .database
        .get_wallet_address(ADDRESS, Some(1.0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wallet.user_id, user_id);
    assert!(wallet.is_primary);
    let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id(), "siwe");
    assert_eq!(accounts[0].account_id(), format!("{ADDRESS}:1"));
    let cookie = response
        .headers
        .get_all("Set-Cookie")
        .find(|header| header.starts_with("better-auth.session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut read = AuthRequest::new(HttpMethod::Get, "/get-session");
    _ = read.headers.insert("cookie".into(), cookie.to_owned());
    let (_, session) = ctx.require_session(&read).await.unwrap();
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.token, result["token"].as_str().unwrap());
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&format!("siwe:{nonce}"))
            .await
            .unwrap()
            .is_none()
    );
    let replay = plugin
        .on_request(
            &request(
                "/siwe/verify",
                json!({"message":fixture["message"],"signature":fixture["signature"]}),
            ),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        body(&replay)["code"],
        "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
    );
    let next = issue(&plugin, &ctx, "/siwe/nonce").await;
    let signed = message(
        &next,
        "HTTPS://FIXTURE.EXAMPLE/ignored",
        &ADDRESS.to_lowercase(),
        "0x10",
        "Expiration Time: not a date\nNot Before: not a date",
    );
    let cross_chain = verify(&plugin, &ctx, &signed, 1, None).await;
    assert_eq!(cross_chain.status, 200, "{}", body(&cross_chain));
    assert_eq!(body(&cross_chain)["user"]["id"], user_id);
    assert_ne!(body(&cross_chain)["token"], result["token"]);
    assert!(
        !ctx.database
            .get_wallet_address(ADDRESS, Some(16.0))
            .await
            .unwrap()
            .unwrap()
            .is_primary
    );
    assert_eq!(
        wallet_address::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        ctx.database.get_user_sessions(user_id).await.unwrap().len(),
        2
    );
    assert_eq!(
        ctx.database.get_user_accounts(user_id).await.unwrap().len(),
        2
    );
    let next = issue(&plugin, &ctx, "/siwe/nonce").await;
    let huge = verify(
        &plugin,
        &ctx,
        &message(&next, "fixture.example", ADDRESS, "1e21", ""),
        1,
        None,
    )
    .await;
    assert_eq!(huge.status, 200, "{}", body(&huge));
    assert!(
        ctx.database
            .get_user_accounts(user_id)
            .await
            .unwrap()
            .iter()
            .any(|account| account.account_id() == format!("{ADDRESS}:1e+21"))
    );
    let observed = verifier.inputs.lock().await;
    assert_eq!(observed.len(), 3);
    assert_eq!(observed[0].cacao.p.nonce, "GoldenNonce0001");
    assert_eq!(observed[0].cacao.p.domain, "fixture.example");
    assert_eq!(observed[0].cacao.p.aud, "fixture.example");
    assert_eq!(observed[0].cacao.p.iss, "fixture.example");
    assert_eq!(
        observed[0].cacao.s.s,
        fixture["signature"].as_str().unwrap()
    );
    assert_eq!(observed[1].chain_id, 16.0);
    assert_eq!(observed[2].chain_id, 1e21);
}

#[tokio::test]
async fn signed_preferences_change_cookie_persistence_without_shortening_siwe_sessions() {
    use better_auth_core::utils::cookie_utils::{related_cookie_name, sign_cookie_value};
    let (ctx, _) = context().await;
    let (plugin, _) = plugin();
    let preference_name = related_cookie_name(&ctx.config, "dont_remember");
    for (preference, temporary) in [
        (None, false),
        (Some(""), false),
        (Some("false"), true),
        (Some("true"), true),
    ] {
        let nonce = issue(&plugin, &ctx, "/siwe/nonce").await;
        let signed = message(&nonce, "fixture.example", ADDRESS, "1", "");
        let mut req = request(
            "/siwe/verify",
            json!({"message":signed,"signature":sign(&signed,1)}),
        );
        if let Some(preference) = preference {
            _ = req.headers.insert(
                "cookie".into(),
                format!(
                    "{preference_name}={}",
                    sign_cookie_value(preference, &ctx.config.secret)
                ),
            );
        }
        let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let result = body(&response);
        let session = ctx
            .database
            .get_session(result["token"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(
            ((session.expires_at - session.created_at) - ctx.config.session.expires_in)
                .num_milliseconds()
                .abs()
                < 1_000
        );
        let cookie = response
            .headers
            .get_all("Set-Cookie")
            .find(|cookie| cookie.starts_with("better-auth.session_token="))
            .unwrap();
        assert_eq!(
            !cookie.contains("Max-Age="),
            temporary,
            "preference={preference:?}"
        );
        assert_eq!(
            response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&format!("{preference_name}="))),
            temporary
        );
    }
    assert_eq!(
        ctx.database
            .get_user_sessions(
                &ctx.database
                    .get_wallet_address(ADDRESS, Some(1.0))
                    .await
                    .unwrap()
                    .unwrap()
                    .user_id
            )
            .await
            .unwrap()
            .len(),
        4
    );
}
