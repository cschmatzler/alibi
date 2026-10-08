use super::*;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::siwe::{
    Eip191Verifier, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiwePlugin,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use serde_cbor_2::Value as Cbor;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

backend_tests!(
    wallet_signature_consumes_the_issued_nonce_and_persists_identity,
    registered_passkey_authenticates_from_stored_credential
);
postgres_tests!(
    wallet_signature_consumes_the_issued_nonce_and_persists_identity,
    registered_passkey_authenticates_from_stored_credential
);

struct FixtureNonce;
#[async_trait]
impl SiweNonceProvider for FixtureNonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok("GoldenNonce0001".into())
    }
}

async fn wallet_signature_consumes_the_issued_nonce_and_persists_identity<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(SiwePlugin::new(SiweConfig::new(
            "fixture.example",
            Arc::new(FixtureNonce),
            Arc::new(Eip191Verifier),
        )))
        .build()
        .await?;
    // An independently signed EIP-191 vector, never a seeded verification row.
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/siwe/eip191-noble-2.0.1.json"
    ))?;
    let original = fixture["message"].as_str().unwrap();
    // Each denial gets a real fresh nonce and otherwise-valid EIP-191 proof.
    // Reusing an already-consumed nonce would never reach these policy gates.
    for (message, wrong_signature, code) in [
        (original.to_owned(), true, None),
        (
            original.replacen("fixture.example", "foreign.example", 1),
            false,
            Some("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"),
        ),
        (
            format!("{original}\nExpiration Time: 2000-01-01T00:00:00Z"),
            false,
            Some("UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"),
        ),
        (
            format!("{original}\nNot Before: 2099-01-01T00:00:00Z"),
            false,
            Some("UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"),
        ),
    ] {
        let _ = call(&auth, request("/siwe/nonce", Some(json!({})), ""), 200).await;
        let signature = wallet_signature(&message, if wrong_signature { 2 } else { 1 });
        let denied = call(
            &auth,
            request(
                "/siwe/verify",
                Some(json!({"message":message,"signature":signature})),
                "",
            ),
            401,
        )
        .await;
        if let Some(code) = code {
            assert_eq!(body(&denied)["code"], code);
        } else {
            assert_eq!(
                body(&denied)["message"],
                "Unauthorized: Invalid SIWE signature"
            );
        }
        assert!(denied.headers.get_all("set-cookie").next().is_none());
        for table in [
            "users",
            "accounts",
            "sessions",
            "wallet_address",
            "verifications",
        ] {
            assert_eq!(db.count(table).await?, 0, "{table}: rejected {message}");
        }
    }
    let issued = call(&auth, request("/siwe/nonce", Some(json!({})), ""), 200).await;
    assert_eq!(body(&issued)["nonce"], fixture["nonce"]);
    assert_eq!(db.count("verifications").await?, 1);
    let input = request(
        "/siwe/verify",
        Some(json!({"message":fixture["message"],"signature":fixture["signature"]})),
        "",
    );
    let accepted = call(&auth, input.clone(), 200).await;
    assert_eq!(body(&accepted)["user"]["walletAddress"], fixture["address"]);
    let session = call(
        &auth,
        request("/get-session", None, &cookies(&accepted)),
        200,
    )
    .await;
    assert_eq!(body(&session)["user"]["id"], body(&accepted)["user"]["id"]);
    assert_eq!(body(&session)["session"]["token"], body(&accepted)["token"]);
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("accounts").await?, 1);
    assert_eq!(db.count("wallet_address").await?, 1);
    assert_eq!(db.count("verifications").await?, 0);
    let replay = call(&auth, input, 401).await;
    assert_eq!(
        body(&replay)["code"],
        "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
    );
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await?;
    wallet_email_policy::<B>(&db).await
}

struct RejectedWalletNonce(&'static str);
#[async_trait]
impl SiweNonceProvider for RejectedWalletNonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        use alibi::plugins::siwe::SiweCallbackError;
        match self.0 {
            "invalid" => Ok("not valid".into()),
            "api" => Err(SiweCallbackError::Api(alibi_core::AuthResponse::new(418))),
            _ => Err(SiweCallbackError::Failed(
                "nonce service unavailable".into(),
            )),
        }
    }
}
struct WalletEns {
    fail: bool,
    observed: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl alibi::plugins::siwe::EnsLookup for WalletEns {
    async fn lookup(&self, address: &str) -> SiweCallbackResult<alibi::plugins::siwe::EnsProfile> {
        self.observed.lock().unwrap().push(address.to_owned());
        if self.fail {
            return Err(alibi::plugins::siwe::SiweCallbackError::Failed(
                "ENS unavailable".into(),
            ));
        }
        Ok(alibi::plugins::siwe::EnsProfile {
            name: Some("wallet.eth".into()),
            avatar: Some("https://images.example/wallet.png".into()),
        })
    }
}
async fn wallet_email_policy<B: Backend>(parent: &Db) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/siwe/eip191-noble-2.0.1.json"
    ))?;
    for mode in ["invalid", "api", "failure"] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = builder::<B>(&connection)
            .plugin(SiwePlugin::new(SiweConfig::new(
                "fixture.example",
                Arc::new(RejectedWalletNonce(mode)),
                Arc::new(Eip191Verifier),
            )))
            .build()
            .await?;
        let result = call(
            &auth,
            request("/siwe/nonce", Some(json!({})), ""),
            if mode == "api" { 418 } else { 500 },
        )
        .await;
        if mode == "invalid" {
            assert_eq!(body(&result)["code"], "SIWE_INVALID_NONCE");
        }
        assert_eq!(db.count("verifications").await?, 0);
        assert_eq!(db.count("users").await?, 0);
        B::close(connection).await?;
    }
    for mode in ["new", "existing", "reserved", "ens-error"] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut config = SiweConfig::new(
            "fixture.example",
            Arc::new(FixtureNonce),
            Arc::new(Eip191Verifier),
        );
        config.anonymous = false;
        config.email_domain_name = Some("wallets.example".into());
        config.ens_lookup = Some(Arc::new(WalletEns {
            fail: mode == "ens-error",
            observed: observed.clone(),
        }));
        let auth = builder::<B>(&connection)
            .plugin(EmailPasswordPlugin::new())
            .plugin(SiwePlugin::new(config))
            .build()
            .await?;
        let existing = if mode == "existing" {
            Some(signup(&auth, "claimed@example.test").await)
        } else {
            None
        };
        if mode == "reserved" {
            assert!(
                auth.context()
                    .verifications()
                    .reserve(alibi_core::CreateVerification {
                        identifier: "siwe-email-claim-claimed@example.test".into(),
                        value: "another-wallet".into(),
                        expires_at: chrono::Utc::now() + chrono::Duration::minutes(1)
                    })
                    .await?
            );
        }
        let _ = call(&auth, request("/siwe/nonce", Some(json!({})), ""), 200).await;
        let proof = json!({"message":fixture["message"],"signature":fixture["signature"]});
        let _ = call(&auth, request("/siwe/verify", Some(proof.clone()), ""), 400).await;
        assert!(observed.lock().unwrap().is_empty());
        assert_eq!(
            db.count("verifications").await?,
            if mode == "reserved" { 2 } else { 1 }
        );
        let mut proof = proof;
        proof["email"] = json!("Claimed@Example.Test");
        let response = call(
            &auth,
            request("/siwe/verify", Some(proof.clone()), ""),
            if mode == "ens-error" { 401 } else { 200 },
        )
        .await;
        assert_eq!(
            *observed.lock().unwrap(),
            vec![fixture["address"].as_str().unwrap().to_owned()]
        );
        if mode == "ens-error" {
            assert_eq!(body(&response)["error"], "ENS unavailable");
            for table in ["users", "sessions", "accounts", "wallet_address"] {
                assert_eq!(db.count(table).await?, 0);
            }
            assert_eq!(db.count("verifications").await?, 1);
            assert_eq!(
                db.text("SELECT identifier FROM verifications", &[])
                    .await?
                    .as_deref(),
                Some("siwe-email-claim-claimed@example.test")
            );
        } else {
            let expected_email = if mode == "new" {
                "claimed@example.test".to_owned()
            } else {
                format!(
                    "{}@wallets.example",
                    fixture["address"].as_str().unwrap().to_lowercase()
                )
            };
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&response)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], expected_email);
            assert_eq!(body(&session)["user"]["name"], "wallet.eth");
            assert_eq!(
                body(&session)["user"]["image"],
                "https://images.example/wallet.png"
            );
            assert_eq!(body(&session)["user"]["emailVerified"], false);
            assert_eq!(db.count("wallet_address").await?, 1);
            assert_eq!(
                db.count("users").await?,
                if existing.is_some() { 2 } else { 1 }
            );
            if let Some(existing) = existing {
                assert_ne!(body(&session)["user"]["id"], body(&existing)["user"]["id"]);
                authenticated(&auth, &cookies(&existing), "claimed@example.test").await;
            }
            assert_eq!(
                db.count("verifications").await?,
                i64::from(mode == "reserved")
            );
        }
        let _ = call(&auth, request("/siwe/verify", Some(proof), ""), 401).await;
        assert_eq!(observed.lock().unwrap().len(), 1);
        B::close(connection).await?;
    }
    Ok(())
}

fn wallet_signature(message: &str, scalar: u8) -> String {
    use std::fmt::Write;
    // Public test scalars, independently signing the EIP-191 wire format.
    let mut secret = [0_u8; 32];
    secret[31] = scalar;
    let key = k256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
    let mut digest = sha3::Keccak256::new();
    digest.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    digest.update(message.as_bytes());
    let (signature, recovery) = key.sign_digest_recoverable(digest);
    let mut encoded = String::from("0x");
    for byte in signature
        .to_bytes()
        .iter()
        .copied()
        .chain([recovery.to_byte() + 27])
    {
        write!(encoded, "{byte:02x}").unwrap();
    }
    encoded
}

#[derive(Default)]
struct PasskeyPolicy {
    registration: std::sync::atomic::AtomicU8,
    deny_authentication: std::sync::atomic::AtomicBool,
    registrations: Mutex<Vec<String>>,
    authentications: Mutex<Vec<u32>>,
}
#[async_trait]
impl alibi::plugins::passkey::PasskeyAuthenticationAfterVerification for PasskeyPolicy {
    async fn after_verification(
        &self,
        context: &alibi::plugins::passkey::PasskeyAuthenticationContext<'_>,
        verification: &alibi::plugins::passkey::VerifiedPasskeyAuthentication,
        client: &alibi_core::utils::json::JsValue,
    ) -> alibi_core::AuthResult<()> {
        assert!(
            context
                .request
                .path
                .ends_with("/passkey/verify-authentication")
        );
        assert_eq!(verification.origin, ORIGIN);
        assert_eq!(verification.rp_id, "localhost");
        assert_eq!(
            verification.result.cred_id().as_slice(),
            b"native-stored-passkey"
        );
        assert!(verification.result.user_verified());
        assert!(!verification.result.backup_eligible());
        assert!(!verification.result.backup_state());
        assert!(client.as_object().is_some());
        self.authentications
            .lock()
            .unwrap()
            .push(verification.result.counter());
        if self
            .deny_authentication
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(alibi_core::AuthError::forbidden("Application veto"));
        }
        Ok(())
    }
}
#[async_trait]
impl alibi::plugins::passkey::PasskeyRegistrationAfterVerification for PasskeyPolicy {
    async fn after_verification(
        &self,
        context: &alibi::plugins::passkey::PasskeyRegistrationContext<'_>,
        verification: &alibi::plugins::passkey::VerifiedPasskeyRegistration,
        user: &alibi::plugins::passkey::PasskeyRegistrationUser,
        client: &alibi_core::utils::json::JsValue,
        stored_context: Option<&str>,
    ) -> alibi_core::AuthResult<Option<alibi::plugins::passkey::PasskeyRegistrationOverride>> {
        assert!(
            context
                .request
                .path
                .ends_with("/passkey/verify-registration")
        );
        assert_eq!(
            verification.credential_id,
            URL_SAFE_NO_PAD.encode(b"native-stored-passkey")
        );
        assert_eq!(verification.counter, 1);
        assert_eq!(
            stored_context,
            if self.registration.load(std::sync::atomic::Ordering::SeqCst) == 3 {
                Some("application-enrollment")
            } else {
                None
            }
        );
        assert_eq!(verification.device_type, "singleDevice");
        assert!(!verification.backed_up);
        assert!(!verification.public_key.is_empty());
        assert!(client.as_object().is_some());
        self.registrations.lock().unwrap().push(user.id.clone());
        match self.registration.load(std::sync::atomic::Ordering::SeqCst) {
            0 => Err(alibi_core::AuthError::forbidden("Registration veto")),
            1 => Ok(Some(alibi::plugins::passkey::PasskeyRegistrationOverride {
                user_id: Some("foreign-user".into()),
                name: None,
            })),
            _ => Ok(Some(alibi::plugins::passkey::PasskeyRegistrationOverride {
                user_id: Some(user.id.clone()),
                name: Some("  Application credential  ".into()),
            })),
        }
    }
}

struct RegistrationSessionPolicy(Arc<PasskeyPolicy>);
#[async_trait]
impl<S: AuthSchema, H: alibi_core::store::HookBackend> alibi_core::store::DatabaseHooks<S, H>
    for RegistrationSessionPolicy
{
    async fn before_create_session(
        &self,
        _: &mut alibi_core::CreateSession,
        context: &alibi_core::store::DatabaseHookContext<'_, H>,
    ) -> alibi_core::AuthResult<alibi_core::store::HookControl> {
        if context
            .request
            .as_ref()
            .is_some_and(|request| request.path.ends_with("/passkey/verify-registration"))
        {
            assert!(
                context.tx.is_some(),
                "credential and session must share a transaction"
            );
            if self
                .0
                .registration
                .load(std::sync::atomic::Ordering::SeqCst)
                == 2
            {
                return Ok(alibi_core::store::HookControl::Cancel);
            }
        }
        Ok(alibi_core::store::HookControl::Continue)
    }
}
struct RegistrationResolver(String);
#[async_trait]
impl alibi::plugins::passkey::PasskeyUserResolver for RegistrationResolver {
    async fn resolve_user(
        &self,
        context: &alibi::plugins::passkey::PasskeyRegistrationContext<'_>,
        requested: Option<&str>,
    ) -> alibi_core::AuthResult<Option<alibi::plugins::passkey::PasskeyRegistrationUser>> {
        assert!(
            context
                .request
                .path
                .ends_with("/passkey/generate-register-options")
        );
        Ok((requested == Some("application-enrollment")).then(|| {
            alibi::plugins::passkey::PasskeyRegistrationUser {
                id: self.0.clone(),
                name: "Resolved owner".into(),
                display_name: Some("Application registration".into()),
            }
        }))
    }
}

async fn registered_passkey_authenticates_from_stored_credential<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(PasskeyPolicy::default());
    let hook_config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = builder::<B>(&connection)
        .store(B::hook(
            B::store(Arc::new(hook_config), &connection),
            RegistrationSessionPolicy(policy.clone()),
        ))
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("Native test")
                .origin(ORIGIN)
                .registration(alibi::plugins::passkey::PasskeyRegistrationConfig {
                    extensions: None,
                    after_verification: Some(policy.clone()),
                    ..Default::default()
                })
                .authentication(alibi::plugins::passkey::PasskeyAuthenticationConfig {
                    extensions: None,
                    after_verification: Some(policy.clone()),
                }),
        )
        .build()
        .await?;
    for route in [
        "/passkey/generate-register-options",
        "/passkey/list-user-passkeys",
    ] {
        let _ = call(&auth, request(route, None, ""), 401).await;
    }
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.count("passkeys").await?, 0);
    let owner = signup(&auth, "passkey@example.test").await;
    let resolver_auth = builder::<B>(&connection)
        .store(B::hook(
            B::store(
                Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN)),
                &connection,
            ),
            RegistrationSessionPolicy(policy.clone()),
        ))
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("Native test")
                .origin(ORIGIN)
                .registration(alibi::plugins::passkey::PasskeyRegistrationConfig {
                    extensions: None,
                    require_session: false,
                    resolve_user: Some(Arc::new(RegistrationResolver(
                        body(&owner)["user"]["id"].as_str().unwrap().into(),
                    ))),
                    after_verification: Some(policy.clone()),
                }),
        )
        .build()
        .await?;
    let rejected = call(
        &resolver_auth,
        request("/passkey/generate-register-options", None, ""),
        400,
    )
    .await;
    assert_eq!(body(&rejected)["code"], "RESOLVED_USER_INVALID");
    assert_eq!(db.count("verifications").await?, 0);

    // Act as an authenticator: answer the server's actual challenge with a
    // public test key. No production encoder, verifier or credential is mocked.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let id = b"native-stored-passkey";
    let key = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
        (Cbor::Integer(1), Cbor::Integer(1)),
        (Cbor::Integer(3), Cbor::Integer(-8)),
        (Cbor::Integer(-1), Cbor::Integer(6)),
        (
            Cbor::Integer(-2),
            Cbor::Bytes(signing.verifying_key().as_bytes().to_vec()),
        ),
    ])))?;
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(0x45); // User present, user verified, attested credential included.
    data.extend_from_slice(&1_u32.to_be_bytes());
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
    data.extend_from_slice(id);
    data.extend_from_slice(&key);
    let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
        (Cbor::Text("authData".into()), Cbor::Bytes(data)),
    ])))?;
    let original = db.tables(&["passkeys", "sessions"]).await?;
    for mode in 0..4 {
        policy
            .registration
            .store(mode, std::sync::atomic::Ordering::SeqCst);
        let registration_auth = if mode == 3 { &resolver_auth } else { &auth };
        let registration_cookie = if mode == 3 {
            String::new()
        } else {
            cookies(&owner)
        };
        let mut generate = request(
            "/passkey/generate-register-options",
            None,
            &registration_cookie,
        );
        if mode == 3 {
            drop(
                generate
                    .query
                    .insert("context".into(), "application-enrollment".into()),
            );
        }
        let options = call(registration_auth, generate, 200).await;
        let client = serde_json::to_vec(
            &json!({"type":"webauthn.create","challenge":body(&options)["challenge"],"origin":ORIGIN}),
        )?;
        let proof = json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"attestationObject":URL_SAFE_NO_PAD.encode(&attestation),"transports":["internal"]}});
        if mode == 0 {
            let before = db
                .tables(&["verifications", "passkeys", "sessions"])
                .await?;
            for input in [
                json!({}),
                json!({"response":proof,"name":null}),
                json!({"response":proof,"createSession":"true"}),
                json!({"response":proof,"createSession":null}),
            ] {
                let _ = call(
                    registration_auth,
                    request(
                        "/passkey/verify-registration",
                        Some(input),
                        &format!("{}; {}", registration_cookie, cookies(&options)),
                    ),
                    400,
                )
                .await;
                assert_eq!(
                    db.tables(&["verifications", "passkeys", "sessions"])
                        .await?,
                    before
                );
            }
        }
        let registered = call(
            registration_auth,
            request(
                "/passkey/verify-registration",
                Some(json!({"response":proof,"createSession":true})),
                &format!("{}; {}", registration_cookie, cookies(&options)),
            ),
            match mode {
                0 => 403,
                1 => 401,
                2 => 500,
                _ => 200,
            },
        )
        .await;
        if mode < 3 {
            assert_eq!(db.tables(&["passkeys", "sessions"]).await?, original);
            if mode == 1 {
                assert_eq!(
                    body(&registered)["code"],
                    "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
                );
            }
        } else {
            authenticated(&auth, &cookies(&registered), "passkey@example.test").await;
            assert_eq!(
                db.text("SELECT name FROM passkeys", &[]).await?.as_deref(),
                Some("Application credential")
            );
        }
    }
    assert_eq!(
        *policy.registrations.lock().unwrap(),
        vec![body(&owner)["user"]["id"].as_str().unwrap().to_owned(); 4]
    );
    assert_eq!(db.count("passkeys").await?, 1);
    let options = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    let client = serde_json::to_vec(&json!({
        "type":"webauthn.get","challenge":body(&options)["challenge"],"origin":ORIGIN
    }))?;
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(0x05); // User present and verified.
    data.extend_from_slice(&2_u32.to_be_bytes());
    let mut signed = data.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let proof = json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),
    "type":"public-key","clientExtensionResults":{},"response":{
        "clientDataJSON":URL_SAFE_NO_PAD.encode(client),
        "authenticatorData":URL_SAFE_NO_PAD.encode(data),
        "signature":URL_SAFE_NO_PAD.encode(signing.sign(&signed).to_bytes())
    }});
    let before = db
        .tables(&["verifications", "passkeys", "sessions"])
        .await?;
    for malformed in [
        json!({}),
        json!({"response":null}),
        json!({"response":[]}),
        json!({"response":"invalid"}),
    ] {
        let _ = call(
            &auth,
            request(
                "/passkey/verify-authentication",
                Some(malformed),
                &cookies(&options),
            ),
            400,
        )
        .await;
        assert_eq!(
            db.tables(&["verifications", "passkeys", "sessions"])
                .await?,
            before
        );
    }
    let credential_id = db.text("SELECT id FROM passkeys", &[]).await?.unwrap();
    let _ = call(
        &auth,
        request(
            "/passkey/update-passkey",
            Some(json!({"id":credential_id,"name":" \t "})),
            &cookies(&owner),
        ),
        400,
    )
    .await;
    assert_eq!(
        db.tables(&["verifications", "passkeys", "sessions"])
            .await?,
        before
    );
    let input = request(
        "/passkey/verify-authentication",
        Some(json!({"response":proof})),
        &cookies(&options),
    );
    let accepted = call(&auth, input.clone(), 200).await;
    authenticated(&auth, &cookies(&accepted), "passkey@example.test").await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM passkeys WHERE counter = 2 AND user_id = $1",
            &[body(&owner)["user"]["id"].as_str().unwrap()]
        )
        .await?,
        1
    );
    let replay = call(&auth, input, 400).await;
    assert_eq!(body(&replay)["code"], "CHALLENGE_NOT_FOUND");
    assert_eq!(db.count("sessions").await?, 3);
    let persisted = db.table("passkeys").await?;
    for (counter, corrupt_signature, veto) in
        [(3_u32, true, false), (2, false, false), (3, false, true)]
    {
        policy
            .deny_authentication
            .store(veto, std::sync::atomic::Ordering::SeqCst);
        let callbacks_before = policy.authentications.lock().unwrap().len();
        let options = call(
            &auth,
            request("/passkey/generate-authenticate-options", None, ""),
            200,
        )
        .await;
        let client = serde_json::to_vec(&json!({
            "type":"webauthn.get","challenge":body(&options)["challenge"],"origin":ORIGIN
        }))?;
        let mut data = Sha256::digest(b"localhost").to_vec();
        data.push(0x05);
        data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let mut signature = signing.sign(&signed).to_bytes();
        if corrupt_signature {
            signature[0] ^= 1;
        }
        let proof = json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),
        "type":"public-key","clientExtensionResults":{},"response":{
            "clientDataJSON":URL_SAFE_NO_PAD.encode(client),
            "authenticatorData":URL_SAFE_NO_PAD.encode(data),
            "signature":URL_SAFE_NO_PAD.encode(signature)
        }});
        let denied = call(
            &auth,
            request(
                "/passkey/verify-authentication",
                Some(json!({"response":proof})),
                &cookies(&options),
            ),
            if veto {
                403
            } else if corrupt_signature {
                401
            } else {
                400
            },
        )
        .await;
        if veto {
            assert_eq!(body(&denied)["message"], "Application veto");
        } else {
            assert_eq!(body(&denied)["code"], "AUTHENTICATION_FAILED");
        }
        assert_eq!(
            policy.authentications.lock().unwrap().len(),
            callbacks_before + usize::from(veto)
        );
        assert_eq!(db.table("passkeys").await?, persisted);
        assert_eq!(db.count("sessions").await?, 3);
        assert!(
            !denied
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.session_token=")
                    && !cookie.contains("Max-Age=0"))
        );
    }
    assert_eq!(*policy.authentications.lock().unwrap(), vec![2, 3]);
    B::close(connection).await
}
