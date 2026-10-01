use super::*;
use crate::plugins::test_helpers;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_auth_core::{CreatePasskey, CreateUser, HttpMethod};
use chrono::Duration;
use std::collections::HashMap;
use std::fmt::Write;

fn passkey_plugin() -> PasskeyPlugin {
    PasskeyPlugin::new()
        .rp_id("localhost")
        .rp_name("Better Auth Test")
        .origin("http://localhost:3000")
}

fn cookie_header(response: &AuthResponse) -> &str {
    response
        .headers
        .get("Set-Cookie")
        .expect("response should include a Set-Cookie header")
}

fn credential_id(label: &str) -> String {
    URL_SAFE_NO_PAD.encode(label.as_bytes())
}

#[test]
fn test_extract_passkey_snapshot_fields_requires_all_expected_fields() {
    let value = serde_json::json!({
        "cred": {
            "counter": 7,
            "backup_state": true
        }
    });

    let err = webauthn::extract_passkey_snapshot_fields(&value).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Internal server error: Stored passkey JSON missing backup_eligible"
    );
}

#[test]
fn test_extract_passkey_snapshot_fields_reads_expected_values() {
    let value = serde_json::json!({
        "cred": {
            "counter": 11,
            "backup_state": true,
            "backup_eligible": false
        }
    });

    let (counter, backed_up, backup_eligible) =
        webauthn::extract_passkey_snapshot_fields(&value).unwrap();
    assert_eq!(counter, 11);
    assert!(backed_up);
    assert!(!backup_eligible);
}

#[tokio::test]
async fn test_generate_register_options_sets_cookie_and_uses_query_name() {
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: Some("Existing Key".to_owned()),
            credential_id: credential_id("cred-existing"),
            public_key: "public-key".to_owned(),
            counter: 0,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: Some("usb,nfc".to_owned()),
            credential: "invalid-stored-passkey".to_owned(),
            aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        Some(&session.token),
        None,
        HashMap::from([
            ("name".to_owned(), "Custom Account Label".to_owned()),
            (
                "authenticatorAttachment".to_owned(),
                "cross-platform".to_owned(),
            ),
        ]),
    );

    let response = plugin
        .handle_generate_register_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(cookie_header(&response).contains("better-auth-passkey="));

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!((*(body).get("challenge").unwrap_or(&serde_json::Value::Null)).is_string());
    assert_eq!(
        (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
            .get("name")
            .unwrap_or(&serde_json::Value::Null)),
        "Custom Account Label"
    );
    assert_eq!(
        (*(*(body)
            .get("authenticatorSelection")
            .unwrap_or(&serde_json::Value::Null))
        .get("authenticatorAttachment")
        .unwrap_or(&serde_json::Value::Null)),
        "cross-platform"
    );
    assert_eq!(
        (*(*(*(body)
            .get("excludeCredentials")
            .unwrap_or(&serde_json::Value::Null))
        .get(0)
        .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null)),
        credential_id("cred-existing")
    );
    assert_eq!(
        (*(*(*(*(body)
            .get("excludeCredentials")
            .unwrap_or(&serde_json::Value::Null))
        .get(0)
        .unwrap_or(&serde_json::Value::Null))
        .get("transports")
        .unwrap_or(&serde_json::Value::Null))
        .get(0)
        .unwrap_or(&serde_json::Value::Null)),
        "usb"
    );
}

#[tokio::test]
async fn test_generate_authenticate_options_is_get_and_sets_cookie_without_auth() {
    let plugin = passkey_plugin();
    let ctx = test_helpers::create_test_context().await;
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-authenticate-options",
        None,
        None,
    );

    let response = plugin
        .handle_generate_authenticate_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(cookie_header(&response).contains("better-auth-passkey="));

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!((*(body).get("challenge").unwrap_or(&serde_json::Value::Null)).is_string());
    assert!(body.get("allowCredentials").is_none());
}

#[tokio::test]
async fn test_generate_authenticate_options_with_auth_lists_allow_credentials() {
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: Some("Authenticator".to_owned()),
            credential_id: credential_id("cred-auth"),
            public_key: "public-key".to_owned(),
            counter: 0,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: Some("internal".to_owned()),
            credential: "invalid-stored-passkey".to_owned(),
            aaguid: None,
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/generate-authenticate-options",
        Some(&session.token),
        None,
    );

    let response = plugin
        .handle_generate_authenticate_options(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(*(*(body)
            .get("allowCredentials")
            .unwrap_or(&serde_json::Value::Null))
        .get(0)
        .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null)),
        credential_id("cred-auth")
    );
    assert_eq!(
        (*(*(*(*(body)
            .get("allowCredentials")
            .unwrap_or(&serde_json::Value::Null))
        .get(0)
        .unwrap_or(&serde_json::Value::Null))
        .get("transports")
        .unwrap_or(&serde_json::Value::Null))
        .get(0)
        .unwrap_or(&serde_json::Value::Null)),
        "internal"
    );
}

#[tokio::test]
async fn test_verify_registration_without_challenge_cookie_returns_challenge_not_found() {
    let plugin = passkey_plugin();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    let body = serde_json::json!({
        "response": {
            "id": "fake-credential-id",
            "rawId": "ZmFrZS1yYXctaWQ",
            "response": {
                "attestationObject": "ZmFrZS1hdHRlc3RhdGlvbg",
                "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ"
            },
            "type": "public-key"
        }
    });
    let mut req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(body),
    );
    req.headers
        .insert("origin".to_owned(), "http://localhost:3000".to_owned());

    let response = plugin.handle_verify_registration(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 400);

    let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
        "Challenge not found"
    );
}

#[tokio::test]
async fn test_verify_authentication_without_challenge_cookie_returns_challenge_not_found() {
    let plugin = passkey_plugin();
    let ctx = test_helpers::create_test_context().await;

    let body = serde_json::json!({
        "response": {
            "id": credential_id("cred-auth"),
            "rawId": credential_id("cred-auth"),
            "response": {
                "authenticatorData": "ZmFrZS1hdXRoLWRhdGE",
                "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ",
                "signature": "ZmFrZS1zaWduYXR1cmU"
            },
            "type": "public-key"
        }
    });
    let mut req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/verify-authentication",
        None,
        Some(body),
    );
    req.headers
        .insert("origin".to_owned(), "http://localhost:3000".to_owned());

    let response = plugin
        .handle_verify_authentication(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 400);

    let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
        "Challenge not found"
    );
}

#[tokio::test]
async fn test_list_user_passkeys_includes_updated_at_and_optional_fields() {
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("passkey-test@example.com")
            .with_name("Passkey Tester"),
        Duration::hours(1),
    )
    .await;

    ctx.database
        .create_passkey(CreatePasskey {
            user_id: user.id.clone(),
            name: None,
            credential_id: credential_id("cred-list"),
            public_key: "public-key".to_owned(),
            counter: 0,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: None,
            credential: "invalid-stored-passkey".to_owned(),
            aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()),
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/passkey/list-user-passkeys",
        Some(&session.token),
        None,
    );
    let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        (*(body).get(0).unwrap_or(&serde_json::Value::Null))
            .get("updatedAt")
            .is_none()
    );
    assert_eq!(
        (*(*(body).get(0).unwrap_or(&serde_json::Value::Null))
            .get("aaguid")
            .unwrap_or(&serde_json::Value::Null)),
        "00000000-0000-0000-0000-000000000000"
    );
    assert!(
        (*(body).get(0).unwrap_or(&serde_json::Value::Null))
            .get("name")
            .is_none()
    );
}

#[tokio::test]
async fn test_delete_passkey_non_owner_is_unauthorized() {
    let plugin = passkey_plugin();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("owner@example.com")
            .with_name("Owner"),
        Duration::hours(1),
    )
    .await;
    let other = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email("other@example.com")
            .with_name("Other"),
    )
    .await;

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: other.id.clone(),
            name: Some("Other Key".to_owned()),
            credential_id: credential_id("cred-other-delete"),
            public_key: "public-key".to_owned(),
            counter: 0,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: None,
            credential: "invalid-stored-passkey".to_owned(),
            aaguid: None,
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/delete-passkey",
        Some(&session.token),
        Some(serde_json::json!({ "id": passkey.id })),
    );

    let response = plugin.handle_delete_passkey(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 401);
    assert_eq!(response.body.len(), 0);
    let preserved = ctx
        .database
        .get_passkey_by_id(&passkey.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.name.as_deref(), Some("Other Key"));
}

#[tokio::test]
async fn test_update_passkey_non_owner_is_unauthorized() {
    let plugin = passkey_plugin();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("owner@example.com")
            .with_name("Owner"),
        Duration::hours(1),
    )
    .await;
    let other = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email("other@example.com")
            .with_name("Other"),
    )
    .await;

    let passkey = ctx
        .database
        .create_passkey(CreatePasskey {
            user_id: other.id.clone(),
            name: Some("Other Key".to_owned()),
            credential_id: credential_id("cred-other-update"),
            public_key: "public-key".to_owned(),
            counter: 0,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: None,
            credential: "invalid-stored-passkey".to_owned(),
            aaguid: None,
        })
        .await
        .unwrap();

    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/passkey/update-passkey",
        Some(&session.token),
        Some(serde_json::json!({
            "id": passkey.id,
            "name": "Hijacked",
        })),
    );

    let response = plugin.handle_update_passkey(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 401);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
    );
    let preserved = ctx
        .database
        .get_passkey_by_id(&passkey.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.name.as_deref(), Some("Other Key"));
}

/// Previously persisted ceremonies keep both their codec and original Required policy.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
fn pending_registration_challenges_keep_original_verification_policy()
-> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use serde_cbor_2::Value as Cbor;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use webauthn_rs::prelude::RegisterPublicKeyCredential;

    let config = PasskeyConfig {
        rp_id: "localhost".into(),
        origin: "http://localhost:3100".into(),
        ..Default::default()
    };
    let webauthn = webauthn::build_webauthn(
        &config,
        &better_auth_core::AuthConfig::default(),
        &config.origin,
    )?;
    let (options, legacy) = webauthn.start_passkey_registration(
        uuid::Uuid::new_v4(),
        "Legacy owner",
        "Legacy owner",
        None,
    )?;
    // This is the old externally persisted protocol, with a real library state.
    let stored = serde_json::to_string(&serde_json::json!({
        "user_id": "legacy-owner", "user": null, "context": "old-context", "state": legacy,
    }))?;
    let decoded: webauthn::StoredRegistrationState = serde_json::from_str(&stored)?;
    assert_eq!(decoded.user_id, "legacy-owner");
    assert_eq!(decoded.context.as_deref(), Some("old-context"));
    let webauthn::StoredRegistrationVerifier::Legacy(state) = decoded.state else {
        panic!("Old challenge changed verifier policy");
    };
    let secret = p256::SecretKey::random(&mut rand::thread_rng());
    let point = secret.public_key().to_encoded_point(false);
    let key = Cbor::Map(BTreeMap::from([
        (Cbor::Integer(1), Cbor::Integer(2)),
        (Cbor::Integer(3), Cbor::Integer(-7)),
        (Cbor::Integer(-1), Cbor::Integer(1)),
        (
            Cbor::Integer(-2),
            Cbor::Bytes(point.x().ok_or("missing generated X coordinate")?.to_vec()),
        ),
        (
            Cbor::Integer(-3),
            Cbor::Bytes(point.y().ok_or("missing generated Y coordinate")?.to_vec()),
        ),
    ]));
    let core = webauthn::build_verification_core(
        &config,
        &better_auth_core::AuthConfig::default(),
        &config.origin,
    )?;
    let builder = core
        .new_challenge_register_builder(b"actual-core-owner", "Core owner", "Core owner")?
        .user_verification_policy(webauthn_rs_core::proto::UserVerificationPolicy::Preferred);
    let (core_options, core_state) = core.generate_challenge_register(builder)?;
    let old_core_wire = serde_json::to_string(&serde_json::json!({
        "user_id": "core-owner", "user": null, "context": "old-core-context",
        "state": {"kind": "core", "state": core_state},
    }))?;
    let decoded_core: webauthn::StoredRegistrationState = serde_json::from_str(&old_core_wire)?;
    let webauthn::StoredRegistrationVerifier::Source(webauthn::StoredCoreRegistrationState::Core {
        state: old_core,
    }) = decoded_core.state
    else {
        panic!("Old Core protocol changed verifier");
    };
    let credential_id = b"actual-legacy-credential";
    let client_data = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.create", "challenge": options.public_key.challenge,
        "origin": config.origin, "crossOrigin": false,
    }))?;
    for verified in [true, false] {
        let mut auth_data = Sha256::digest(config.rp_id.as_bytes()).to_vec();
        auth_data.push(if verified { 0x45 } else { 0x41 });
        auth_data.extend_from_slice(&[0; 20]);
        auth_data.extend_from_slice(&u16::try_from(credential_id.len())?.to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&serde_cbor_2::to_vec(&key)?);
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]));
        let response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
            "id": URL_SAFE_NO_PAD.encode(credential_id), "rawId": URL_SAFE_NO_PAD.encode(credential_id),
            "type": "public-key", "clientExtensionResults": {}, "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                "attestationObject": URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&attestation)?),
                "transports": ["internal"],
            },
        }))?;
        // Feed the historical Core wire's genuinely issued challenge to its
        // actual consumer. This old policy accepts UV absent as well as present.
        let core_client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create", "challenge": core_options.public_key.challenge,
            "origin": config.origin, "crossOrigin": false,
        }))?;
        let mut core_response = response.clone();
        core_response.response.client_data_json = core_client_data.into();
        let restored_core =
            webauthn::finish_core_registration(&core, &core_response, &old_core, &config.origin)?;
        assert_eq!(restored_core.cred_id().as_ref(), credential_id);
        let stored_credential = serde_json::to_string(&restored_core)?;
        let decoded_credential = webauthn::parse_stored_passkey(&stored_credential)?;
        assert_eq!(decoded_credential.cred_id(), restored_core.cred_id());
        let result = webauthn.finish_passkey_registration(&response, &state);
        if verified {
            assert_eq!(result?.cred_id().as_ref(), credential_id);
        } else {
            assert!(matches!(
                result,
                Err(webauthn_rs_core::error::WebauthnError::UserNotVerified)
            ));
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn raw_none_credential_sql_readback_keeps_original_key_and_hidden_codec()
-> Result<(), Box<dyn std::error::Error>> {
    use serde_cbor_2::Value as Cbor;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    let plugin = passkey_plugin();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("raw-codec-owner@fixture.test")
            .with_name("Raw codec owner"),
        Duration::hours(1),
    )
    .await;
    let request = test_helpers::create_auth_request(
        HttpMethod::Get,
        "/passkey/generate-register-options",
        Some(&session.token),
        None,
        HashMap::new(),
    );
    let options = plugin
        .handle_generate_register_options(&request, &ctx)
        .await?;
    let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
    let key = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
        (Cbor::Integer(1), Cbor::Integer(1)),
        (Cbor::Integer(3), Cbor::Integer(-8)),
        (Cbor::Integer(-1), Cbor::Integer(8)),
        (Cbor::Integer(-2), Cbor::Bytes(vec![7; 32])),
    ])))?;
    let id = b"raw-none-actual-persisted-credential";
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(0x41);
    data.extend_from_slice(&25_u32.to_be_bytes());
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
    data.extend_from_slice(id);
    data.extend_from_slice(&key);
    let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
        (Cbor::Text("authData".into()), Cbor::Bytes(data)),
    ])))?;
    let proof = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{
        "clientDataJSON":URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":(*(issued).get("challenge").expect("fixture contains the requested index")),"origin":"http://localhost:3000"}))?),
        "attestationObject":URL_SAFE_NO_PAD.encode(attestation),"transports":["internal"],
    }});
    let mut request_2 = test_helpers::create_auth_request(
        HttpMethod::Post,
        "/passkey/verify-registration",
        Some(&session.token),
        Some(serde_json::to_vec(&serde_json::json!({"response":proof}))?),
        HashMap::new(),
    );
    let issued_cookie = cookie_header(&options)
        .split(';')
        .next()
        .ok_or("issued challenge cookie required")?;
    _ = write!(
        request_2
            .headers
            .get_mut("cookie")
            .ok_or("signed owner cookie required")?,
        "; {issued_cookie}"
    );
    let result = plugin.handle_verify_registration(&request_2, &ctx).await?;
    assert_eq!(result.status, 200);
    let wire: serde_json::Value = serde_json::from_slice(&result.body)?;
    assert!(wire.get("credential").is_none());
    let row = ctx
        .database
        .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
        .await?
        .ok_or("actual credential row required")?;
    assert_eq!(row.user_id, user.id);
    assert_eq!(row.counter, 25);
    assert_eq!(
        row.public_key,
        base64::engine::general_purpose::STANDARD.encode(&key)
    );
    let raw_none::StoredCredential::Raw(raw) = serde_json::from_str(&row.credential)? else {
        panic!("actual raw codec required")
    };
    assert_eq!(raw.credential_id(), id);
    assert_eq!(raw.public_key(), key);
    assert_eq!(raw.snapshot()?.counter, 25);
    assert!(raw.has_unsupported_curve());
    assert!(webauthn::parse_stored_passkey(&row.credential).is_err());
    assert_eq!(ctx.database.get_user_sessions(&user.id).await?.len(), 1);
    Ok(())
}
