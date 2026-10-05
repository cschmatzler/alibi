//! Real CRL delivery must affect enrollment before any credential is committed.
#![allow(
    clippy::indexing_slicing,
    reason = "Independent ceremony fixtures have asserted JSON and byte shapes"
)]
use super::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Signer,
    x509::{X509, X509Extension, X509NameBuilder, extension::BasicConstraints},
};
use serde_cbor_2::Value as Cbor;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert ceremony and persistence contracts while propagating fixture setup errors"
)]
async fn delivered_crl_rejects_revoked_attestation_without_persisting_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let root_pem =
        include_str!("../../../../../../tests/compat/fixtures/passkey-attestation/ca.pem");
    let root = X509::from_pem(root_pem.as_bytes())?;
    let root_key = PKey::private_key_from_pem(include_bytes!(
        "../../../../../../tests/compat/fixtures/passkey-attestation/ca-key.pem"
    ))?;
    let crl =
        include_bytes!("../../../../../../tests/compat/fixtures/passkey-attestation/revoked.der");
    for (mode, serial, expected) in [
        ("revoked", 42, 500),
        ("allowed", 43, 200),
        ("malformed", 42, 200),
        ("http-error-valid-crl", 42, 500),
        ("unavailable", 42, 200),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let uri = format!("http://{}/revocation.der", listener.local_addr()?);
        let delivered = Arc::new(AtomicUsize::new(0));
        let count = delivered.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let size = socket.read(&mut request).await.unwrap();
                assert!(request[..size].starts_with(b"GET /revocation.der HTTP/1.1"));
                count.fetch_add(1, Ordering::SeqCst);
                if mode == "unavailable" {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\ntruncated").await.unwrap();
                    continue;
                }
                let bytes = if mode == "malformed" {
                    b"not a DER CRL".as_slice()
                } else {
                    crl.as_slice()
                };
                let status = if mode == "http-error-valid-crl" {
                    "503 Unavailable"
                } else {
                    "200 OK"
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(bytes).await.unwrap();
            }
        });
        let key = PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?;
        let mut name = X509NameBuilder::new()?;
        for (field, value) in [
            ("C", "US"),
            ("O", "Native test authenticator"),
            ("OU", "Authenticator Attestation"),
            ("CN", "Native CRL leaf"),
        ] {
            name.append_entry_by_text(field, value)?;
        }
        let name = name.build();
        let mut leaf = X509::builder()?;
        leaf.set_version(2)?;
        leaf.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
        leaf.set_subject_name(&name)?;
        leaf.set_issuer_name(root.subject_name())?;
        leaf.set_pubkey(&key)?;
        leaf.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        leaf.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        leaf.append_extension(BasicConstraints::new().critical().build()?)?;
        // No AKI/SKI: each ceremony must actually fetch its own local CRL, and
        // cannot inherit a process-global cached verdict from another case.
        #[expect(
            deprecated,
            reason = "OpenSSL exposes distribution-point configuration through this extension builder"
        )]
        let distribution = X509Extension::new_nid(
            None,
            None,
            Nid::CRL_DISTRIBUTION_POINTS,
            &format!("URI:{uri}"),
        )?;
        leaf.append_extension(distribution)?;
        leaf.sign(&root_key, MessageDigest::sha256())?;
        let leaf = leaf.build();
        let plugin = passkey_plugin().attestation_root_certificates(BTreeMap::from([(
            "packed".into(),
            vec![root_pem.into()],
        )]));
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("revocation@fixture.test")
                .with_name("CRL owner"),
            Duration::hours(1),
        )
        .await;
        let options = plugin
            .handle_generate_register_options(
                &test_helpers::create_auth_request(
                    HttpMethod::Get,
                    "/passkey/generate-register-options",
                    Some(&session.token),
                    None,
                    HashMap::new(),
                ),
                &ctx,
            )
            .await?;
        let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
        let client = serde_json::to_vec(
            &serde_json::json!({"type":"webauthn.create","challenge":issued["challenge"],"origin":"http://localhost:3000"}),
        )?;
        let credential_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let cose = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(1)),
            (Cbor::Integer(3), Cbor::Integer(-8)),
            (Cbor::Integer(-1), Cbor::Integer(6)),
            (
                Cbor::Integer(-2),
                Cbor::Bytes(credential_key.verifying_key().as_bytes().to_vec()),
            ),
        ])))?;
        let id = b"crl-enrollment";
        let mut data = Sha256::digest(b"localhost").to_vec();
        data.push(0x45);
        data.extend_from_slice(&1_u32.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
        data.extend_from_slice(id);
        data.extend_from_slice(&cose);
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(&signed)?;
        let statement = Cbor::Map(BTreeMap::from([
            (Cbor::Text("alg".into()), Cbor::Integer(-7)),
            (
                Cbor::Text("x5c".into()),
                Cbor::Array(vec![Cbor::Bytes(leaf.to_der()?)]),
            ),
            (Cbor::Text("sig".into()), Cbor::Bytes(signer.sign_to_vec()?)),
        ]));
        let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
            (Cbor::Text("attStmt".into()), statement),
        ])))?;
        let response = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"attestationObject":URL_SAFE_NO_PAD.encode(attestation),"transports":["internal"]}});
        let mut request = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(serde_json::to_vec(
                &serde_json::json!({"response":response}),
            )?),
            HashMap::new(),
        );
        write!(
            request.headers.get_mut("cookie").unwrap(),
            "; {}",
            cookie_header(&options).split(';').next().unwrap()
        )?;
        let result = plugin.handle_verify_registration(&request, &ctx).await?;
        server.abort();
        assert_eq!(delivered.load(Ordering::SeqCst), 1, "{mode}");
        assert_eq!(
            result.status,
            expected,
            "{mode}: {}",
            String::from_utf8_lossy(&result.body)
        );
        let stored = ctx
            .database
            .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
            .await?;
        if expected == 200 {
            assert_eq!(stored.unwrap().user_id, user.id);
        } else {
            assert!(stored.is_none());
            assert!(
                result
                    .headers
                    .get_all("set-cookie")
                    .all(|cookie| !cookie.contains("session_token="))
            );
        }
        assert_eq!(ctx.database.get_user_sessions(&user.id).await?.len(), 1);
    }
    Ok(())
}
