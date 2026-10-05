//! Cryptographic interoperability of the public RFC 7523 assertion generator.
//! HTTP delivery/binding is separately owned by storage/plugin_flows/oidc.rs.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "contract tests assert independently specified wire fields; setup errors propagate"
)]

use crate::storage::TestResult;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::plugins::oauth::{
    OAuthClientAssertionContext, OAuthPrivateKeyJwtOptions, OAuthTokenGrant,
};
use serde_json::{Value, json};
use std::collections::HashSet;

const CLIENT: &str = "assertion-client";
const ENDPOINT: &str = "https://issuer.example.test/token";
fn context() -> OAuthClientAssertionContext {
    OAuthClientAssertionContext {
        client_id: CLIENT.into(),
        token_endpoint: ENDPOINT.into(),
        grant_type: OAuthTokenGrant::AuthorizationCode,
    }
}
fn keys() -> Value {
    serde_json::from_str(include_str!(
        "../../fixtures/oauth/client-assertion-keys.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn every_client_assertion_algorithm_interoperates_for_jwk_and_pkcs8() -> TestResult {
    let keys = keys();
    let mut identifiers = HashSet::new();
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
        for format in ["jwk", "pem"] {
            let options = OAuthPrivateKeyJwtOptions {
                private_key_jwk: (format == "jwk").then(|| key["privateJwk"].clone()),
                private_key_pem: (format == "pem")
                    .then(|| key["privatePem"].as_str().unwrap().to_owned()),
                algorithm: Some(algorithm.into()),
                kid: Some("application-key".into()),
                expires_in: Some(90.0),
            };
            let before = chrono::Utc::now().timestamp();
            let token = options
                .into_assertion()?
                .0
                .get_client_assertion(context())
                .await?;
            let after = chrono::Utc::now().timestamp();
            let parts: Vec<_> = token.split('.').collect();
            assert_eq!(parts.len(), 3);
            let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
            assert_eq!(header["alg"], algorithm);
            assert_eq!(header["typ"], "JWT");
            assert_eq!(header["kid"], "application-key");
            let claims = if algorithm == "ES512" {
                // jsonwebtoken does not implement ES512. Verify its JOSE fixed-width
                // r||s signature with the public P-521 key and SHA-512 verifier.
                use p521::ecdsa::signature::Verifier as _;
                let mut point = vec![4];
                point.extend(URL_SAFE_NO_PAD.decode(key["publicJwk"]["x"].as_str().unwrap())?);
                point.extend(URL_SAFE_NO_PAD.decode(key["publicJwk"]["y"].as_str().unwrap())?);
                let verifier = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)?;
                let bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
                assert_eq!(bytes.len(), 132);
                let signature = p521::ecdsa::Signature::from_slice(&bytes)?;
                verifier.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)?;
                serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(parts[1])?)?
            } else {
                let algorithm: jsonwebtoken::Algorithm = algorithm.parse()?;
                let jwk = serde_json::from_value(key["publicJwk"].clone())?;
                let mut validation = jsonwebtoken::Validation::new(algorithm);
                validation.set_audience(&[ENDPOINT]);
                validation.set_issuer(&[CLIENT]);
                validation.sub = Some(CLIENT.into());
                jsonwebtoken::decode::<Value>(
                    &token,
                    &jsonwebtoken::DecodingKey::from_jwk(&jwk)?,
                    &validation,
                )?
                .claims
            };
            assert_eq!(claims["iss"], CLIENT);
            assert_eq!(claims["sub"], CLIENT);
            assert_eq!(claims["aud"], ENDPOINT);
            assert!((before..=after).contains(&claims["iat"].as_i64().unwrap()));
            assert_eq!(
                claims["exp"].as_f64().unwrap() - claims["iat"].as_f64().unwrap(),
                90.0
            );
            assert!(
                identifiers.insert(claims["jti"].as_str().unwrap().to_owned()),
                "freshness failed for {algorithm}/{format}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn client_assertions_reject_unusable_or_unauthorized_key_material() -> TestResult {
    for options in [
        OAuthPrivateKeyJwtOptions::default(),
        OAuthPrivateKeyJwtOptions {
            private_key_pem: Some("present".into()),
            algorithm: Some("HS256".into()),
            ..Default::default()
        },
        OAuthPrivateKeyJwtOptions {
            private_key_jwk: Some(json!({"alg":"RS384"})),
            algorithm: Some("RS256".into()),
            ..Default::default()
        },
    ] {
        assert!(options.into_assertion().is_err());
    }
    let keys = keys();
    let key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "P-256")
        .unwrap();
    let valid = OAuthPrivateKeyJwtOptions {
        private_key_jwk: Some(key["privateJwk"].clone()),
        algorithm: Some("ES256".into()),
        ..Default::default()
    };
    assert!(
        valid
            .clone()
            .into_assertion()?
            .0
            .get_client_assertion(context())
            .await
            .is_ok()
    );
    for (field, replacement) in [
        ("key_ops", json!(["verify"])),
        ("key_ops", json!(["sign", "sign"])),
        ("ext", json!("true")),
        ("kty", json!("RSA")),
        ("crv", json!("P-384")),
        ("x", json!(URL_SAFE_NO_PAD.encode([0_u8; 32]))),
        ("d", json!("not base64!")),
    ] {
        let mut options = valid.clone();
        options.private_key_jwk.as_mut().unwrap()[field] = replacement;
        assert!(
            options
                .into_assertion()?
                .0
                .get_client_assertion(context())
                .await
                .is_err(),
            "{field}"
        );
    }
    let mut invalid_expiry = valid.clone();
    invalid_expiry.expires_in = Some(f64::NAN);
    assert!(
        invalid_expiry
            .into_assertion()?
            .0
            .get_client_assertion(context())
            .await
            .is_err()
    );
    let mut malformed_pem = valid.clone();
    malformed_pem.private_key_jwk = None;
    malformed_pem.private_key_pem = Some("not a PEM key".into());
    assert!(
        malformed_pem
            .into_assertion()?
            .0
            .get_client_assertion(context())
            .await
            .is_err()
    );
    // A present, invalid JWK must not silently use a valid fallback PEM.
    let mut precedence = valid;
    precedence.private_key_jwk = Some(json!({}));
    precedence.private_key_pem = Some(key["privatePem"].as_str().unwrap().into());
    assert!(
        precedence
            .into_assertion()?
            .0
            .get_client_assertion(context())
            .await
            .is_err()
    );
    Ok(())
}
