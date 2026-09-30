use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult};
use ed25519_dalek::{Signer, Verifier};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::{Value, json};
use sha2::Sha256;

use super::{JwtAlgorithm, JwtKeyPairConfig};

pub(super) fn generate(config: &JwtKeyPairConfig) -> AuthResult<(Value, Value)> {
    match config.algorithm {
        JwtAlgorithm::EdDsa => {
            let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let public = json!({ "kty": "OKP", "crv": "Ed25519", "x": encode(key.verifying_key().as_bytes()) });
            let private = private_jwk(&public, [("d", json!(encode(key.as_bytes())))])?;
            Ok((public, private))
        }
        JwtAlgorithm::Es256 => {
            let key = p256::SecretKey::random(&mut OsRng);
            let point = key.public_key().to_encoded_point(false);
            ec_pair(
                "P-256",
                key.to_bytes().as_slice(),
                point.x().map(|x| x.as_slice()),
                point.y().map(|y| y.as_slice()),
            )
        }
        JwtAlgorithm::Es512 => {
            let key = p521::SecretKey::random(&mut OsRng);
            let point = key.public_key().to_encoded_point(false);
            ec_pair(
                "P-521",
                key.to_bytes().as_slice(),
                point.x().map(|x| x.as_slice()),
                point.y().map(|y| y.as_slice()),
            )
        }
        JwtAlgorithm::Ps256 | JwtAlgorithm::Rs256 => {
            let bits = config.modulus_length.unwrap_or(2048);
            if bits < 2048 {
                return Err(AuthError::config(
                    "RSA modulus length must be at least 2048 bits",
                ));
            }
            let mut key = rsa::RsaPrivateKey::new(&mut OsRng, bits).map_err(crypto_error)?;
            key.precompute().map_err(crypto_error)?;
            let public = json!({ "kty": "RSA", "n": encode(&key.n().to_bytes_be()), "e": encode(&key.e().to_bytes_be()) });
            let mut primes = key.primes().iter();
            let p = primes
                .next()
                .ok_or_else(|| AuthError::internal("RSA key has no first prime"))?;
            let q = primes
                .next()
                .ok_or_else(|| AuthError::internal("RSA key has no second prime"))?;
            let private = private_jwk(
                &public,
                [
                    ("d", json!(encode(&key.d().to_bytes_be()))),
                    ("p", json!(encode(&p.to_bytes_be()))),
                    ("q", json!(encode(&q.to_bytes_be()))),
                    (
                        "dp",
                        json!(encode(
                            &key.dp()
                                .ok_or_else(|| AuthError::internal("RSA CRT exponent missing"))?
                                .to_bytes_be()
                        )),
                    ),
                    (
                        "dq",
                        json!(encode(
                            &key.dq()
                                .ok_or_else(|| AuthError::internal("RSA CRT exponent missing"))?
                                .to_bytes_be()
                        )),
                    ),
                    (
                        "qi",
                        json!(encode(
                            &key.qinv()
                                .ok_or_else(|| AuthError::internal("RSA CRT coefficient missing"))?
                                .to_bytes_be()
                                .1
                        )),
                    ),
                ],
            )?;
            Ok((public, private))
        }
    }
}

fn ec_pair(
    curve: &str,
    secret: &[u8],
    x: Option<&[u8]>,
    y: Option<&[u8]>,
) -> AuthResult<(Value, Value)> {
    let public = json!({ "kty": "EC", "crv": curve,
        "x": encode(x.ok_or_else(|| AuthError::internal("EC coordinate missing"))?),
        "y": encode(y.ok_or_else(|| AuthError::internal("EC coordinate missing"))?),
    });
    let private = private_jwk(&public, [("d", json!(encode(secret)))])?;
    Ok((public, private))
}

fn private_jwk<const N: usize>(public: &Value, fields: [(&str, Value); N]) -> AuthResult<Value> {
    let mut private = public
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::internal("Public JWK must be an object"))?;
    for (name, value) in fields {
        let _ = private.insert(name.to_owned(), value);
    }
    Ok(Value::Object(private))
}

pub(super) fn sign(
    algorithm: JwtAlgorithm,
    private: &Value,
    message: &[u8],
) -> AuthResult<Vec<u8>> {
    validate_key_metadata(algorithm, private, "sign")?;
    match algorithm {
        JwtAlgorithm::EdDsa => {
            let seed: [u8; 32] = field(private, "d")?
                .try_into()
                .map_err(|_| AuthError::internal("Invalid Ed25519 private key"))?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
                .sign(message)
                .to_bytes()
                .to_vec())
        }
        JwtAlgorithm::Es256 => {
            let key =
                p256::ecdsa::SigningKey::from_slice(&field(private, "d")?).map_err(crypto_error)?;
            let signature: p256::ecdsa::Signature = key.sign_with_rng(&mut OsRng, message);
            Ok(signature.to_bytes().to_vec())
        }
        JwtAlgorithm::Es512 => {
            let key =
                p521::ecdsa::SigningKey::from_slice(&field(private, "d")?).map_err(crypto_error)?;
            let signature: p521::ecdsa::Signature = key.sign_with_rng(&mut OsRng, message);
            Ok(signature.to_bytes().to_vec())
        }
        JwtAlgorithm::Rs256 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private(private)?);
            Ok(key.sign(message).to_vec())
        }
        JwtAlgorithm::Ps256 => {
            let key = rsa::pss::SigningKey::<Sha256>::new(rsa_private(private)?);
            Ok(key.sign_with_rng(&mut OsRng, message).to_vec())
        }
    }
}

pub(super) fn verify(
    algorithm: JwtAlgorithm,
    public: &Value,
    message: &[u8],
    signature: &[u8],
) -> AuthResult<bool> {
    validate_key_metadata(algorithm, public, "verify")?;
    let valid = match algorithm {
        JwtAlgorithm::EdDsa => {
            let bytes: [u8; 32] = field(public, "x")?
                .try_into()
                .map_err(|_| AuthError::internal("Invalid Ed25519 public key"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(crypto_error)?;
            let signature =
                ed25519_dalek::Signature::from_slice(signature).map_err(crypto_error)?;
            key.verify(message, &signature).is_ok()
        }
        JwtAlgorithm::Es256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&ec_public(public)?)
                .map_err(crypto_error)?;
            let signature = p256::ecdsa::Signature::from_slice(signature).map_err(crypto_error)?;
            key.verify(message, &signature).is_ok()
        }
        JwtAlgorithm::Es512 => {
            let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&ec_public(public)?)
                .map_err(crypto_error)?;
            let signature = p521::ecdsa::Signature::from_slice(signature).map_err(crypto_error)?;
            key.verify(message, &signature).is_ok()
        }
        JwtAlgorithm::Rs256 => {
            let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_public(public)?);
            let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(crypto_error)?;
            key.verify(message, &signature).is_ok()
        }
        JwtAlgorithm::Ps256 => {
            let key = rsa::pss::VerifyingKey::<Sha256>::new(rsa_public(public)?);
            let signature = rsa::pss::Signature::try_from(signature).map_err(crypto_error)?;
            key.verify(message, &signature).is_ok()
        }
    };
    Ok(valid)
}

fn rsa_public(key: &Value) -> AuthResult<rsa::RsaPublicKey> {
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&field(key, "n")?),
        rsa::BigUint::from_bytes_be(&field(key, "e")?),
    )
    .map_err(crypto_error)?;
    if key.n().bits() < 2048 {
        return Err(AuthError::config(
            "RSA modulus length must be at least 2048 bits",
        ));
    }
    Ok(key)
}

fn rsa_private(key: &Value) -> AuthResult<rsa::RsaPrivateKey> {
    let key = rsa::RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(&field(key, "n")?),
        rsa::BigUint::from_bytes_be(&field(key, "e")?),
        rsa::BigUint::from_bytes_be(&field(key, "d")?),
        vec![
            rsa::BigUint::from_bytes_be(&field(key, "p")?),
            rsa::BigUint::from_bytes_be(&field(key, "q")?),
        ],
    )
    .map_err(crypto_error)?;
    if key.n().bits() < 2048 {
        return Err(AuthError::config(
            "RSA modulus length must be at least 2048 bits",
        ));
    }
    Ok(key)
}

fn validate_key_metadata(algorithm: JwtAlgorithm, key: &Value, operation: &str) -> AuthResult<()> {
    let key_type = match algorithm {
        JwtAlgorithm::EdDsa => "OKP",
        JwtAlgorithm::Es256 | JwtAlgorithm::Es512 => "EC",
        JwtAlgorithm::Rs256 | JwtAlgorithm::Ps256 => "RSA",
    };
    if key.get("kty").and_then(Value::as_str) != Some(key_type)
        || algorithm
            .curve()
            .is_some_and(|curve| key.get("crv").and_then(Value::as_str) != Some(curve))
        || key.get("ext").is_some_and(|value| !value.is_boolean())
        || (operation == "verify" && (key.get("d").is_some() || key.get("priv").is_some()))
    {
        return Err(AuthError::config(
            "Invalid JWK metadata for signing algorithm",
        ));
    }
    if let Some(operations) = key.get("key_ops")
        && !operations.as_array().is_some_and(|values| {
            values.len() == 1 && values.first().and_then(Value::as_str) == Some(operation)
        })
    {
        return Err(AuthError::config("Invalid JWK key operations"));
    }
    let coordinate_length = match algorithm {
        JwtAlgorithm::EdDsa | JwtAlgorithm::Es256 => Some(32),
        JwtAlgorithm::Es512 => Some(66),
        JwtAlgorithm::Rs256 | JwtAlgorithm::Ps256 => None,
    };
    if let Some(length) = coordinate_length
        && (field(key, "x")?.len() != length
            || (key_type == "EC" && field(key, "y")?.len() != length))
    {
        return Err(AuthError::config("Invalid JWK coordinate length"));
    }
    Ok(())
}

fn ec_public(key: &Value) -> AuthResult<Vec<u8>> {
    let mut bytes = vec![4];
    bytes.extend(field(key, "x")?);
    bytes.extend(field(key, "y")?);
    Ok(bytes)
}

fn field(key: &Value, field: &str) -> AuthResult<Vec<u8>> {
    let value = key
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::internal(format!("JWK {field} missing")))?;
    URL_SAFE_NO_PAD.decode(value).map_err(crypto_error)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn crypto_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::internal(format!("JWT key operation failed: {error}"))
}
