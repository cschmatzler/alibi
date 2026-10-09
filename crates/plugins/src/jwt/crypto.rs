use super::{JwtAlgorithm, JwtKeyPairConfig};
use alibi_core::{AuthError, AuthResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, Verifier};
use p256::elliptic_curve::Generate as _;
use p256::elliptic_curve::sec1::ToSec1Point;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::{RandomizedSigner as _, Signer as _, Verifier as _};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::{Value, json};
use signature::RandomizedSigner as _;

pub(super) fn generate(config: &JwtKeyPairConfig) -> AuthResult<(Value, Value)> {
    match config.algorithm {
        JwtAlgorithm::EdDsa => {
            let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
            let public = json!({ "kty": "OKP", "crv": "Ed25519", "x": encode(key.verifying_key().as_bytes()) });
            let private = private_jwk(&public, [("d", json!(encode(key.as_bytes())))])?;
            Ok((public, private))
        }
        JwtAlgorithm::Es256 => {
            let key = p256::SecretKey::generate();
            let point = key.public_key().to_sec1_point(false);
            ec_pair(
                "P-256",
                key.to_bytes().as_slice(),
                point.x().map(AsRef::<[u8]>::as_ref),
                point.y().map(AsRef::<[u8]>::as_ref),
            )
        }
        JwtAlgorithm::Es512 => {
            let key = p521::SecretKey::generate();
            let point = key.public_key().to_sec1_point(false);
            ec_pair(
                "P-521",
                key.to_bytes().as_slice(),
                point.x().map(AsRef::<[u8]>::as_ref),
                point.y().map(AsRef::<[u8]>::as_ref),
            )
        }
        JwtAlgorithm::Ps256 | JwtAlgorithm::Rs256 => {
            let bits = config.modulus_length.unwrap_or(2048);
            if bits < 2048 {
                return Err(AuthError::config(
                    "RSA modulus length must be at least 2048 bits",
                ));
            }
            let mut key =
                rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).map_err(crypto_error)?;
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
        drop(private.insert(name.to_owned(), value));
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
                .map_err(|_error| AuthError::internal("Invalid Ed25519 private key"))?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
                .sign(message)
                .to_bytes()
                .to_vec())
        }
        JwtAlgorithm::Es256 => {
            let secret = ec_field(private, "d", 32)?;
            let key = p256::ecdsa::SigningKey::from_slice(&secret).map_err(crypto_error)?;
            validate_ec_pair(private, key.verifying_key().to_sec1_point(false).as_bytes())?;
            let signature: p256::ecdsa::Signature = key
                .try_sign_with_rng(&mut rand::rng(), message)
                .map_err(crypto_error)?;
            Ok(signature.to_bytes().to_vec())
        }
        JwtAlgorithm::Es512 => {
            let secret = ec_field(private, "d", 66)?;
            let public = p521::SecretKey::from_slice(&secret)
                .map_err(crypto_error)?
                .public_key();
            validate_ec_pair(private, public.to_sec1_point(false).as_bytes())?;
            let key = p521::ecdsa::SigningKey::from_slice(&secret).map_err(crypto_error)?;
            let signature: p521::ecdsa::Signature = key
                .try_sign_with_rng(&mut rand::rng(), message)
                .map_err(crypto_error)?;
            Ok(signature.to_bytes().to_vec())
        }
        JwtAlgorithm::Rs256 => {
            let key = rsa::pkcs1v15::SigningKey::<RsaSha256>::new(rsa_private(private)?);
            Ok(key.sign(message).to_vec())
        }
        JwtAlgorithm::Ps256 => {
            let key = rsa::pss::SigningKey::<RsaSha256>::new(rsa_private(private)?);
            Ok(key
                .sign_with_rng(&mut rsa::rand_core::OsRng, message)
                .to_vec())
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
                .map_err(|_error| AuthError::internal("Invalid Ed25519 public key"))?;
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
            let key = rsa::pkcs1v15::VerifyingKey::<RsaSha256>::new(rsa_public(public)?);
            let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(crypto_error)?;
            key.verify(message, &signature).is_ok()
        }
        JwtAlgorithm::Ps256 => {
            let key = rsa::pss::VerifyingKey::<RsaSha256>::new(rsa_public(public)?);
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
    if algorithm == JwtAlgorithm::EdDsa && field(key, "x")?.len() != 32 {
        return Err(AuthError::config("Invalid JWK coordinate length"));
    }
    Ok(())
}

fn ec_public(key: &Value) -> AuthResult<Vec<u8>> {
    let width = match key.get("crv").and_then(Value::as_str) {
        Some("P-256") => 32,
        Some("P-521") => 66,
        _ => return Err(AuthError::config("Invalid EC curve")),
    };
    let mut bytes = vec![4];
    bytes.extend(ec_field(key, "x", width)?);
    bytes.extend(ec_field(key, "y", width)?);
    Ok(bytes)
}

fn ec_field(key: &Value, name: &str, width: usize) -> AuthResult<Vec<u8>> {
    let scalar = field(key, name)?
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect::<Vec<_>>();
    if scalar.len() > width {
        return Err(AuthError::config(format!(
            "EC {name} exceeds the curve field width"
        )));
    }
    // WebCrypto imports EC fields as unsigned integers. Omitted and extra
    // leading zero bytes preserve their value; restore the fixed field width.
    let mut padded = vec![0; width - scalar.len()];
    padded.extend(scalar);
    Ok(padded)
}

fn validate_ec_pair(private: &Value, derived_public: &[u8]) -> AuthResult<()> {
    if ec_public(private)? != derived_public {
        return Err(AuthError::config(
            "EC private key does not match its public coordinates",
        ));
    }
    Ok(())
}

fn field(key: &Value, field: &str) -> AuthResult<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

    let value = key
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::internal(format!("JWK {field} missing")))?;

    // WebCrypto JWK import allows trailing padding of any length and unused
    // trailing bits. It rejects all whitespace and the ordinary base64 alphabet.
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(value.trim_end_matches('='))
    .map_err(crypto_error)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn crypto_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::internal(format!("JWT key operation failed: {error}"))
}
