//! Published RFC 7523 client assertions for application-owned token endpoints.
use super::{OAuthClientAssertion, OAuthClientAssertionContext, OAuthClientAssertionGetter};
use base64::{
    Engine,
    alphabet::URL_SAFE,
    engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE_NO_PAD,
    },
};
use rsa::{
    pkcs8::DecodePrivateKey,
    signature::{RandomizedSigner, SignatureEncoding, Signer},
};
use serde_json::{Value, json};
use std::sync::Arc;

const ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
];

/// Key material stays private; Debug deliberately never renders it.
/// JWK takes precedence over PKCS#8 PEM. Algorithm defaults to JWK `alg`, then
/// RS256; explicit algorithm and JWK `alg` must agree. `kid` overrides JWK `kid`.
#[derive(Clone, Default)]
pub struct OAuthPrivateKeyJwtOptions {
    pub private_key_jwk: Option<Value>,
    pub private_key_pem: Option<String>,
    pub algorithm: Option<String>,
    pub kid: Option<String>,
    /// Seconds, default 120. Negative lifetimes produce expired assertions.
    pub expires_in: Option<f64>,
}
impl std::fmt::Debug for OAuthPrivateKeyJwtOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthPrivateKeyJwtOptions")
            .finish_non_exhaustive()
    }
}
impl OAuthPrivateKeyJwtOptions {
    /// Validate configuration eagerly; key import/signing occurs for each grant,
    /// matching the published getter's construction versus request boundaries.
    /// # Errors
    /// Rejects missing key material, unsupported algorithms, and algorithm conflicts.
    pub fn into_assertion(self) -> Result<OAuthClientAssertion, String> {
        let _algorithm = self.resolved_algorithm()?;
        Ok(OAuthClientAssertion(Arc::new(self)))
    }
    fn resolved_algorithm(&self) -> Result<&str, String> {
        if self.private_key_jwk.as_ref().is_none_or(Value::is_null)
            && self.private_key_pem.as_deref().is_none_or(str::is_empty)
        {
            return Err("private_key_jwt requires either privateKeyJwk or privateKeyPem".into());
        }
        let embedded = self
            .private_key_jwk
            .as_ref()
            .and_then(|k| k.get("alg"))
            .and_then(Value::as_str);
        for algorithm in [
            self.algorithm.as_deref().filter(|s| !s.is_empty()),
            embedded,
        ]
        .into_iter()
        .flatten()
        {
            if !ALGORITHMS.contains(&algorithm) {
                return Err("Unsupported private_key_jwt signing algorithm".into());
            }
        }
        if let (Some(explicit), Some(embedded)) = (
            self.algorithm.as_deref().filter(|s| !s.is_empty()),
            embedded,
        ) && explicit != embedded
        {
            return Err("JWK alg does not match configured algorithm".into());
        }
        Ok(self.algorithm.as_deref().or(embedded).unwrap_or("RS256"))
    }
    fn sign(&self, algorithm: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        let jwk = self.private_key_jwk.as_ref().filter(|v| !v.is_null());
        let pem = self.private_key_pem.as_deref().unwrap_or_default();
        if let Some(jwk) = jwk {
            if jwk.get("ext").is_some_and(|value| !value.is_boolean()) {
                return Err("JWK ext must be a boolean".into());
            }
            if let Some(ops) = jwk.get("key_ops")
                && !ops.as_array().is_some_and(|ops| {
                    ops.iter().any(|op| op.as_str() == Some("sign"))
                        && ops.iter().enumerate().all(|(index, op)| {
                            op.is_string() && ops.iter().take(index).all(|previous| previous != op)
                        })
                })
            {
                return Err("JWK does not permit signing".into());
            }
            let (kty, curve) = match algorithm {
                "EdDSA" => ("OKP", Some("Ed25519")),
                "ES256" => ("EC", Some("P-256")),
                "ES384" => ("EC", Some("P-384")),
                "ES512" => ("EC", Some("P-521")),
                _ => ("RSA", None),
            };
            if jwk.get("kty").and_then(Value::as_str) != Some(kty)
                || curve.is_some_and(|c| jwk.get("crv").and_then(Value::as_str) != Some(c))
            {
                return Err("JWK does not match signing algorithm".into());
            }
        }
        if algorithm.starts_with("RS") || algorithm.starts_with("PS") {
            let key = if let Some(jwk) = jwk {
                // WebCrypto imports the complete two-prime private JWK.
                for name in ["dp", "dq", "qi"] {
                    let _component = field(jwk, name)?;
                }
                rsa::RsaPrivateKey::from_components(
                    rsa::BigUint::from_bytes_be(&field(jwk, "n")?),
                    rsa::BigUint::from_bytes_be(&field(jwk, "e")?),
                    rsa::BigUint::from_bytes_be(&field(jwk, "d")?),
                    vec![
                        rsa::BigUint::from_bytes_be(&field(jwk, "p")?),
                        rsa::BigUint::from_bytes_be(&field(jwk, "q")?),
                    ],
                )
                .map_err(key_error)?
            } else {
                rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(key_error)?
            };
            use rsa::traits::PublicKeyParts;
            if key.n().bits() < 2048 {
                return Err("RSA modulus length must be at least 2048 bits".into());
            }
            macro_rules! rsa_sign {
                ($digest:ty) => {
                    if algorithm.starts_with("RS") {
                        rsa::pkcs1v15::SigningKey::<$digest>::new(key)
                            .sign(message)
                            .to_vec()
                    } else {
                        rsa::pss::SigningKey::<$digest>::new(key)
                            .sign_with_rng(&mut rsa::rand_core::OsRng, message)
                            .to_vec()
                    }
                };
            }
            return Ok(match algorithm {
                "RS256" | "PS256" => rsa_sign!(rsa::sha2::Sha256),
                "RS384" | "PS384" => rsa_sign!(rsa::sha2::Sha384),
                _ => rsa_sign!(rsa::sha2::Sha512),
            });
        }
        macro_rules! ec_sign {
            ($curve:ident) => {{
                use $curve::ecdsa::signature::RandomizedSigner as _;
                use $curve::elliptic_curve::pkcs8::DecodePrivateKey as _;
                use $curve::elliptic_curve::sec1::ToSec1Point as _;

                let key = if let Some(jwk) = jwk {
                    $curve::SecretKey::from_slice(&field(jwk, "d")?).map_err(key_error)?
                } else {
                    $curve::SecretKey::from_pkcs8_pem(pem).map_err(key_error)?
                };
                if let Some(jwk) = jwk {
                    let public = key.public_key().to_sec1_point(false);
                    if public.x().map(|x| x.as_slice()) != Some(field(jwk, "x")?.as_slice())
                        || public.y().map(|y| y.as_slice()) != Some(field(jwk, "y")?.as_slice())
                    {
                        return Err("EC private/public key mismatch".into());
                    }
                }
                let signer = $curve::ecdsa::SigningKey::from_slice(key.to_bytes().as_slice())
                    .map_err(key_error)?;
                let signature: $curve::ecdsa::Signature = signer
                    .try_sign_with_rng(&mut rand::rng(), message)
                    .map_err(key_error)?;
                signature.to_bytes().to_vec()
            }};
        }
        Ok(match algorithm {
            "ES256" => ec_sign!(p256),
            "ES384" => ec_sign!(p384),
            "ES512" => ec_sign!(p521),
            "EdDSA" => {
                use ed25519_dalek::Signer;
                let key = if let Some(jwk) = jwk {
                    let seed: [u8; 32] = field(jwk, "d")?
                        .try_into()
                        .map_err(|_| "Invalid Ed25519 seed")?;
                    ed25519_dalek::SigningKey::from_bytes(&seed)
                } else {
                    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
                    ed25519_dalek::SigningKey::from_pkcs8_pem(pem).map_err(key_error)?
                };
                key.sign(message).to_bytes().to_vec()
            }
            _ => return Err("Unsupported private_key_jwt signing algorithm".into()),
        })
    }
}
#[async_trait::async_trait]
impl OAuthClientAssertionGetter for OAuthPrivateKeyJwtOptions {
    async fn get_client_assertion(
        &self,
        context: OAuthClientAssertionContext,
    ) -> Result<String, String> {
        let algorithm = self.resolved_algorithm()?;
        let mut header = json!({"alg":algorithm,"typ":"JWT"});
        let kid = self.kid.as_deref().map(str::to_owned).or_else(|| {
            self.private_key_jwk
                .as_ref()
                .and_then(|k| k.get("kid"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        if let Some(kid) = kid.filter(|k| !k.is_empty())
            && let Some(object) = header.as_object_mut()
        {
            drop(object.insert("kid".into(), Value::String(kid)));
        }
        let now = chrono::Utc::now().timestamp();
        let exp = now as f64 + self.expires_in.unwrap_or(120.0);
        if !exp.is_finite() {
            return Err("Invalid client assertion expiration time".into());
        }
        let claims = json!({"iss":context.client_id,"sub":context.client_id,"aud":context.token_endpoint,"iat":now,"exp":exp,"jti":uuid::Uuid::new_v4().to_string()});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(key_error)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(key_error)?)
        );
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(self.sign(algorithm, message.as_bytes())?)
        ))
    }
}
fn field(key: &Value, name: &str) -> Result<Vec<u8>, String> {
    GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(
        key.get(name)
            .and_then(Value::as_str)
            .ok_or("Missing JWK field")?,
    )
    .map_err(key_error)
}
fn key_error(_: impl std::fmt::Display) -> String {
    "Client assertion key operation failed".into()
}
