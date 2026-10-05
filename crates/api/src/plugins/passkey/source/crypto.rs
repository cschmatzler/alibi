//! Source COSE extensions over registry types and OpenSSL primitives.
//! Derived from webauthn-rs 0.5.4; MPL-2.0, see LICENSE.md.
use base64urlsafedata::HumanBinaryData;
use openssl::{bn::BigNum, hash, pkey, rsa, sign, x509};
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value as Cbor;
use webauthn_rs_core::{error::WebauthnError, proto::*};

// Keep the historical persisted shape, including arbitrary RSA exponent bytes.
// Registry COSERSAKey uses [u8; 3] and cannot read all credentials we have issued.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::plugins::passkey) struct COSEKey {
    pub type_: COSEAlgorithm,
    pub key: COSEKeyType,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[expect(
    non_camel_case_types,
    clippy::upper_case_acronyms,
    reason = "persisted registry-compatible enum names"
)]
pub(in crate::plugins::passkey) enum COSEKeyType {
    EC_OKP(COSEOKPKey),
    EC_EC2(COSEEC2Key),
    RSA(COSERSAKey),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::plugins::passkey) struct COSERSAKey {
    pub n: HumanBinaryData,
    pub e: Vec<u8>,
}

impl From<webauthn_rs_core::proto::COSEKey> for COSEKey {
    fn from(key: webauthn_rs_core::proto::COSEKey) -> Self {
        use webauthn_rs_core::proto::COSEKeyType as Registry;
        Self {
            type_: key.type_,
            key: match key.key {
                Registry::EC_OKP(key) => COSEKeyType::EC_OKP(key),
                Registry::EC_EC2(key) => COSEKeyType::EC_EC2(key),
                Registry::RSA(key) => COSEKeyType::RSA(COSERSAKey {
                    n: key.n,
                    e: key.e.to_vec(),
                }),
            },
        }
    }
}

impl TryFrom<&Cbor> for COSEKey {
    type Error = WebauthnError;
    fn try_from(value: &Cbor) -> Result<Self, Self::Error> {
        let Cbor::Map(map) = value else {
            return Err(WebauthnError::COSEKeyInvalidCBORValue);
        };
        if map.get(&Cbor::Integer(1)) != Some(&Cbor::Integer(3)) {
            return webauthn_rs_core::proto::COSEKey::try_from(value).map(Into::into);
        }
        let Some(Cbor::Integer(algorithm)) = map.get(&Cbor::Integer(3)) else {
            return Err(WebauthnError::COSEKeyInvalidCBORValue);
        };
        let type_ = COSEAlgorithm::try_from(*algorithm)
            .map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)?;
        if !matches!(
            type_,
            COSEAlgorithm::RS256
                | COSEAlgorithm::RS384
                | COSEAlgorithm::RS512
                | COSEAlgorithm::PS256
                | COSEAlgorithm::PS384
                | COSEAlgorithm::PS512
                | COSEAlgorithm::INSECURE_RS1
        ) {
            return Err(WebauthnError::COSEKeyInvalidType);
        }
        let (Some(Cbor::Bytes(n)), Some(Cbor::Bytes(e))) =
            (map.get(&Cbor::Integer(-1)), map.get(&Cbor::Integer(-2)))
        else {
            return Err(WebauthnError::COSEKeyInvalidCBORValue);
        };
        if n.is_empty() || e.is_empty() {
            return Err(WebauthnError::COSEKeyRSANEInvalid);
        }
        let key = Self {
            type_,
            key: COSEKeyType::RSA(COSERSAKey {
                n: n.clone().into(),
                e: e.clone(),
            }),
        };
        drop(key.get_openssl_pkey()?);
        Ok(key)
    }
}

impl TryFrom<(COSEAlgorithm, &x509::X509)> for COSEKey {
    type Error = WebauthnError;
    fn try_from((type_, certificate): (COSEAlgorithm, &x509::X509)) -> Result<Self, Self::Error> {
        if !matches!(
            type_,
            COSEAlgorithm::ES256 | COSEAlgorithm::ES384 | COSEAlgorithm::ES512
        ) {
            return Err(WebauthnError::COSEKeyInvalidType);
        }
        let key = certificate.public_key()?.ec_key()?;
        key.check_key()?;
        let curve = key
            .group()
            .curve_name()
            .ok_or(WebauthnError::OpenSSLErrorNoCurveName)
            .and_then(ECDSACurve::try_from)?;
        let mut context = openssl::bn::BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        key.public_key()
            .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut context)?;
        let size = match curve {
            ECDSACurve::SECP256R1 => 32,
            ECDSACurve::SECP384R1 => 48,
            ECDSACurve::SECP521R1 => 66,
        };
        if x.num_bytes() > size || y.num_bytes() > size {
            return Err(WebauthnError::COSEKeyECDSAXYInvalid);
        }
        Ok(Self {
            type_,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve,
                x: x.to_vec_padded(size)?.into(),
                y: y.to_vec_padded(size)?.into(),
            }),
        })
    }
}

impl COSEKey {
    pub(super) fn get_openssl_pkey(&self) -> Result<pkey::PKey<pkey::Public>, WebauthnError> {
        use webauthn_rs_core::proto::COSEKeyType as Registry;
        let key = match &self.key {
            COSEKeyType::EC_OKP(key) => Registry::EC_OKP(key.clone()),
            COSEKeyType::EC_EC2(key) => Registry::EC_EC2(key.clone()),
            COSEKeyType::RSA(key) => {
                return Ok(pkey::PKey::from_rsa(rsa::Rsa::from_public_components(
                    BigNum::from_slice(key.n.as_ref())?,
                    BigNum::from_slice(&key.e)?,
                )?)?);
            }
        };
        webauthn_rs_core::proto::COSEKey {
            type_: self.type_,
            key,
        }
        .get_openssl_pkey()
    }
    pub(in crate::plugins::passkey) fn verify_signature(
        &self,
        signature: &[u8],
        bytes: &[u8],
    ) -> Result<bool, WebauthnError> {
        let key = self.get_openssl_pkey()?;
        let mut verifier = if self.type_ == COSEAlgorithm::EDDSA {
            sign::Verifier::new_without_digest(&key)?
        } else {
            let digest = digest(self.type_)?;
            let mut verifier = sign::Verifier::new(digest, &key)?;
            if matches!(
                self.type_,
                COSEAlgorithm::PS256 | COSEAlgorithm::PS384 | COSEAlgorithm::PS512
            ) {
                verifier.set_rsa_padding(rsa::Padding::PKCS1_PSS)?;
                verifier.set_rsa_mgf1_md(digest)?;
                verifier.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH)?;
            }
            verifier
        };
        Ok(verifier.verify_oneshot(signature, bytes)?)
    }
}

fn digest(algorithm: COSEAlgorithm) -> Result<hash::MessageDigest, WebauthnError> {
    Ok(match algorithm {
        COSEAlgorithm::ES256 | COSEAlgorithm::RS256 | COSEAlgorithm::PS256 => {
            hash::MessageDigest::sha256()
        }
        COSEAlgorithm::ES384 | COSEAlgorithm::RS384 | COSEAlgorithm::PS384 => {
            hash::MessageDigest::sha384()
        }
        COSEAlgorithm::ES512 | COSEAlgorithm::RS512 | COSEAlgorithm::PS512 => {
            hash::MessageDigest::sha512()
        }
        COSEAlgorithm::INSECURE_RS1 => hash::MessageDigest::sha1(),
        _ => return Err(WebauthnError::COSEKeyInvalidType),
    })
}
pub(super) fn only_hash_from_type(
    algorithm: COSEAlgorithm,
    bytes: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    Ok(hash::hash(digest(algorithm)?, bytes)?.to_vec())
}
