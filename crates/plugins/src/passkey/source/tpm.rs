//! TPM compatibility policy over the registry's signed-structure parsers.
//! MPL-2.0; derived from webauthn-rs 0.5.4. See LICENSE.md.
use super::{
    attestation::certificates,
    crypto::{COSEKey, COSEKeyType, only_hash_from_type},
    data::AttestationObject,
    policy::verify_certificate_signature,
};
use serde_cbor_2::Value as Cbor;
use webauthn_rs_core::{
    attestation::{FidoGenCeAaguid, validate_extension},
    error::WebauthnError,
    internals::{Tpm2bName, TpmSt, TpmsAttest, TpmtSignature, TpmuAttest},
    proto::*,
};

fn malformed() -> WebauthnError {
    WebauthnError::ParseNOMFailure
}

// Only TPMT_PUBLIC is private upstream. Keep its bounded wire parser here;
// the registry still parses and validates the signed TPMS_ATTEST structure.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], WebauthnError> {
        let (value, tail) = self.0.split_at_checked(size).ok_or_else(malformed)?;
        self.0 = tail;
        Ok(value)
    }
    fn word(&mut self) -> Result<u16, WebauthnError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| malformed())?,
        ))
    }
    fn vector(&mut self) -> Result<&'a [u8], WebauthnError> {
        let size = usize::from(self.word()?);
        self.take(size)
    }
    fn null(&mut self) -> Result<(), WebauthnError> {
        if self.word()? == 0x10 {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}

fn check_public(bytes: &[u8], key: &COSEKey) -> Result<(), WebauthnError> {
    let mut input = Reader(bytes);
    let kind = input.word()?;
    // Preserve the pinned parser's admitted nameAlg identifiers even though
    // Source derives the name hash selector from the signed certInfo name.
    if !matches!(
        input.word()?,
        0 | 1 | 4 | 5 | 6 | 11 | 12 | 13 | 16 | 20 | 22 | 24 | 26 | 35
    ) {
        return Err(malformed());
    }
    let _ = input.take(4)?; // objectAttributes
    let _ = input.vector()?; // authPolicy
    input.null()?; // symmetric
    input.null()?; // scheme
    let matched = match kind {
        1 => {
            let _ = input.take(6)?; // keyBits and exponent, ignored by pinned policy
            let modulus = input.vector()?;
            matches!(&key.key, COSEKeyType::RSA(key) if key.n.as_slice() == modulus)
        }
        0x23 => {
            let curve = input.word()?;
            if !matches!(curve, 0..=5 | 16 | 17 | 32) {
                return Err(malformed());
            }
            input.null()?; // kdf
            let x = input.vector()?;
            let y = input.vector()?;
            matches!(&key.key, COSEKeyType::EC_EC2(key) if matches!((&key.curve,curve), (ECDSACurve::SECP256R1,3) | (ECDSACurve::SECP384R1,4) | (ECDSACurve::SECP521R1,5)) && key.x.as_slice() == x && key.y.as_slice() == y)
        }
        _ => return Err(malformed()),
    };
    if matched {
        Ok(())
    } else {
        Err(WebauthnError::AttestationTpmPubAreaMismatch)
    }
}

pub(super) fn verify(
    acd: &AttestedCredentialData,
    object: &AttestationObject<Registration>,
    hash: &[u8],
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    let Cbor::Map(statement) = &object.att_stmt else {
        return Err(WebauthnError::AttestationStatementMapInvalid);
    };
    if statement.get(&Cbor::Text("ver".into())) != Some(&Cbor::Text("2.0".into())) {
        return Err(WebauthnError::AttestationStatementVerUnsupported);
    }
    let Some(Cbor::Integer(algorithm)) = statement.get(&Cbor::Text("alg".into())) else {
        return Err(WebauthnError::AttestationStatementAlgInvalid);
    };
    let algorithm =
        COSEAlgorithm::try_from(*algorithm).map_err(|()| WebauthnError::COSEKeyInvalidAlgorithm)?;
    let bytes = |key: &str| match statement.get(&Cbor::Text(key.into())) {
        Some(Cbor::Bytes(bytes)) => Ok(bytes.as_slice()),
        _ => Err(malformed()),
    };
    let info_bytes = bytes("certInfo")?;
    let info = TpmsAttest::try_from(info_bytes)?;
    let public = bytes("pubArea")?;
    let signature = TpmtSignature::try_from(bytes("sig")?)?;
    let chain = certificates(
        statement
            .get(&Cbor::Text("x5c".into()))
            .ok_or(WebauthnError::AttestationStatementX5CMissing)?,
    )?;
    let leaf = chain
        .first()
        .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;
    let key = COSEKey::try_from(&acd.credential_pk)?;
    check_public(public, &key)?;
    let mut signed = object.auth_data_bytes.clone();
    signed.extend_from_slice(hash);
    if info.type_ != TpmSt::AttestCertify {
        return Err(WebauthnError::AttestationTpmStInvalid);
    }
    let extra = info
        .extra_data
        .ok_or(WebauthnError::AttestationTpmExtraDataInvalid)?;
    if only_hash_from_type(algorithm, &signed)? != extra {
        return Err(WebauthnError::AttestationTpmExtraDataMismatch);
    }
    let TpmuAttest::AttestCertify(Tpm2bName::Digest(name), _) = info.typeattested else {
        return Err(WebauthnError::AttestationTpmPubAreaHashInvalid);
    };
    let (name_algorithm, identifier) = match name.get(..2) {
        Some([0, 4]) => (COSEAlgorithm::INSECURE_RS1, 4),
        Some([0, 11]) => (COSEAlgorithm::ES256, 11),
        Some([0, 12]) => (COSEAlgorithm::ES384, 12),
        Some([0, 13]) => (COSEAlgorithm::ES512, 13),
        _ => return Err(WebauthnError::AttestationTpmPubAreaHashUnknown),
    };
    let mut expected_name = vec![0, identifier];
    expected_name.extend_from_slice(&only_hash_from_type(name_algorithm, public)?);
    if name != expected_name {
        return Err(WebauthnError::AttestationTpmPubAreaHashInvalid);
    }
    let TpmtSignature::RawSignature(signature) = signature;
    if !verify_certificate_signature(leaf, &signature, info_bytes, Some(algorithm))? {
        return Err(WebauthnError::AttestationStatementSigInvalid);
    }
    check_certificate(leaf)?;
    drop(validate_extension::<FidoGenCeAaguid>(leaf, &acd.aaguid)?);
    Ok((
        ParsedAttestationData::AttCa(chain),
        AttestationMetadata::Tpm {
            aaguid: uuid::Uuid::from_bytes(acd.aaguid),
            firmware_version: info.firmware_version,
        },
    ))
}

fn check_certificate(certificate: &openssl::x509::X509) -> Result<(), WebauthnError> {
    use x509_parser::{prelude::GeneralName, x509::X509Version};
    let rejected = || WebauthnError::AttestationCertificateRequirementsNotMet;
    let der = certificate.to_der()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|_| WebauthnError::AttestationStatementX5CInvalid)?;
    if cert.version != X509Version::V3 || certificate.subject_name().entries().count() != 0 {
        return Err(rejected());
    }
    let san = cert
        .subject_alternative_name()
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if !san.critical
        || !san.value.general_names.iter().any(|name| {
            let GeneralName::DirectoryName(name) = name else {
                return false;
            };
            let mut manufacturer = None;
            let mut model = None;
            let mut version = None;
            for attribute in name.iter_attributes() {
                let output = match attribute.attr_type().to_id_string().as_str() {
                    "2.23.133.2.1" => &mut manufacturer,
                    "2.23.133.2.2" => &mut model,
                    "2.23.133.2.3" => &mut version,
                    _ => continue,
                };
                let Ok(value) = attribute.attr_value().as_str() else {
                    return false;
                };
                *output = Some(value);
            }
            let Some(((manufacturer, _), _)) = manufacturer.zip(model).zip(version) else {
                return false;
            };
            let Some(code) = manufacturer
                .strip_prefix("id:")
                .and_then(|value| value.get(..8))
            else {
                return false;
            };
            matches!(
                code,
                "414d4400"
                    | "41544D4C"
                    | "4252434D"
                    | "4353434F"
                    | "464C5953"
                    | "524F4343"
                    | "474F4F47"
                    | "48504500"
                    | "48495349"
                    | "49424D00"
                    | "49465800"
                    | "494E5443"
                    | "4C454E00"
                    | "4D534654"
                    | "4E534D20"
                    | "4E545A00"
                    | "4E544300"
                    | "51434F4D"
                    | "534D534E"
                    | "534E5300"
                    | "534D5343"
                    | "53544D20"
                    | "54584E00"
                    | "57454300"
            )
        })
    {
        return Err(rejected());
    }
    let eku = cert
        .extended_key_usage()
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if !eku
        .value
        .other
        .iter()
        .any(|oid| oid.to_id_string() == "2.23.133.8.3")
    {
        return Err(rejected());
    }
    let constraints = cert
        .basic_constraints()
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if constraints.value.ca {
        return Err(rejected());
    }
    Ok(())
}
