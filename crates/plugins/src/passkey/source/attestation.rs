//! Packed attestation policy. MPL-2.0; derived from webauthn-rs 0.5.4.
use super::{crypto::COSEKey, data::AttestationObject, policy::verify_certificate_signature};
use serde_cbor_2::Value as Cbor;
use webauthn_rs_core::{
    attestation::{FidoGenCeAaguid, assert_packed_attest_req, validate_extension},
    error::WebauthnError,
    proto::*,
};

pub(super) fn packed(
    acd: &AttestedCredentialData,
    object: &AttestationObject<Registration>,
    hash: &[u8],
) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
    let Cbor::Map(statement) = &object.att_stmt else {
        return Err(WebauthnError::AttestationStatementMapInvalid);
    };
    let Some(Cbor::Integer(algorithm)) = statement.get(&Cbor::Text("alg".into())) else {
        return Err(WebauthnError::AttestationStatementAlgInvalid);
    };
    let algorithm =
        COSEAlgorithm::try_from(*algorithm).map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)?;
    let Some(Cbor::Bytes(signature)) = statement.get(&Cbor::Text("sig".into())) else {
        return Err(WebauthnError::AttestationStatementSigMissing);
    };
    let mut signed = object.auth_data_bytes.clone();
    signed.extend_from_slice(hash);
    if let Some(chain) = statement.get(&Cbor::Text("x5c".into())) {
        let chain = certificates(chain)?;
        let leaf = chain
            .first()
            .ok_or(WebauthnError::AttestationStatementX5CInvalid)?;
        if !verify_certificate_signature(leaf, signature, &signed, Some(algorithm))? {
            return Err(WebauthnError::AttestationStatementSigInvalid);
        }
        assert_packed_attest_req(leaf)?;
        drop(validate_extension::<FidoGenCeAaguid>(leaf, &acd.aaguid)?);
        Ok((
            ParsedAttestationData::Basic(chain),
            AttestationMetadata::Packed {
                aaguid: uuid::Uuid::from_bytes(acd.aaguid),
            },
        ))
    } else if statement.contains_key(&Cbor::Text("ecdaaKeyId".into())) {
        Err(WebauthnError::AttestationNotSupported)
    } else {
        let key = COSEKey::try_from(&acd.credential_pk)?;
        if algorithm != key.type_ {
            return Err(WebauthnError::AttestationStatementAlgMismatch);
        }
        if !key.verify_signature(signature, &signed)? {
            return Err(WebauthnError::AttestationStatementSigInvalid);
        }
        Ok((ParsedAttestationData::Self_, AttestationMetadata::None))
    }
}

pub(super) fn certificates(value: &Cbor) -> Result<Vec<openssl::x509::X509>, WebauthnError> {
    let Cbor::Array(chain) = value else {
        return Err(WebauthnError::AttestationStatementX5CInvalid);
    };
    chain
        .iter()
        .map(|value| {
            let Cbor::Bytes(bytes) = value else {
                return Err(WebauthnError::AttestationStatementX5CInvalid);
            };
            openssl::x509::X509::from_der(bytes).map_err(Into::into)
        })
        .collect()
}
