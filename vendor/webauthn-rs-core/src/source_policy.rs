//! Opt-in Better Auth 1.7.6 / SimpleWebAuthn 13.3.3 ceremony policy.
//! This extension is MPL-2.0, like the verifier it extends.
use crate::{crypto::compute_sha256, error::WebauthnError, internals::AttestationObject, proto::*};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use openssl::{asn1::Asn1Time, hash::MessageDigest, nid::Nid, pkey::Id, sign::Verifier, stack::Stack, x509::{store::X509StoreBuilder, X509, X509StoreContext}};
use serde_cbor_2::Value as Cbor;
use serde_json::Value;
use std::{collections::BTreeMap, time::{SystemTime, UNIX_EPOCH}};

/// Per-format trust anchors, equivalent to SimpleWebAuthn's SettingsService.
#[derive(Clone, Debug)]
pub struct SourcePolicy {
    /// PEM certificates. An empty configured list skips chain validation for
    /// that format, exactly as the pinned verifier does.
    pub roots: BTreeMap<String, Vec<String>>,
}

impl Default for SourcePolicy {
    fn default() -> Self {
        Self { roots: [
            ("android-key", include_str!("source_roots/android-key.pem")),
            ("android-safetynet", include_str!("source_roots/android-safetynet.pem")),
            ("apple", include_str!("source_roots/apple.pem")),
        ].into_iter().map(|(format, pem)| (format.to_owned(), vec![pem.to_owned()])).collect() }
    }
}

fn malformed() -> WebauthnError { WebauthnError::AttestationCertificateRequirementsNotMet }

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub(crate) fn client_data(bytes: &[u8], unsupported: &str) -> Result<CollectedClientData, WebauthnError> {
    let mut parsed: Value = serde_json::from_slice(bytes).map_err(WebauthnError::ParseJSONFailure)?;
    let object = parsed.as_object_mut().ok_or_else(malformed)?;
    if let Some(binding) = object.get("tokenBinding").filter(|value| truthy(value)) {
        let status = binding.get("status").and_then(Value::as_str);
        if !binding.is_object() || !status.is_some_and(|status| status == "present" || status == "supported" || status == unsupported) {
            return Err(malformed());
        }
    }
    // This affects only parsed policy. The caller keeps the original byte
    // buffer, and every attestation/assertion signature covers its original hash.
    object.remove("crossOrigin");
    object.remove("tokenBinding");
    serde_json::from_value(parsed).map_err(WebauthnError::ParseJSONFailure)
}

fn valid_now(cert: &X509) -> Result<bool, WebauthnError> {
    let now = Asn1Time::days_from_now(0)?;
    Ok(cert.not_before().compare(&now)? != std::cmp::Ordering::Greater && cert.not_after().compare(&now)? != std::cmp::Ordering::Less)
}

impl SourcePolicy {
    pub(crate) fn check_leaf(&self, object: &AttestationObject<Registration>) -> Result<(), WebauthnError> {
        if object.fmt == "packed" || object.fmt == "tpm" {
            if let Cbor::Map(statement) = &object.att_stmt {
                if let Some(Cbor::Array(chain)) = statement.get(&Cbor::Text("x5c".into())) {
                    let Some(Cbor::Bytes(der)) = chain.first() else { return Err(malformed()); };
                    let leaf = X509::from_der(der)?;
                    if !valid_now(&leaf)? { return Err(malformed()); }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn verify_path(&self, format: &str, attestation: &ParsedAttestationData) -> Result<(), WebauthnError> {
        let chain = match attestation {
            ParsedAttestationData::Basic(chain) | ParsedAttestationData::AttCa(chain) | ParsedAttestationData::AnonCa(chain) => chain,
            _ => return Ok(()),
        };
        if format == "android-key" {
            let root = chain.last().ok_or_else(malformed)?;
            let root_pem = String::from_utf8(root.to_pem()?).map_err(|_| malformed())?;
            if self.roots.get(format).is_some_and(|roots| !roots.is_empty() && !roots.iter().any(|pem| pem.contains(root_pem.trim()))) {
                return Err(WebauthnError::AttestationNotVerifiable);
            }
            return Self::verify_chain(&[root_pem], &chain[..chain.len() - 1]);
        }
        let Some(pems) = self.roots.get(format).filter(|roots| !roots.is_empty()) else { return Ok(()); };
        Self::verify_chain(pems, chain)
    }

    fn verify_chain(pems: &[String], chain: &[X509]) -> Result<(), WebauthnError> {
        let (leaf, intermediates) = chain.split_first().ok_or_else(malformed)?;
        for certificate in chain { if !valid_now(certificate)? { return Err(malformed()); } }
        let mut anchors = Vec::new();
        for pem in pems { anchors.extend(X509::stack_from_pem(pem.as_bytes())?); }
        for anchor in anchors {
            if !valid_now(&anchor)? { continue; }
            let anchor_der = anchor.to_der()?;
            let mut supplied = std::collections::BTreeSet::new();
            for certificate in chain {
                let der = certificate.to_der()?;
                if der == anchor_der || !supplied.insert(der) { return Err(malformed()); }
            }
            let mut store = X509StoreBuilder::new()?;
            store.add_cert(anchor)?;
            let store = store.build();
            let mut untrusted = Stack::new()?;
            for certificate in intermediates { untrusted.push(certificate.clone())?; }
            let mut context = X509StoreContext::new()?;
            let verified = context.init(&store, leaf, &untrusted, |context| {
                if !context.verify_cert()? { return Ok(false); }
                Ok(context.chain().is_some_and(|verified| verified.len() == chain.len() + 1))
            })?;
            if verified { return Ok(()); }
        }
        Err(WebauthnError::AttestationNotVerifiable)
    }

    pub(crate) fn verify_android_key(&self, acd: &AttestedCredentialData, object: &AttestationObject<Registration>, client_hash: &[u8]) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
        let Cbor::Map(statement) = &object.att_stmt else { return Err(malformed()); };
        let Some(Cbor::Array(entries)) = statement.get(&Cbor::Text("x5c".into())) else { return Err(malformed()); };
        let chain: Result<Vec<_>, WebauthnError> = entries.iter().map(|value| {
            let Cbor::Bytes(bytes) = value else { return Err(malformed()); };
            X509::from_der(bytes).map_err(Into::into)
        }).collect();
        let chain = chain?;
        let leaf = chain.first().ok_or_else(malformed)?;
        let der = leaf.to_der()?;
        let (_, certificate) = x509_parser::parse_x509_certificate(&der).map_err(|_| malformed())?;
        let extension = certificate.extensions().iter().find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.11129.2.1.17").ok_or_else(malformed)?;
        let (_, description) = der_parser::der::parse_der_sequence(extension.value).map_err(|_| malformed())?;
        let fields = description.as_sequence().map_err(|_| malformed())?;
        if fields.get(4).ok_or_else(malformed)?.as_slice().map_err(|_| malformed())? != client_hash { return Err(malformed()); }
        for index in [6, 7] {
            let authorization = fields.get(index).ok_or_else(malformed)?.as_sequence().map_err(|_| malformed())?;
            if authorization.iter().any(|entry| entry.tag().0 == 600) { return Err(malformed()); }
        }
        let key = COSEKey::try_from(&acd.credential_pk)?;
        if key != COSEKey::try_from((key.type_, leaf))? { return Err(WebauthnError::AttestationCredentialSubjectKeyMismatch); }
        let Some(Cbor::Integer(algorithm)) = statement.get(&Cbor::Text("alg".into())) else { return Err(malformed()); };
        let algorithm = COSEAlgorithm::try_from(*algorithm).map_err(|_| malformed())?;
        let Some(Cbor::Bytes(signature)) = statement.get(&Cbor::Text("sig".into())) else { return Err(malformed()); };
        let attestation = ParsedAttestationData::Basic(chain.clone());
        self.verify_path("android-key", &attestation)?;
        let mut signed = object.auth_data_bytes.clone(); signed.extend_from_slice(client_hash);
        if !crate::crypto::verify_signature(algorithm, leaf, signature, &signed)? { return Err(WebauthnError::AttestationStatementSigInvalid); }
        Ok((attestation, AttestationMetadata::None))
    }

    pub(crate) fn verify_safetynet(&self, object: &AttestationObject<Registration>, client_hash: &[u8]) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
        let Cbor::Map(statement) = &object.att_stmt else { return Err(malformed()); };
        if !matches!(statement.get(&Cbor::Text("ver".into())), Some(Cbor::Text(version)) if !version.is_empty()) { return Err(malformed()); }
        let Some(Cbor::Bytes(response)) = statement.get(&Cbor::Text("response".into())) else { return Err(malformed()); };
        let jwt = std::str::from_utf8(response).map_err(|_| malformed())?;
        let parts: Vec<_> = jwt.split('.').collect();
        let [header, payload, signature] = parts.as_slice() else { return Err(malformed()); };
        let decode = |value: &str| URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).map_err(|_| malformed());
        let header_value: Value = serde_json::from_slice(&decode(header)?).map_err(WebauthnError::ParseJSONFailure)?;
        let payload_value: Value = serde_json::from_slice(&decode(payload)?).map_err(WebauthnError::ParseJSONFailure)?;
        let timestamp = payload_value.get("timestampMs").and_then(Value::as_f64).ok_or_else(malformed)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| malformed())?.as_secs_f64() * 1000.0;
        if timestamp > now || timestamp + 60_000.0 < now { return Err(malformed()); }
        let mut nonce_input = object.auth_data_bytes.clone();
        nonce_input.extend_from_slice(client_hash);
        let nonce = STANDARD.encode(compute_sha256(&nonce_input));
        if payload_value.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) || !payload_value.get("ctsProfileMatch").is_some_and(truthy) { return Err(malformed()); }
        let entries = header_value.get("x5c").and_then(Value::as_array).ok_or_else(malformed)?;
        let chain: Result<Vec<_>, WebauthnError> = entries.iter().map(|entry| {
            let der = STANDARD.decode(entry.as_str().ok_or_else(malformed)?).map_err(|_| malformed())?;
            X509::from_der(&der).map_err(Into::into)
        }).collect();
        let chain = chain?;
        let leaf = chain.first().ok_or_else(malformed)?;
        let name = leaf.subject_name().entries_by_nid(Nid::COMMONNAME).next().ok_or_else(malformed)?.data().as_slice();
        if name != b"attest.android.com" { return Err(malformed()); }
        let public_key = leaf.public_key()?;
        let hash = match statement.get(&Cbor::Text("alg".into())) {
            Some(Cbor::Integer(-35 | -258 | -38)) => MessageDigest::sha384(),
            Some(Cbor::Integer(-36 | -259 | -39)) => MessageDigest::sha512(),
            None | Some(Cbor::Integer(-7 | -257 | -37)) => MessageDigest::sha256(),
            _ => return Err(malformed()),
        };
        let attestation = ParsedAttestationData::Basic(chain.clone());
        self.verify_path("android-safetynet", &attestation)?;
        let mut verifier = if public_key.id() == Id::ED25519 { Verifier::new_without_digest(&public_key)? } else { Verifier::new(hash, &public_key)? };
        // Source selects verification from the certificate public key, not the
        // untrusted JWS alg header. The exact encoded header.payload is signed.
        let signed = format!("{header}.{payload}");
        if !verifier.verify_oneshot(&decode(signature)?, signed.as_bytes())? { return Err(WebauthnError::AttestationStatementSigInvalid); }
        Ok((attestation, AttestationMetadata::None))
    }
}
