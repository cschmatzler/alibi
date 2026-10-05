//! Opt-in Better Auth 1.7.6 / SimpleWebAuthn 13.3.3 ceremony policy.
//! This extension is MPL-2.0, like the verifier it extends.
use super::{crypto::COSEKey, data::AttestationObject};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::Id,
    sign::Verifier,
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder},
};
use serde_cbor_2::Value as Cbor;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use webauthn_rs_core::{crypto::compute_sha256, error::WebauthnError, proto::*};

/// Per-format trust anchors, equivalent to SimpleWebAuthn's SettingsService.
#[derive(Clone, Debug)]
pub(in crate::plugins::passkey) struct SourcePolicy {
    /// PEM certificates. An empty configured list skips chain validation for
    /// that format, exactly as the pinned verifier does.
    pub(in crate::plugins::passkey) roots: BTreeMap<String, Vec<String>>,
}

impl Default for SourcePolicy {
    fn default() -> Self {
        Self {
            // The pinned package supplies empty defaults; applications may add
            // per-format roots. An empty list deliberately skips path validation.
            roots: ["android-key", "android-safetynet", "apple"]
                .into_iter()
                .map(|format| (format.to_owned(), Vec::new()))
                .collect(),
        }
    }
}

fn malformed() -> WebauthnError {
    WebauthnError::AttestationCertificateRequirementsNotMet
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub(super) fn client_data(
    bytes: &[u8],
    unsupported: &str,
) -> Result<CollectedClientData, WebauthnError> {
    let mut parsed: Value =
        serde_json::from_slice(bytes).map_err(WebauthnError::ParseJSONFailure)?;
    let object = parsed.as_object_mut().ok_or_else(malformed)?;
    if let Some(binding) = object.get("tokenBinding").filter(|value| truthy(value)) {
        let status = binding.get("status").and_then(Value::as_str);
        if !binding.is_object()
            || !status.is_some_and(|status| {
                status == "present" || status == "supported" || status == unsupported
            })
        {
            return Err(malformed());
        }
    }
    // This affects only parsed policy. The caller keeps the original byte
    // buffer, and every attestation/assertion signature covers its original hash.
    drop(object.remove("crossOrigin"));
    drop(object.remove("tokenBinding"));
    serde_json::from_value(parsed).map_err(WebauthnError::ParseJSONFailure)
}

fn valid_now(cert: &X509) -> Result<bool, WebauthnError> {
    let now = Asn1Time::days_from_now(0)?;
    Ok(
        cert.not_before().compare(&now)? != std::cmp::Ordering::Greater
            && cert.not_after().compare(&now)? != std::cmp::Ordering::Less,
    )
}

impl SourcePolicy {
    /// Apply the pinned verifier's CRL policy before synchronous cryptographic
    /// verification. Network and malformed-CRL failures are non-revoked in Source.
    /// The caller supplies its production HTTP transport; no runtime is imposed.
    pub(in crate::plugins::passkey) async fn check_revocations<F, Fut>(
        &mut self,
        bytes: &[u8],
        fetch: F,
    ) -> Result<(), WebauthnError>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Option<Vec<u8>>>,
    {
        let object = AttestationObject::<Registration>::from_source(bytes)?;
        let Cbor::Map(statement) = &object.att_stmt else {
            return Err(malformed());
        };
        let mut chain = Vec::new();
        if object.fmt == "android-safetynet" {
            if let Some(Cbor::Bytes(response)) = statement.get(&Cbor::Text("response".into())) {
                let encoded = response
                    .split(|byte| *byte == b'.')
                    .next()
                    .ok_or_else(malformed)?;
                let header: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD.decode(encoded).map_err(|_| malformed())?,
                )
                .map_err(WebauthnError::ParseJSONFailure)?;
                if let Some(entries) = header.get("x5c").and_then(Value::as_array) {
                    for entry in entries {
                        chain.push(X509::from_der(
                            &STANDARD
                                .decode(entry.as_str().ok_or_else(malformed)?)
                                .map_err(|_| malformed())?,
                        )?);
                    }
                }
            }
        } else if let Some(Cbor::Array(entries)) = statement.get(&Cbor::Text("x5c".into())) {
            for entry in entries {
                let Cbor::Bytes(der) = entry else {
                    return Err(malformed());
                };
                chain.push(X509::from_der(der)?);
            }
        }
        let configured = self
            .roots
            .get(&object.fmt)
            .filter(|roots| !roots.is_empty());
        // Android Key always validates against the final x5c certificate.
        if configured.is_none() && object.fmt != "android-key" {
            return Ok(());
        }
        for certificate in &chain {
            if revoked(certificate, &fetch).await? {
                return Err(WebauthnError::AttestationNotVerifiable);
            }
        }
        if let Some(roots) = configured {
            let mut usable = Vec::new();
            for pem in roots {
                let certificate = X509::from_pem(pem.as_bytes())?;
                if !revoked(&certificate, &fetch).await? {
                    usable.push(pem.clone());
                }
            }
            if usable.is_empty() {
                return Err(WebauthnError::AttestationNotVerifiable);
            }
            drop(self.roots.insert(object.fmt, usable));
        }
        Ok(())
    }

    pub(super) fn check_leaf(
        &self,
        object: &AttestationObject<Registration>,
    ) -> Result<(), WebauthnError> {
        if let Cbor::Map(statement) = &object.att_stmt
            && let Some(Cbor::Array(chain)) = statement.get(&Cbor::Text("x5c".into()))
        {
            let Some(Cbor::Bytes(der)) = chain.first() else {
                return Err(malformed());
            };
            let leaf = X509::from_der(der)?;
            if matches!(object.fmt.as_str(), "packed" | "tpm") && !valid_now(&leaf)? {
                return Err(malformed());
            }
            if object.fmt == "apple" {
                check_ec_certificate(&leaf, true)?;
            } else {
                let _ = certificate_algorithm(&leaf)?;
                if object.fmt == "android-key" {
                    check_ec_certificate(&leaf, false)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn verify_path(
        &self,
        format: &str,
        attestation: &ParsedAttestationData,
    ) -> Result<(), WebauthnError> {
        let chain = match attestation {
            ParsedAttestationData::Basic(chain)
            | ParsedAttestationData::AttCa(chain)
            | ParsedAttestationData::AnonCa(chain) => chain,
            _ => return Ok(()),
        };
        if format == "android-key" {
            let (root, certificates) = chain.split_last().ok_or_else(malformed)?;
            let root_pem = String::from_utf8(root.to_pem()?).map_err(|_| malformed())?;
            if self
                .roots
                .get(format)
                .is_some_and(|roots| !roots.is_empty() && !roots.iter().any(|pem| pem == &root_pem))
            {
                return Err(WebauthnError::AttestationNotVerifiable);
            }
            return Self::verify_chain(&[root_pem], certificates);
        }
        let Some(pems) = self.roots.get(format).filter(|roots| !roots.is_empty()) else {
            return Ok(());
        };
        Self::verify_chain(pems, chain)
    }

    fn verify_chain(pems: &[String], chain: &[X509]) -> Result<(), WebauthnError> {
        let (leaf, intermediates) = chain.split_first().ok_or_else(malformed)?;
        for certificate in chain {
            if !valid_now(certificate)? {
                return Err(malformed());
            }
        }
        let mut anchors = Vec::new();
        for pem in pems {
            anchors.extend(X509::stack_from_pem(pem.as_bytes())?);
        }
        for anchor in anchors {
            if !valid_now(&anchor)? {
                continue;
            }
            let anchor_der = anchor.to_der()?;
            let mut supplied = std::collections::BTreeSet::new();
            for certificate in chain {
                let der = certificate.to_der()?;
                if der == anchor_der || !supplied.insert(der) {
                    return Err(malformed());
                }
            }
            let mut store = X509StoreBuilder::new()?;
            store.add_cert(anchor)?;
            let store = store.build();
            let mut untrusted = Stack::new()?;
            for certificate in intermediates {
                untrusted.push(certificate.clone())?;
            }
            let mut context = X509StoreContext::new()?;
            let verified = context.init(&store, leaf, &untrusted, |context| {
                if !context.verify_cert()? {
                    return Ok(false);
                }
                Ok(context
                    .chain()
                    .is_some_and(|verified| verified.len() == chain.len() + 1))
            })?;
            if verified {
                return Ok(());
            }
        }
        Err(WebauthnError::AttestationNotVerifiable)
    }

    pub(super) fn verify_u2f(
        &self,
        acd: &AttestedCredentialData,
        object: &AttestationObject<Registration>,
        client_hash: &[u8],
    ) -> Result<ParsedAttestationData, WebauthnError> {
        if acd.aaguid != [0; 16] {
            return Err(malformed());
        }
        let (chain, statement) = attestation_chain(object)?;
        let Some(Cbor::Bytes(signature)) = statement.get(&Cbor::Text("sig".into())) else {
            return Err(malformed());
        };
        let mut signed = vec![0];
        signed.extend_from_slice(&object.auth_data.rp_id_hash);
        signed.extend_from_slice(client_hash);
        signed.extend_from_slice(&acd.credential_id);
        signed.extend_from_slice(&source_pkcs(&acd.credential_pk)?);
        if !verify_certificate_signature(
            chain.first().ok_or_else(malformed)?,
            signature,
            &signed,
            Some(COSEAlgorithm::ES256),
        )? {
            return Err(WebauthnError::AttestationStatementSigInvalid);
        }
        Ok(ParsedAttestationData::Basic(chain))
    }

    pub(super) fn verify_apple(
        &self,
        acd: &AttestedCredentialData,
        object: &AttestationObject<Registration>,
        client_hash: &[u8],
    ) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
        let (chain, _) = attestation_chain(object)?;
        let leaf = chain.first().ok_or_else(malformed)?;
        let der = leaf.to_der()?;
        let (_, certificate) =
            x509_parser::parse_x509_certificate(&der).map_err(|_| malformed())?;
        let extension = certificate
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.2.840.113635.100.8.2")
            .ok_or_else(malformed)?;
        let mut nonce = object.auth_data_bytes.clone();
        nonce.extend_from_slice(client_hash);
        if extension.value.get(6..) != Some(compute_sha256(&nonce).as_slice()) {
            return Err(malformed());
        }
        if source_pkcs(&acd.credential_pk)?.as_slice()
            != certificate.public_key().subject_public_key.data.as_ref()
        {
            return Err(WebauthnError::AttestationCredentialSubjectKeyMismatch);
        }
        Ok((
            ParsedAttestationData::AnonCa(chain),
            AttestationMetadata::None,
        ))
    }

    pub(super) fn verify_android_key(
        &self,
        acd: &AttestedCredentialData,
        object: &AttestationObject<Registration>,
        client_hash: &[u8],
    ) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
        let Cbor::Map(statement) = &object.att_stmt else {
            return Err(malformed());
        };
        let Some(Cbor::Array(entries)) = statement.get(&Cbor::Text("x5c".into())) else {
            return Err(malformed());
        };
        let chain: Result<Vec<_>, WebauthnError> = entries
            .iter()
            .map(|value| {
                let Cbor::Bytes(bytes) = value else {
                    return Err(malformed());
                };
                X509::from_der(bytes).map_err(Into::into)
            })
            .collect();
        let chain = chain?;
        let leaf = chain.first().ok_or_else(malformed)?;
        let der = leaf.to_der()?;
        let (_, certificate) =
            x509_parser::parse_x509_certificate(&der).map_err(|_| malformed())?;
        let extension = certificate
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.11129.2.1.17")
            .ok_or_else(malformed)?;
        let (_, description) =
            der_parser::der::parse_der_sequence(extension.value).map_err(|_| malformed())?;
        let fields = description.as_sequence().map_err(|_| malformed())?;
        if fields
            .get(4)
            .ok_or_else(malformed)?
            .as_slice()
            .map_err(|_| malformed())?
            != client_hash
        {
            return Err(malformed());
        }
        for index in [6, 7] {
            let authorization = fields
                .get(index)
                .ok_or_else(malformed)?
                .as_sequence()
                .map_err(|_| malformed())?;
            if authorization.iter().any(|entry| entry.tag().0 == 600) {
                return Err(malformed());
            }
        }
        let key = COSEKey::try_from(&acd.credential_pk)?;
        if key != COSEKey::try_from((key.type_, leaf))? {
            return Err(WebauthnError::AttestationCredentialSubjectKeyMismatch);
        }
        let Some(Cbor::Integer(algorithm)) = statement.get(&Cbor::Text("alg".into())) else {
            return Err(malformed());
        };
        let algorithm = COSEAlgorithm::try_from(*algorithm).map_err(|_| malformed())?;
        let Some(Cbor::Bytes(signature)) = statement.get(&Cbor::Text("sig".into())) else {
            return Err(malformed());
        };
        let attestation = ParsedAttestationData::Basic(chain.clone());
        self.verify_path("android-key", &attestation)?;
        let mut signed = object.auth_data_bytes.clone();
        signed.extend_from_slice(client_hash);
        if !verify_certificate_signature(leaf, signature, &signed, Some(algorithm))? {
            return Err(WebauthnError::AttestationStatementSigInvalid);
        }
        Ok((attestation, AttestationMetadata::None))
    }

    pub(super) fn verify_safetynet(
        &self,
        object: &AttestationObject<Registration>,
        client_hash: &[u8],
    ) -> Result<(ParsedAttestationData, AttestationMetadata), WebauthnError> {
        let Cbor::Map(statement) = &object.att_stmt else {
            return Err(malformed());
        };
        let version = statement
            .get(&Cbor::Text("ver".into()))
            .ok_or_else(malformed)?;
        let version_present = match version {
            Cbor::Null => false,
            Cbor::Bool(value) => *value,
            Cbor::Integer(value) => *value != 0,
            Cbor::Float(value) => *value != 0.0 && !value.is_nan(),
            Cbor::Text(value) => !value.is_empty(),
            _ => true,
        };
        if !version_present {
            return Err(malformed());
        }
        let Some(Cbor::Bytes(response)) = statement.get(&Cbor::Text("response".into())) else {
            return Err(malformed());
        };
        let jwt = std::str::from_utf8(response).map_err(|_| malformed())?;
        let parts: Vec<_> = jwt.split('.').collect();
        let [header, payload, signature] = parts.as_slice() else {
            return Err(malformed());
        };
        let decode = |value: &str| {
            URL_SAFE_NO_PAD
                .decode(value.trim_end_matches('='))
                .map_err(|_| malformed())
        };
        let header_value: Value =
            serde_json::from_slice(&decode(header)?).map_err(WebauthnError::ParseJSONFailure)?;
        let payload_value: Value =
            serde_json::from_slice(&decode(payload)?).map_err(WebauthnError::ParseJSONFailure)?;
        let timestamp = payload_value.get("timestampMs");
        let numeric = js_number(timestamp);
        let delayed = match timestamp {
            Some(value @ (Value::String(_) | Value::Array(_) | Value::Object(_))) => {
                format!("{}60000", js_string(value))
                    .parse::<f64>()
                    .unwrap_or(f64::NAN)
            }
            _ => numeric + 60_000.0,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| malformed())?
            .as_secs_f64()
            * 1000.0;
        if numeric > now || delayed < now {
            return Err(malformed());
        }
        let mut nonce_input = object.auth_data_bytes.clone();
        nonce_input.extend_from_slice(client_hash);
        let nonce = STANDARD.encode(compute_sha256(&nonce_input));
        if payload_value.get("nonce").and_then(Value::as_str) != Some(nonce.as_str())
            || !payload_value.get("ctsProfileMatch").is_some_and(truthy)
        {
            return Err(malformed());
        }
        let entries = header_value
            .get("x5c")
            .and_then(Value::as_array)
            .ok_or_else(malformed)?;
        let chain: Result<Vec<_>, WebauthnError> = entries
            .iter()
            .map(|entry| {
                let der = STANDARD
                    .decode(entry.as_str().ok_or_else(malformed)?)
                    .map_err(|_| malformed())?;
                X509::from_der(&der).map_err(Into::into)
            })
            .collect();
        let chain = chain?;
        let leaf = chain.first().ok_or_else(malformed)?;
        let name = leaf
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .ok_or_else(malformed)?
            .data()
            .as_slice();
        if name != b"attest.android.com" {
            return Err(malformed());
        }
        let algorithm = match statement.get(&Cbor::Text("alg".into())) {
            None | Some(Cbor::Null | Cbor::Bool(false) | Cbor::Integer(0)) => None,
            Some(Cbor::Integer(algorithm)) => {
                Some(COSEAlgorithm::try_from(*algorithm).map_err(|_| malformed())?)
            }
            _ => return Err(malformed()),
        };
        let attestation = ParsedAttestationData::Basic(chain.clone());
        self.verify_path("android-safetynet", &attestation)?;
        let signed = format!("{header}.{payload}");
        if !verify_certificate_signature(leaf, &decode(signature)?, signed.as_bytes(), algorithm)? {
            return Err(WebauthnError::AttestationStatementSigInvalid);
        }
        Ok((attestation, AttestationMetadata::None))
    }
}

#[derive(Clone)]
struct RevocationList {
    serials: Vec<Vec<u8>>,
    next_update: Option<i64>,
}

async fn revoked<F, Fut>(certificate: &X509, fetch: &F) -> Result<bool, WebauthnError>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
{
    use std::sync::{Mutex, OnceLock};
    use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
    static CACHE: OnceLock<Mutex<BTreeMap<Vec<u8>, RevocationList>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let key = certificate
        .authority_key_id()
        .or_else(|| certificate.subject_key_id())
        .map(|key| key.as_slice().to_vec());
    let serial = certificate.serial_number().to_bn()?.to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| malformed())?
        .as_secs() as i64;
    if let Some(key) = &key {
        let cached = cache.lock().map_err(|_| malformed())?.get(key).cloned();
        if let Some(cached) = cached.filter(|list| list.next_update.is_none_or(|next| next > now)) {
            return Ok(cached.serials.contains(&serial));
        }
    }
    let der = certificate.to_der()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|_| malformed())?;
    let url = parsed.extensions().iter().find_map(|extension| {
        let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() else {
            return None;
        };
        let DistributionPointName::FullName(names) = points.first()?.distribution_point.as_ref()?
        else {
            return None;
        };
        let GeneralName::URI(url) = names.first()? else {
            return None;
        };
        Some((*url).to_owned())
    });
    let Some(url) = url else {
        return Ok(false);
    };
    let Some(bytes) = fetch(url).await else {
        return Ok(false);
    };
    let Ok(crl) = openssl::x509::X509Crl::from_der(&bytes) else {
        return Ok(false);
    };
    let Some(entries) = crl.get_revoked() else {
        return Ok(false);
    };
    let serials = entries
        .iter()
        .map(|entry| entry.serial_number().to_bn().map(|number| number.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let next_update = x509_parser::parse_x509_crl(&bytes)
        .ok()
        .and_then(|(_, crl)| crl.next_update().map(|time| time.timestamp()));
    let is_revoked = serials.contains(&serial);
    if let Some(key) = key {
        drop(cache.lock().map_err(|_| malformed())?.insert(
            key,
            RevocationList {
                serials,
                next_update,
            },
        ));
    }
    Ok(is_revoked)
}

// Source applies JavaScript relational/addition coercion to SafetyNet timestampMs.
fn js_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                if value.is_null() {
                    String::new()
                } else {
                    js_string(value)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}
fn js_number(value: Option<&Value>) -> f64 {
    match value {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(value)) => {
            if *value {
                1.0
            } else {
                0.0
            }
        }
        Some(Value::Number(value)) => value.as_f64().unwrap_or(f64::NAN),
        Some(value) => {
            let string = js_string(value);
            let string = string.trim();
            if string.is_empty() {
                0.0
            } else {
                string.parse().unwrap_or(f64::NAN)
            }
        }
    }
}

fn check_ec_certificate(certificate: &X509, apple: bool) -> Result<(), WebauthnError> {
    let der = certificate.to_der()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|_| malformed())?;
    let public = certificate.public_key()?.ec_key()?;
    let curve = public.group().curve_name();
    if parsed.public_key().subject_public_key.data.first() != Some(&4)
        || !(matches!(curve, Some(Nid::X9_62_PRIME256V1 | Nid::SECP384R1))
            || apple && curve == Some(Nid::SECP521R1))
    {
        return Err(malformed());
    }
    Ok(())
}
fn certificate_algorithm(certificate: &X509) -> Result<COSEAlgorithm, WebauthnError> {
    let der = certificate.to_der()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|_| malformed())?;
    let algorithm = match parsed
        .tbs_certificate
        .signature
        .algorithm
        .to_id_string()
        .as_str()
    {
        "1.2.840.10045.4.3.2" => COSEAlgorithm::ES256,
        "1.2.840.10045.4.3.3" => COSEAlgorithm::ES384,
        "1.2.840.10045.4.3.4" => COSEAlgorithm::ES512,
        "1.2.840.113549.1.1.11" => COSEAlgorithm::RS256,
        "1.2.840.113549.1.1.12" => COSEAlgorithm::RS384,
        "1.2.840.113549.1.1.13" => COSEAlgorithm::RS512,
        "1.2.840.113549.1.1.5" => COSEAlgorithm::INSECURE_RS1,
        _ => return Err(malformed()),
    };
    match parsed
        .public_key()
        .algorithm
        .algorithm
        .to_id_string()
        .as_str()
    {
        "1.2.840.10045.2.1" => check_ec_certificate(certificate, false)?,
        "1.2.840.113549.1.1.1"
            if matches!(
                algorithm,
                COSEAlgorithm::RS256
                    | COSEAlgorithm::RS384
                    | COSEAlgorithm::RS512
                    | COSEAlgorithm::INSECURE_RS1
            ) => {}
        _ => return Err(malformed()),
    }
    Ok(algorithm)
}
/// Source gets the signature primitive from the certificate and only overrides
/// its hash from attStmt.alg. In particular RSA x5c statements use PKCS#1 v1.5.
pub(super) fn verify_certificate_signature(
    certificate: &X509,
    signature: &[u8],
    bytes: &[u8],
    hash_override: Option<COSEAlgorithm>,
) -> Result<bool, WebauthnError> {
    let algorithm = hash_override.unwrap_or(certificate_algorithm(certificate)?);
    let hash = match algorithm {
        COSEAlgorithm::ES256 | COSEAlgorithm::PS256 | COSEAlgorithm::RS256 => {
            MessageDigest::sha256()
        }
        COSEAlgorithm::ES384 | COSEAlgorithm::PS384 | COSEAlgorithm::RS384 => {
            MessageDigest::sha384()
        }
        COSEAlgorithm::ES512
        | COSEAlgorithm::PS512
        | COSEAlgorithm::RS512
        | COSEAlgorithm::EDDSA => MessageDigest::sha512(),
        COSEAlgorithm::INSECURE_RS1 => MessageDigest::sha1(),
        _ => return Err(malformed()),
    };
    let public = certificate.public_key()?;
    let mut verifier = Verifier::new(hash, &public)?;
    if public.id() == Id::RSA {
        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
    }
    Ok(verifier.verify_oneshot(signature, bytes)?)
}

fn attestation_chain(
    object: &AttestationObject<Registration>,
) -> Result<(Vec<X509>, &std::collections::BTreeMap<Cbor, Cbor>), WebauthnError> {
    let Cbor::Map(statement) = &object.att_stmt else {
        return Err(malformed());
    };
    let Some(Cbor::Array(entries)) = statement.get(&Cbor::Text("x5c".into())) else {
        return Err(malformed());
    };
    let chain = entries
        .iter()
        .map(|entry| {
            let Cbor::Bytes(bytes) = entry else {
                return Err(malformed());
            };
            X509::from_der(bytes).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, WebauthnError>>()?;
    Ok((chain, statement))
}
fn source_pkcs(key: &Cbor) -> Result<Vec<u8>, WebauthnError> {
    let Cbor::Map(key) = key else {
        return Err(malformed());
    };
    let Some(Cbor::Bytes(x)) = key.get(&Cbor::Integer(-2)) else {
        return Err(malformed());
    };
    let mut bytes = vec![4];
    bytes.extend_from_slice(x);
    if let Some(y) = key.get(&Cbor::Integer(-3)) {
        let Cbor::Bytes(y) = y else {
            return Err(malformed());
        };
        bytes.extend_from_slice(y);
    }
    Ok(bytes)
}
