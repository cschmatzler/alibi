//! `DPoP` proof verification and single-use reservations for OAuth resource servers.
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthSchema, CreateVerification};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::HashMap, str::FromStr, sync::Mutex};

pub const DPOP_AUTHORIZATION_SCHEME: &str = "DPoP";
pub const BEARER_AUTHORIZATION_SCHEME: &str = "Bearer";
pub const DPOP_PROOF_TYPE: &str = "dpop+jwt";
pub const DPOP_SIGNING_ALGORITHMS: [&str; 5] = ["EdDSA", "ES256", "ES512", "PS256", "RS256"];
#[derive(Debug, Clone)]
pub struct DpopError {
    pub code: Option<String>,
    pub message: String,
}
impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for DpopError {}
impl DpopError {
    fn proof(message: impl Into<String>) -> Self {
        Self {
            code: Some("invalid_dpop_proof".into()),
            message: message.into(),
        }
    }
    fn ordinary(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: message.into(),
        }
    }
}
pub fn create_dpop_proof_error(code: &str, message: &str) -> DpopError {
    DpopError {
        code: Some(code.into()),
        message: message.into(),
    }
}
pub fn create_dpop_binding_error(code: &str, message: &str) -> DpopError {
    create_dpop_proof_error(code, message)
}
pub fn is_dpop_proof_error(error: &DpopError) -> bool {
    error.code.as_deref() == Some("invalid_dpop_proof")
}
pub fn is_dpop_binding_error(error: &DpopError) -> bool {
    matches!(
        error.code.as_deref(),
        Some("invalid_dpop_proof" | "invalid_token")
    )
}
#[derive(Debug, Clone)]
pub struct DpopReplayReservation {
    pub key: String,
    /// None represents a reference Invalid Date, not an absent reservation.
    pub expires_at: Option<DateTime<Utc>>,
    pub now: Option<DateTime<Utc>>,
}
#[async_trait]
pub trait DpopReplayStore: Send + Sync {
    async fn reserve(&self, reservation: &DpopReplayReservation) -> Result<bool, DpopError>;
}
#[derive(Debug, Default)]
pub struct InMemoryDpopReplayStore {
    reservations: Mutex<HashMap<String, Option<DateTime<Utc>>>>,
}
pub fn create_in_memory_dpop_replay_store() -> InMemoryDpopReplayStore {
    InMemoryDpopReplayStore::default()
}
#[async_trait]
impl DpopReplayStore for InMemoryDpopReplayStore {
    async fn reserve(&self, r: &DpopReplayReservation) -> Result<bool, DpopError> {
        let mut rows = self
            .reservations
            .lock()
            .map_err(|_| DpopError::ordinary("DPoP replay store lock poisoned"))?;
        rows.retain(|_, expires| match (expires, r.now) {
            (Some(expires), Some(now)) => *expires > now,
            _ => true,
        });
        if rows.contains_key(&r.key) {
            return Ok(false);
        }
        _ = rows.insert(r.key.clone(), r.expires_at);
        Ok(true)
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DpopVerificationReservation {
    pub identifier: String,
    pub value: String,
    pub expires_at: Option<DateTime<Utc>>,
}
/// Single-use storage capability for applications and auth contexts.
#[async_trait]
pub trait DpopReplayReservations: Send + Sync {
    async fn reserve_verification_value(
        &self,
        data: DpopVerificationReservation,
    ) -> Result<bool, DpopError>;
}
#[async_trait]
impl<S: AuthSchema> DpopReplayReservations for AuthContext<S> {
    async fn reserve_verification_value(
        &self,
        data: DpopVerificationReservation,
    ) -> Result<bool, DpopError> {
        let expires_at = data
            .expires_at
            .ok_or_else(|| DpopError::ordinary("Invalid time value"))?;
        self.verifications()
            .reserve(CreateVerification {
                identifier: data.identifier,
                value: data.value,
                expires_at,
            })
            .await
            .map_err(|error| DpopError::ordinary(auth_message(error)))
    }
}
pub struct DatabaseDpopReplayStore<'a> {
    reservations: &'a dyn DpopReplayReservations,
}
pub fn create_dpop_replay_store(
    reservations: &dyn DpopReplayReservations,
) -> DatabaseDpopReplayStore<'_> {
    DatabaseDpopReplayStore { reservations }
}
#[async_trait]
impl DpopReplayStore for DatabaseDpopReplayStore<'_> {
    async fn reserve(&self, r: &DpopReplayReservation) -> Result<bool, DpopError> {
        self.reservations
            .reserve_verification_value(DpopVerificationReservation {
                identifier: format!("dpop-proof:{}", r.key),
                value: r.key.clone(),
                expires_at: r.expires_at,
            })
            .await
    }
}
pub struct VerifyDpopProofOptions<'a> {
    pub proof_jwt: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub access_token: Option<&'a str>,
    pub expected_jkt: Option<&'a str>,
    pub require_ath: bool,
    pub now_seconds: Option<f64>,
    pub proof_max_age_seconds: Option<f64>,
    pub signing_algorithms: Option<Vec<String>>,
    pub replay_store: Option<&'a dyn DpopReplayStore>,
}
impl<'a> VerifyDpopProofOptions<'a> {
    pub fn new(proof_jwt: &'a str, method: &'a str, url: &'a str) -> Self {
        Self {
            proof_jwt,
            method,
            url,
            access_token: None,
            expected_jkt: None,
            require_ath: false,
            now_seconds: None,
            proof_max_age_seconds: None,
            signing_algorithms: None,
            replay_store: None,
        }
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedDpopProof {
    pub jwk: Value,
    pub jkt: String,
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    pub replay_key: String,
    pub expires_at: Option<DateTime<Utc>>,
}
pub fn normalize_dpop_htu(input: &str) -> Result<String, DpopError> {
    let parsed = url::Url::parse(input).map_err(|_| DpopError::ordinary("Invalid URL"))?;
    if parsed.fragment().is_some_and(|value| !value.is_empty()) {
        return Err(DpopError::ordinary(
            "DPoP proof htu must not contain a fragment",
        ));
    }
    Ok(format!(
        "{}{}",
        parsed.origin().ascii_serialization(),
        parsed.path()
    ))
}
pub fn derive_dpop_ath(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token))
}
pub fn derive_dpop_jkt(jwk: &Value) -> Result<String, DpopError> {
    let kind = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::ordinary("Key must be a JSON Web Key"))?;
    let fields: &[(&str, &str)] = match kind {
        "EC" => &[
            ("crv", "Curve"),
            ("kty", "Key Type"),
            ("x", "X Coordinate"),
            ("y", "Y Coordinate"),
        ],
        "OKP" => &[
            ("crv", "Subtype of Key Pair"),
            ("kty", "Key Type"),
            ("x", "Public Key"),
        ],
        "RSA" => &[("e", "Exponent"), ("kty", "Key Type"), ("n", "Modulus")],
        "oct" => &[("k", "Key Value"), ("kty", "Key Type")],
        "AKP" => &[
            ("alg", "Algorithm"),
            ("kty", "Key Type"),
            ("pub", "Public key"),
        ],
        _ => {
            return Err(DpopError::ordinary(
                "\"kty\" (Key Type) Parameter missing or unsupported",
            ));
        }
    };
    let mut canonical = std::collections::BTreeMap::new();
    for (field, label) in fields {
        let value = jwk
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() || (kind == "oct" && *field == "k"))
            .ok_or_else(|| {
                DpopError::ordinary(format!(
                    "\"{field}\" ({label}) Parameter missing or invalid"
                ))
            })?;
        _ = canonical.insert(*field, value);
    }
    let bytes =
        serde_json::to_vec(&canonical).map_err(|error| DpopError::ordinary(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}
pub fn get_confirmation_jkt(confirmation: &Value) -> Option<&str> {
    confirmation
        .as_object()?
        .get("jkt")?
        .as_str()
        .filter(|value| !value.is_empty())
}
pub fn get_dpop_jkt_from_payload(payload: &Value) -> Result<Option<&str>, DpopError> {
    if payload.is_null() {
        return Err(DpopError::ordinary(
            "null is not an object (evaluating 'payload.cnf')",
        ));
    }
    Ok(payload.get("cnf").and_then(get_confirmation_jkt))
}
fn auth_message(error: alibi_core::AuthError) -> String {
    match error {
        alibi_core::AuthError::Internal(message) | alibi_core::AuthError::Config(message) => {
            message
        }
        other => other.to_string(),
    }
}
fn date(seconds: f64) -> Option<DateTime<Utc>> {
    let millis = (seconds * 1000.0).trunc().to_string().parse::<i64>().ok()?;
    DateTime::from_timestamp_millis(millis)
}
fn decode(value: &str) -> Result<JsValue, DpopError> {
    let bytes = crate::jwt::decode_compact_part(value, false)
        .map_err(|_| DpopError::proof("Invalid Token or Protected Header formatting"))?;
    alibi_core::utils::json::parse_value(&String::from_utf8_lossy(&bytes))
        .map_err(|_| DpopError::proof("Invalid Token or Protected Header formatting"))
}
fn string_claim<'a>(payload: &'a JsValue, key: &str) -> Option<&'a str> {
    payload.get(key)?.as_str().filter(|value| !value.is_empty())
}
fn prepare_dpop_public_key(algorithm: &str, jwk: &Value) -> Result<(Value, bool), DpopError> {
    if jwk.get("ext").is_some_and(|v| !v.is_boolean()) {
        return Err(DpopError::proof(
            "\"ext\" (Extractable) Parameter must be a boolean",
        ));
    }
    let operations = if let Some(value) = jwk.get("key_ops") {
        let invalid = || {
            DpopError::proof(
                "\"key_ops\" (Key Operations) Parameter must be an array of unique strings",
            )
        };
        let values = value.as_array().ok_or_else(invalid)?;
        let mut unique = std::collections::HashSet::new();
        for value in values {
            let value = value.as_str().ok_or_else(invalid)?;
            if !unique.insert(value) {
                return Err(invalid());
            }
        }
        Some(values)
    } else {
        None
    };
    let kty = jwk.get("kty").and_then(Value::as_str);
    if !matches!(kty, Some("EC" | "OKP" | "RSA" | "AKP")) {
        return Err(DpopError::proof(
            "Unsupported \"kty\" (Key Type) Parameter value",
        ));
    }
    let (expected, name, curve) = match algorithm {
        "EdDSA" | "Ed25519" => ("OKP", "Ed25519", Some("Ed25519")),
        "ES256" => ("EC", "ECDSA", Some("P-256")),
        "ES384" => ("EC", "ECDSA", Some("P-384")),
        "ES512" => ("EC", "ECDSA", Some("P-521")),
        "RS256" | "RS384" | "RS512" => ("RSA", "RSASSA-PKCS1-v1_5", None),
        "PS256" | "PS384" | "PS512" => ("RSA", "RSA-PSS", None),
        _ => {
            return Err(DpopError::proof(
                "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value",
            ));
        }
    };
    if kty != Some(expected) {
        return Err(DpopError::proof(
            "Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value",
        ));
    }
    if expected == "OKP" && jwk.get("crv").and_then(Value::as_str) != curve {
        return Err(DpopError::proof(
            "JWK \"crv\" Parameter and algorithm name mismatch",
        ));
    }
    if let Some(values) = operations
        && values.iter().any(|v| {
            ![
                "encrypt",
                "decrypt",
                "sign",
                "verify",
                "deriveKey",
                "deriveBits",
                "wrapKey",
                "unwrapKey",
            ]
            .contains(&v.as_str().unwrap_or_default())
        })
    {
        return Err(DpopError::proof("value must be enumeration (string)"));
    }
    let private = jwk
        .get("priv")
        .is_some_and(|v| JsValue::from(v.clone()).is_truthy());
    if operations.map_or(private, |values| {
        values.iter().any(|v| v.as_str() != Some("verify"))
    }) {
        return Err(DpopError::proof(format!(
            "Unsupported key usage for an {name} key"
        )));
    }
    if expected == "EC" && jwk.get("crv").and_then(Value::as_str) != curve {
        return Err(DpopError::proof(
            "JWK \"crv\" does not match the requested algorithm",
        ));
    }
    let can_verify = operations.is_none_or(|values| !values.is_empty());
    let mut public = jwk
        .as_object()
        .cloned()
        .ok_or_else(|| DpopError::proof("DPoP proof header must include a public jwk"))?;
    // JOSE imports using the protected algorithm, discards use/alg, and
    // validates key_ops before passing the key to signature verification.
    for field in ["priv", "alg", "use", "key_ops"] {
        _ = public.remove(field);
    }
    Ok((Value::Object(public), can_verify))
}
fn check_dpop_rsa_size(algorithm: &str, jwk: &Value) -> Result<(), DpopError> {
    if (algorithm.starts_with("RS") || algorithm.starts_with("PS"))
        && let Some(n) = jwk.get("n").and_then(Value::as_str)
        && let Ok(bytes) = crate::jwt::decode_compact_part(n, false)
        && let Some((first, byte)) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0)
        && (bytes.len() - first) * 8 - (byte.leading_zeros() as usize) < 2048
    {
        return Err(DpopError::proof(format!(
            "{algorithm} requires key modulusLength to be 2048 bits or larger"
        )));
    }
    Ok(())
}
pub async fn verify_dpop_proof(
    options: &VerifyDpopProofOptions<'_>,
) -> Result<VerifiedDpopProof, DpopError> {
    let parts = options.proof_jwt.split('.').collect::<Vec<_>>();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(DpopError::proof("DPoP proof must be a compact JWT"));
    };
    if options.proof_jwt.is_empty() {
        return Err(DpopError::proof("DPoP proof must be a compact JWT"));
    }
    let raw_header = decode(header)?;
    if !matches!(raw_header, JsValue::Object(_)) {
        return Err(DpopError::proof(
            "Protected Header must be a top-level JSON object",
        ));
    }
    if raw_header.get("typ").and_then(JsValue::as_str) != Some(DPOP_PROOF_TYPE) {
        return Err(DpopError::proof("DPoP proof typ must be \"dpop+jwt\""));
    }
    let raw_alg = raw_header.get("alg");
    if raw_alg.is_none_or(|value| !value.is_truthy()) {
        return Err(DpopError::proof(
            "DPoP proof must use an asymmetric JWS algorithm",
        ));
    }
    let Some(algorithm) = raw_alg.and_then(JsValue::as_str) else {
        return Err(DpopError::ordinary(
            "alg.startsWith is not a function. (In 'alg.startsWith(\"HS\")', 'alg.startsWith' is undefined)",
        ));
    };
    if algorithm == "none" || algorithm.starts_with("HS") {
        return Err(DpopError::proof(
            "DPoP proof must use an asymmetric JWS algorithm",
        ));
    }
    let permitted = options.signing_algorithms.as_ref().map_or_else(
        || DPOP_SIGNING_ALGORITHMS.contains(&algorithm),
        |values| values.iter().any(|value| value == algorithm),
    );
    if !permitted {
        return Err(DpopError::proof(
            "DPoP proof uses an unsupported JWS algorithm",
        ));
    }
    let header = raw_header
        .to_json_value()
        .map_err(|error| DpopError::ordinary(error.to_string()))?;
    let jwk = header
        .get("jwk")
        .filter(|value| value.is_object())
        .ok_or_else(|| DpopError::proof("DPoP proof header must include a public jwk"))?;
    if jwk.get("kty").and_then(Value::as_str) == Some("oct") {
        return Err(DpopError::proof("DPoP proof jwk must be asymmetric"));
    }
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if jwk.get(field).is_some() {
            return Err(DpopError::proof(
                "DPoP proof jwk must not contain private key material",
            ));
        }
    }
    let (public, can_verify) = prepare_dpop_public_key(algorithm, jwk)?;
    let map = header
        .as_object()
        .ok_or_else(|| DpopError::proof("Protected Header must be a top-level JSON object"))?;
    crate::jwt::validate_critical_header(map, false)
        .map_err(|error| DpopError::proof(auth_message(error)))?;
    let input = format!(
        "{}.{}",
        parts.first().copied().unwrap_or_default(),
        parts.get(1).copied().unwrap_or_default()
    );
    let signature_bytes = crate::jwt::decode_compact_part(signature, false)
        .map_err(|_| DpopError::proof("Failed to base64url decode the signature"))?;
    if !can_verify {
        return Err(DpopError::proof(
            "CryptoKey does not support this operation, its usages must include verify.",
        ));
    }
    check_dpop_rsa_size(algorithm, &public)?;
    let native_algorithm = if algorithm == "Ed25519" {
        Some(crate::jwt::JwtAlgorithm::EdDsa)
    } else {
        crate::jwt::JwtAlgorithm::from_str(algorithm).ok()
    };
    let valid = if let Some(algorithm) = native_algorithm {
        crate::jwt::crypto::verify(algorithm, &public, input.as_bytes(), &signature_bytes)
            .unwrap_or(false)
    } else {
        let algorithm = jsonwebtoken::Algorithm::from_str(algorithm).map_err(|_| {
            DpopError::proof("Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
        })?;
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(public).map_err(|error| DpopError::proof(error.to_string()))?;
        let key = jsonwebtoken::DecodingKey::from_jwk(&jwk)
            .map_err(|error| DpopError::proof(error.to_string()))?;
        jsonwebtoken::crypto::verify(
            &URL_SAFE_NO_PAD.encode(&signature_bytes),
            input.as_bytes(),
            &key,
            algorithm,
        )
        .unwrap_or(false)
    };
    if !valid {
        return Err(DpopError::proof("signature verification failed"));
    }
    let payload = decode(payload)
        .map_err(|_| DpopError::proof("Failed to parse the decoded payload as JSON"))?;
    if !matches!(payload, JsValue::Object(_)) {
        return Err(DpopError::proof(
            "JWT Claims Set must be a top-level JSON object",
        ));
    }
    for field in ["iat", "nbf", "exp"] {
        if payload
            .get(field)
            .is_some_and(|value| !matches!(value, JsValue::Number(_)))
        {
            return Err(DpopError::proof(format!(
                "\"{field}\" claim must be a number"
            )));
        }
    }
    // JOSE checks temporal claims against its wall clock, independently of the
    // caller's manual clock for the DPoP iat window.
    let clock = json!(Utc::now().timestamp()).as_f64().unwrap_or_default();
    if payload
        .get("nbf")
        .and_then(JsValue::as_f64)
        .is_some_and(|nbf| nbf > clock)
    {
        return Err(DpopError::proof("\"nbf\" claim timestamp check failed"));
    }
    if payload
        .get("exp")
        .and_then(JsValue::as_f64)
        .is_some_and(|exp| exp <= clock)
    {
        return Err(DpopError::proof("\"exp\" claim timestamp check failed"));
    }
    let htm = string_claim(&payload, "htm");
    let htu = string_claim(&payload, "htu");
    let jti = string_claim(&payload, "jti");
    let iat = payload
        .get("iat")
        .and_then(JsValue::as_f64)
        .filter(|value| value.is_finite());
    let (Some(htm), Some(htu), Some(jti), Some(iat)) = (htm, htu, jti, iat) else {
        return Err(DpopError::proof(
            "DPoP proof must include htm, htu, jti, and iat claims",
        ));
    };
    if jti.encode_utf16().count() > 512 {
        return Err(DpopError::proof("DPoP proof jti is too large"));
    }
    if htm.to_uppercase() != options.method.to_uppercase() {
        return Err(DpopError::proof(
            "DPoP proof htm does not match the request method",
        ));
    }
    let normalized =
        normalize_dpop_htu(options.url).map_err(|error| DpopError::proof(error.message))?;
    let proof_htu = normalize_dpop_htu(htu).map_err(|error| DpopError::proof(error.message))?;
    if proof_htu != normalized {
        return Err(DpopError::proof(
            "DPoP proof htu does not match the request URL",
        ));
    }
    let now = options.now_seconds.unwrap_or(clock);
    let age = options.proof_max_age_seconds.unwrap_or(300.0);
    if iat > now + 5.0 || now - iat > age {
        return Err(DpopError::proof(
            "DPoP proof iat is outside the accepted window",
        ));
    }
    let ath = string_claim(&payload, "ath");
    if options.require_ath && ath.is_none() {
        return Err(DpopError::proof("DPoP proof must include an ath claim"));
    }
    if let Some(token) = options.access_token
        && ath != Some(derive_dpop_ath(token).as_str())
    {
        return Err(DpopError::proof(
            "DPoP proof ath does not match the access token",
        ));
    }
    let jkt = derive_dpop_jkt(jwk)?;
    if options.expected_jkt.is_some_and(|expected| expected != jkt) {
        return Err(DpopError::proof(
            "DPoP proof key does not match the bound token",
        ));
    }
    let replay_key = derive_dpop_ath(&format!(
        "{jkt}\n{}\n{normalized}\n{jti}",
        htm.to_uppercase()
    ));
    let expires_at = date(iat + age);
    if let Some(store) = options.replay_store
        && !store
            .reserve(&DpopReplayReservation {
                key: replay_key.clone(),
                expires_at,
                now: date(now),
            })
            .await?
    {
        return Err(DpopError::proof("DPoP proof jti has already been used"));
    }
    Ok(VerifiedDpopProof {
        jwk: jwk.clone(),
        jkt,
        jti: jti.into(),
        htm: htm.into(),
        htu: normalized,
        iat,
        ath: ath.map(str::to_owned),
        replay_key,
        expires_at,
    })
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccessTokenAuthorization {
    pub scheme: String,
    pub token: String,
}
fn js_whitespace(c: char) -> bool {
    matches!(c,'\u{0009}'..='\u{000d}'|'\u{0020}'|'\u{00a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}'|'\u{feff}')
}
pub fn parse_access_token_authorization(
    authorization: Option<&str>,
) -> Option<AccessTokenAuthorization> {
    let value = authorization?.trim_matches(js_whitespace);
    if value.is_empty() {
        return None;
    }
    let unknown = || {
        Some(AccessTokenAuthorization {
            scheme: "Unknown".into(),
            token: value.into(),
        })
    };
    let Some((split, _)) = value.char_indices().find(|(_, c)| js_whitespace(*c)) else {
        return unknown();
    };
    let (scheme, rest) = value.split_at(split);
    let token = rest.trim_matches(js_whitespace);
    if !scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c))
        || token.is_empty()
        || token.contains(['\n', '\r', '\u{2028}', '\u{2029}'])
    {
        return unknown();
    }
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        "Bearer"
    } else if scheme.eq_ignore_ascii_case("dpop") {
        "DPoP"
    } else {
        return unknown();
    };
    Some(AccessTokenAuthorization {
        scheme: scheme.into(),
        token: token.into(),
    })
}
pub fn strip_access_token_authorization_scheme(token: &str) -> String {
    parse_access_token_authorization(Some(token))
        .map_or_else(|| token.into(), |authorization| authorization.token)
}
pub struct EnforceDpopBindingParams<'a> {
    pub payload: &'a Value,
    pub authorization: &'a AccessTokenAuthorization,
    pub proof_jwt: Option<&'a str>,
    pub method: &'a str,
    pub url: &'a str,
    pub replay_store: Option<&'a dyn DpopReplayStore>,
    pub proof_max_age_seconds: Option<f64>,
    pub signing_algorithms: Option<Vec<String>>,
}
impl<'a> EnforceDpopBindingParams<'a> {
    pub fn new(
        payload: &'a Value,
        authorization: &'a AccessTokenAuthorization,
        method: &'a str,
        url: &'a str,
    ) -> Self {
        Self {
            payload,
            authorization,
            proof_jwt: None,
            method,
            url,
            replay_store: None,
            proof_max_age_seconds: None,
            signing_algorithms: None,
        }
    }
}
pub async fn enforce_dpop_binding(params: &EnforceDpopBindingParams<'_>) -> Result<(), DpopError> {
    let Some(jkt) = get_dpop_jkt_from_payload(params.payload)? else {
        if params.authorization.scheme == DPOP_AUTHORIZATION_SCHEME {
            return Err(create_dpop_binding_error(
                "invalid_token",
                "DPoP authorization requires a DPoP-bound access token",
            ));
        }
        return Ok(());
    };
    if params.authorization.scheme != DPOP_AUTHORIZATION_SCHEME {
        return Err(create_dpop_binding_error(
            "invalid_token",
            "DPoP-bound access token requires the DPoP authorization scheme",
        ));
    }
    let proof = params
        .proof_jwt
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DpopError::proof("DPoP proof header is required"))?;
    let mut options = VerifyDpopProofOptions::new(proof, params.method, params.url);
    options.access_token = Some(&params.authorization.token);
    options.expected_jkt = Some(jkt);
    options.require_ath = true;
    options.replay_store = params.replay_store;
    options.proof_max_age_seconds = params.proof_max_age_seconds;
    options.signing_algorithms = params.signing_algorithms.clone();
    _ = verify_dpop_proof(&options).await?;
    Ok(())
}
