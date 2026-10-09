//! Bounded Source COSE cases that Core cannot represent retain raw identity.
//! None validates a ceremony; packed and authentication verify original proofs.
use super::source::credential::Passkey;
use super::webauthn::PasskeySnapshot;
use alibi_core::utils::json::{JsValue, from_slice};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value as Cbor;
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::{crypto::compute_sha256, error::WebauthnError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RawNonePolicy {
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(super) enum RawCredential {
    // Keep the historical codec discriminator readable across upgrades.
    #[serde(rename = "sourceRawNone")]
    SourceRawKey {
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        counter: u32,
        backup_eligible: bool,
        backup_state: bool,
        aaguid: [u8; 16],
        transports: Option<Vec<String>>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StoredCredential {
    Raw(RawCredential),
    Core(Passkey),
}

impl RawCredential {
    pub(super) fn credential_id(&self) -> &[u8] {
        let Self::SourceRawKey { credential_id, .. } = self;
        credential_id
    }
    pub(super) fn replace_public_key(&mut self, bytes: Vec<u8>) {
        let Self::SourceRawKey { public_key, .. } = self;
        *public_key = bytes;
    }
    pub(super) fn public_key(&self) -> &[u8] {
        let Self::SourceRawKey { public_key, .. } = self;
        public_key
    }
    pub(super) const fn aaguid(&self) -> [u8; 16] {
        let Self::SourceRawKey { aaguid, .. } = self;
        *aaguid
    }
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn snapshot(&self) -> alibi_core::AuthResult<PasskeySnapshot> {
        let Self::SourceRawKey {
            counter,
            backup_eligible,
            backup_state,
            ..
        } = self;
        Ok(PasskeySnapshot {
            serialized: serde_json::to_string(self)?,
            counter: u64::from(*counter),
            backed_up: *backup_state,
            backup_eligible: *backup_eligible,
        })
    }
}

// Pinned Tiny-CBOR has a narrower value contract than serde's CBOR decoder:
// number/string map keys, SameValueZero uniqueness, literal tags, lossy text,
// and only three half-float values. Decode one item without inspecting its tail.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SourceMapKey {
    Text(String),
    Number(u64),
}

impl SourceMapKey {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn from_value(value: &Cbor) -> Result<Self, WebauthnError> {
        let number = match value {
            Cbor::Text(value) => return Ok(Self::Text(value.clone())),
            // Only safe integers enter this representation. Their conversion
            // back to a JS number is exact, including integer/float key aliases.
            Cbor::Integer(value) => *value as f64,
            Cbor::Float(value) => *value,
            Cbor::Null
            | Cbor::Bool(_)
            | Cbor::Bytes(_)
            | Cbor::Array(_)
            | Cbor::Map(_)
            | Cbor::Tag(..)
            | Cbor::__Hidden => return Err(malformed()),
        };
        Ok(Self::Number(if number.is_nan() {
            f64::NAN.to_bits()
        } else if number == 0.0 {
            0
        } else {
            number.to_bits()
        }))
    }
}

struct SourceDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl SourceDecoder<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], WebauthnError> {
        let end = self.cursor.checked_add(N).ok_or_else(malformed)?;
        let bytes = self.bytes.get(self.cursor..end).ok_or_else(malformed)?;
        let result = bytes.try_into().map_err(|_error| malformed())?;
        self.cursor = end;
        Ok(result)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, WebauthnError> {
        let value = match additional {
            0..=23 => return Ok(u64::from(additional)),
            24 => u64::from(self.take::<1>()?[0]),
            25 => u64::from(u16::from_be_bytes(self.take()?)),
            26 => u64::from(u32::from_be_bytes(self.take()?)),
            27 => u64::from_be_bytes(self.take()?),
            _ => return Err(malformed()),
        };
        if !(24..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(malformed());
        }
        Ok(value)
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn item(&mut self, depth: usize) -> Result<Cbor, WebauthnError> {
        if depth >= 128 {
            return Err(malformed());
        }
        let header = self.take::<1>()?[0];
        let major = header >> 5;
        let additional = header & 31;
        if major == 7 {
            return Ok(match additional {
                20 => Cbor::Bool(false),
                21 => Cbor::Bool(true),
                // Undefined and null are rejected in the same positions by
                // this verifier and each re-encodes to one byte. Original raw
                // bytes are retained; this is not a persisted value codec.
                22 | 23 => Cbor::Null,
                25 => Cbor::Float(match u16::from_be_bytes(self.take()?) {
                    0x7c00 => f64::INFINITY,
                    0xfc00 => f64::NEG_INFINITY,
                    0x7e00 => f64::NAN,
                    _ => return Err(malformed()),
                }),
                26 => source_number(f64::from(f32::from_be_bytes(self.take()?))),
                27 => source_number(f64::from_be_bytes(self.take()?)),
                _ => return Err(malformed()),
            });
        }
        let argument = self.argument(additional)?;
        match major {
            0 => Ok(Cbor::Integer(i128::from(argument))),
            1 if argument < MAX_SAFE_INTEGER => Ok(Cbor::Integer(-1 - i128::from(argument))),
            // -MAX_SAFE_INTEGER-1 is representable in JS, but is not a safe
            // integer and therefore re-encodes as a float in Tiny-CBOR.
            1 => Ok(Cbor::Float(-(MAX_SAFE_INTEGER as f64) - 1.0)),
            2 | 3 => {
                let length = usize::try_from(argument).map_err(|_error| malformed())?;
                let end = self.cursor.checked_add(length).ok_or_else(malformed)?;
                // Source ArrayBuffer.slice truncates the payload, but reports
                // the declared consumed length. A following item still fails.
                let bytes = self
                    .bytes
                    .get(self.cursor..end.min(self.bytes.len()))
                    .ok_or_else(malformed)?;
                self.cursor = end;
                if major == 2 {
                    Ok(Cbor::Bytes(bytes.to_vec()))
                } else {
                    let text = String::from_utf8_lossy(bytes);
                    Ok(Cbor::Text(
                        text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned(),
                    ))
                }
            }
            4 | 5 => {
                let count = usize::try_from(argument).map_err(|_error| malformed())?;
                let items = count
                    .checked_mul(if major == 5 { 2 } else { 1 })
                    .ok_or_else(malformed)?;
                if items > self.bytes.len().saturating_sub(self.cursor) {
                    return Err(malformed());
                }
                if major == 4 {
                    let mut values = Vec::new();
                    for _ in 0..count {
                        values.push(self.item(depth + 1)?);
                    }
                    Ok(Cbor::Array(values))
                } else {
                    let mut keys = std::collections::BTreeSet::new();
                    let mut values = std::collections::BTreeMap::new();
                    for _ in 0..count {
                        let key = self.item(depth + 1)?;
                        if !keys.insert(SourceMapKey::from_value(&key)?) {
                            return Err(malformed());
                        }
                        let value = self.item(depth + 1)?;
                        drop(values.insert(key, value));
                    }
                    Ok(Cbor::Map(values))
                }
            }
            6 => Ok(Cbor::Tag(argument, Box::new(self.item(depth + 1)?))),
            _ => Err(malformed()),
        }
    }
}

const fn malformed() -> WebauthnError {
    WebauthnError::ParseNOMFailure
}

fn text<'a>(map: &'a std::collections::BTreeMap<Cbor, Cbor>, key: &str) -> Option<&'a Cbor> {
    map.get(&Cbor::Text(key.into()))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn source_number(value: f64) -> Cbor {
    if value.is_finite() && value.fract() == 0.0 && value.abs() <= MAX_SAFE_INTEGER as f64 {
        // This bounded integral conversion gives Map.get(number) the same
        // semantics for integer and floating CBOR encodings.
        Cbor::Integer(value as i128)
    } else {
        Cbor::Float(value)
    }
}

pub(super) fn decode_first(bytes: &[u8]) -> Result<(Cbor, usize), WebauthnError> {
    let mut decoder = SourceDecoder { bytes, cursor: 0 };
    let value = decoder.item(0)?;
    Ok((value, decoder.cursor))
}

fn curve_eight(value: &Cbor) -> bool {
    let Cbor::Map(map) = value else { return false };
    [(1, 1), (3, -8), (-1, 8)]
        .iter()
        .all(|(key, expected)| map.get(&Cbor::Integer(*key)) == Some(&Cbor::Integer(*expected)))
}

// This measured mismatch remains raw: alg -7 is not changed to EdDSA.
fn mismatched_ed25519(value: &Cbor) -> bool {
    let Cbor::Map(map) = value else { return false };
    [(1, 1), (3, -7), (-1, 6)]
        .iter()
        .all(|(key, expected)| map.get(&Cbor::Integer(*key)) == Some(&Cbor::Integer(*expected)))
}

fn verify_ed25519(key: &[u8], signature: &[u8], data: &[u8]) -> Result<bool, WebauthnError> {
    use ed25519_dalek::Verifier;
    let (Cbor::Map(map), _) = decode_first(key)? else {
        return Err(malformed());
    };
    let Some(Cbor::Bytes(x)) = map.get(&Cbor::Integer(-2)) else {
        return Err(malformed());
    };
    let bytes: &[u8; 32] = x.as_slice().try_into().map_err(|_error| malformed())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_error| malformed())?;
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return Ok(false);
    };
    Ok(key.verify(data, &signature).is_ok())
}

// Source converts extensions with `for (const [key, value] of input)` and
// recursively converts Map values. Strings and arrays of iterable entries are
// consequently legal; scalar entries throw before registration can finish.
fn extension_conversion_possible(value: &Cbor) -> bool {
    match value {
        Cbor::Map(entries) => entries.values().all(|value_2| {
            !matches!(value_2, Cbor::Map(_)) || extension_conversion_possible(value_2)
        }),
        Cbor::Text(_) => true,
        Cbor::Bytes(bytes) => bytes.is_empty(),
        Cbor::Array(entries) => entries.iter().all(|entry| match entry {
            Cbor::Array(values) => values.get(1).is_none_or(|value_3| {
                !matches!(value_3, Cbor::Map(_)) || extension_conversion_possible(value_3)
            }),
            Cbor::Text(_) | Cbor::Bytes(_) | Cbor::Map(_) => true,
            Cbor::Null
            | Cbor::Bool(_)
            | Cbor::Integer(_)
            | Cbor::Float(_)
            | Cbor::Tag(..)
            | Cbor::__Hidden => false,
        }),
        Cbor::Null
        | Cbor::Bool(_)
        | Cbor::Integer(_)
        | Cbor::Float(_)
        | Cbor::Tag(..)
        | Cbor::__Hidden => false,
    }
}

const fn argument_length(value: u128) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

// Tiny-CBOR re-encodes decoded values before advancing Source's cursor. In
// particular, nonminimal integer/length encodings cannot hide leftover bytes.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn source_encoded_length(value: &Cbor) -> Result<usize, WebauthnError> {
    let sum = |initial: usize, values: Vec<&Cbor>| {
        values.into_iter().try_fold(initial, |length, value_2| {
            length
                .checked_add(source_encoded_length(value_2)?)
                .ok_or_else(malformed)
        })
    };
    match value {
        Cbor::Null | Cbor::Bool(_) => Ok(1),
        Cbor::Integer(value) => Ok(argument_length(if *value < 0 {
            (-1 - value).unsigned_abs()
        } else {
            value.unsigned_abs()
        })),
        Cbor::Float(value) => {
            if value.is_finite() && value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0 {
                let integer = value
                    .to_string()
                    .parse::<i128>()
                    .map_err(|_error| malformed())?;
                source_encoded_length(&Cbor::Integer(integer))
            } else {
                // This conversion tests Source's IEEE float32 round-trip; it
                // never supplies an identity, counter or authorization value.
                Ok(
                    if !value.is_finite() || f64::from(*value as f32).to_bits() == value.to_bits() {
                        5
                    } else {
                        9
                    },
                )
            }
        }
        Cbor::Bytes(value) => argument_length(value.len() as u128)
            .checked_add(value.len())
            .ok_or_else(malformed),
        // Tiny-CBOR prefixes strings with JS UTF16 length, then emits UTF8.
        Cbor::Text(value) => argument_length(value.encode_utf16().count() as u128)
            .checked_add(value.len())
            .ok_or_else(malformed),
        Cbor::Array(values) => sum(
            argument_length(values.len() as u128),
            values.iter().collect(),
        ),
        Cbor::Map(values) => sum(
            argument_length(values.len() as u128),
            values.iter().flat_map(<[&Cbor; 2]>::from).collect(),
        ),
        Cbor::Tag(tag, value) => argument_length(u128::from(*tag))
            .checked_add(source_encoded_length(value)?)
            .ok_or_else(malformed),
        _ => Err(malformed()),
    }
}

fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

/// Select before Core verification. Other formats/keys continue through their
/// existing verifier; a failed verification never falls back into this path.
#[expect(
    clippy::too_many_lines,
    reason = "Keep the pinned WebAuthn validation sequence together for comparison with the reference runtime"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn register_raw_key(
    registration: &RegisterPublicKeyCredential,
    original: &JsValue,
    policy: &RawNonePolicy,
    verification_origin: &str,
) -> Result<Option<RawCredential>, WebauthnError> {
    // Source decodes the first outer CBOR item; outer trailing bytes are legal.
    let attestation_bytes = registration.response.attestation_object.as_ref();
    if attestation_bytes.first().is_none_or(|byte| byte >> 5 != 5) {
        return Err(malformed());
    }
    let (Cbor::Map(object), _) = decode_first(attestation_bytes)? else {
        return Err(malformed());
    };
    let none = text(&object, "fmt") == Some(&Cbor::Text("none".into()));
    let packed = text(&object, "fmt") == Some(&Cbor::Text("packed".into()));
    let Some(Cbor::Bytes(data)) = text(&object, "authData") else {
        return Err(malformed());
    };
    let Some(length) = data.get(53..55) else {
        return Err(malformed());
    };
    let id_length = usize::from(u16::from_be_bytes(
        length.try_into().map_err(|_error| malformed())?,
    ));
    let key_start = 55 + id_length;
    let Some(key_bytes) = data.get(key_start..) else {
        return Err(malformed());
    };
    if key_bytes.first().is_none_or(|byte| byte >> 5 != 5) {
        return Err(malformed());
    }
    let (key, key_length) = decode_first(key_bytes)?;
    if !matches!(
        match &key {
            Cbor::Map(map) => map.get(&Cbor::Integer(3)),
            _ => None,
        },
        Some(Cbor::Integer(
            -8 | -7 | -36 | -37 | -38 | -39 | -257 | -258 | -259 | -65535
        ))
    ) {
        return Err(malformed());
    }
    let mismatch = mismatched_ed25519(&key);
    let representable = super::source::crypto::COSEKey::try_from(&key).is_ok();
    let mut raw_eligible = (none && (curve_eight(&key) || !representable)) || mismatch;
    if packed
        && let Some(Cbor::Map(statement)) = text(&object, "attStmt")
        && statement.contains_key(&Cbor::Text("x5c".into()))
    {
        raw_eligible = false;
    }
    let Some(id) = original.get("id").and_then(JsValue::as_str) else {
        return Err(malformed());
    };
    if id.is_empty()
        || original.get("rawId").and_then(JsValue::as_str) != Some(id)
        || original.get("type").and_then(JsValue::as_str) != Some("public-key")
    {
        return Err(malformed());
    }
    let client: JsValue = from_slice(registration.response.client_data_json.as_ref())?;
    if client.get("type").and_then(JsValue::as_str) != Some("webauthn.create") {
        return Err(WebauthnError::InvalidClientDataType);
    }
    if client.get("challenge").and_then(JsValue::as_str) != Some(policy.challenge.as_str()) {
        return Err(WebauthnError::MismatchedChallenge);
    }
    if client.get("origin").and_then(JsValue::as_str) != Some(verification_origin) {
        return Err(WebauthnError::InvalidRPOrigin);
    }
    if let Some(binding) = client.get("tokenBinding").filter(|value| truthy(value))
        && (!binding.is_object()
            || !matches!(
                binding.get("status").and_then(JsValue::as_str),
                Some("present" | "supported" | "not-supported")
            ))
    {
        return Err(malformed());
    }
    if data.get(..32) != Some(compute_sha256(policy.rp_id.as_bytes()).as_slice()) {
        return Err(WebauthnError::InvalidRPIDHash);
    }
    let flags = *data.get(32).ok_or_else(malformed)?;
    if flags & 1 == 0 {
        return Err(WebauthnError::UserNotPresent);
    }
    if flags & 0x40 == 0 || (flags & 0x10 != 0 && flags & 8 == 0) {
        return Err(malformed());
    }
    let mut end = key_start
        .checked_add(source_encoded_length(&key)?)
        .ok_or_else(malformed)?;
    if flags & 0x80 != 0 {
        let (extensions, _) = decode_first(data.get(end..).ok_or_else(malformed)?)?;
        if !extension_conversion_possible(&extensions) {
            return Err(malformed());
        }
        end = end
            .checked_add(source_encoded_length(&extensions)?)
            .ok_or_else(malformed)?;
    }
    // Source rejects leftover bytes in authenticator data, unlike the outer CBOR.
    if data.len() > end {
        return Err(malformed());
    }
    // None's source verifier reads only `attStmt.size > 0`. Null/missing throw;
    // other decoded primitives/arrays have no size and pass that comparison.
    if none
        && (matches!(text(&object, "attStmt"), None | Some(Cbor::Null))
            || matches!(text(&object, "attStmt"), Some(Cbor::Map(map)) if !map.is_empty()))
    {
        return Err(WebauthnError::AttestationStatementMapInvalid);
    }
    if !raw_eligible {
        return Ok(None);
    }
    if packed {
        let Some(Cbor::Map(statement)) = text(&object, "attStmt") else {
            return Err(malformed());
        };
        // Both the -7 tag and ordinary -8 statement are measured controls.
        if !matches!(
            statement.get(&Cbor::Text("alg".into())),
            Some(Cbor::Integer(-7 | -8))
        ) {
            return Err(malformed());
        }
        let Some(Cbor::Bytes(signature)) = statement.get(&Cbor::Text("sig".into())) else {
            return Err(malformed());
        };
        let mut signed = data.clone();
        signed.extend_from_slice(&compute_sha256(
            registration.response.client_data_json.as_ref(),
        ));
        if !verify_ed25519(
            key_bytes.get(..key_length).ok_or_else(malformed)?,
            signature,
            &signed,
        )? {
            return Err(WebauthnError::AttestationStatementSigInvalid);
        }
    }
    let counter = u32::from_be_bytes(
        data.get(33..37)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_error| malformed())?,
    );
    let aaguid = data
        .get(37..53)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_error| malformed())?;
    Ok(Some(RawCredential::SourceRawKey {
        credential_id: data.get(55..key_start).ok_or_else(malformed)?.to_vec(),
        public_key: key_bytes.get(..key_length).ok_or_else(malformed)?.to_vec(),
        counter,
        backup_eligible: flags & 8 != 0,
        backup_state: flags & 0x10 != 0,
        aaguid,
        transports: registration
            .response
            .transports
            .as_ref()
            .map(|values| values.iter().map(ToString::to_string).collect()),
    }))
}

pub(super) fn raw_credential_id(credential: &RawCredential) -> String {
    URL_SAFE_NO_PAD.encode(credential.credential_id())
}

/// Source requires exactly one well-formed, canonically-sized extension item.
pub(super) fn validate_assertion_data(bytes: &[u8]) -> Result<(), WebauthnError> {
    let flags = *bytes.get(32).ok_or_else(malformed)?;
    let mut end = 37usize;
    if flags & 0x40 != 0 {
        let length = bytes.get(53..55).ok_or_else(malformed)?;
        let id_length = u16::from_be_bytes(length.try_into().map_err(|_| malformed())?);
        let start = 55 + usize::from(id_length);
        let (key, _) = decode_first(bytes.get(start..).ok_or_else(malformed)?)?;
        end = start + source_encoded_length(&key)?;
    }
    if flags & 0x80 != 0 {
        let (extension, _) = decode_first(bytes.get(end..).ok_or_else(malformed)?)?;
        if !extension_conversion_possible(&extension) {
            return Err(malformed());
        }
        end += source_encoded_length(&extension)?;
    }
    if bytes.len() != end {
        return Err(malformed());
    }
    Ok(())
}

/// Only freshly issued Source-policy states may authorize a raw assertion.
/// The stored ID/key tags and current public counter remain authoritative.
pub(super) fn authenticate_raw(
    credential: &RawCredential,
    authentication: &webauthn_rs::prelude::PublicKeyCredential,
    original: &JsValue,
    challenge: &str,
    rp_id: &str,
    origin: &str,
    current_counter: u32,
) -> Result<super::authentication::AuthenticationResult, WebauthnError> {
    let (key, _) = decode_first(credential.public_key())?;

    if original.get("type").and_then(JsValue::as_str) != Some("public-key")
        || authentication.raw_id.as_ref() != credential.credential_id()
        || authentication.id != raw_credential_id(credential)
    {
        return Err(malformed());
    }
    let client: JsValue = from_slice(authentication.response.client_data_json.as_ref())?;
    if client.get("type").and_then(JsValue::as_str) != Some("webauthn.get") {
        return Err(WebauthnError::InvalidClientDataType);
    }
    if client.get("challenge").and_then(JsValue::as_str) != Some(challenge) {
        return Err(WebauthnError::MismatchedChallenge);
    }
    if client.get("origin").and_then(JsValue::as_str) != Some(origin) {
        return Err(WebauthnError::InvalidRPOrigin);
    }
    if let Some(binding) = client.get("tokenBinding").filter(|value| truthy(value))
        && (!binding.is_object()
            || !matches!(
                binding.get("status").and_then(JsValue::as_str),
                Some("present" | "supported" | "notSupported")
            ))
    {
        return Err(malformed());
    }
    let bytes = authentication.response.authenticator_data.as_ref();
    validate_assertion_data(bytes)?;
    let data = super::source::data::AuthenticatorData::<
        webauthn_rs_core::proto::Authentication,
    >::from_source(bytes)?;
    if bytes.get(..32) != Some(compute_sha256(rp_id.as_bytes()).as_slice()) {
        return Err(WebauthnError::InvalidRPIDHash);
    }
    if !data.user_present {
        return Err(WebauthnError::UserNotPresent);
    }
    if data.backup_state && !data.backup_eligible {
        return Err(malformed());
    }
    if (data.counter > 0 || current_counter > 0) && data.counter <= current_counter {
        return Err(malformed());
    }
    let mut signed = bytes.to_vec();
    signed.extend_from_slice(&compute_sha256(
        authentication.response.client_data_json.as_ref(),
    ));
    let verified = if let Cbor::Map(map) = &key
        && map.get(&Cbor::Integer(1)) == Some(&Cbor::Integer(1))
    {
        if map.get(&Cbor::Integer(-1)) != Some(&Cbor::Integer(6)) {
            return Err(WebauthnError::COSEKeyEDDSAInvalidCurve);
        }
        verify_ed25519(
            credential.public_key(),
            authentication.response.signature.as_ref(),
            &signed,
        )?
    } else {
        super::source::crypto::COSEKey::try_from(&key)?
            .verify_signature(authentication.response.signature.as_ref(), &signed)?
    };
    if !verified {
        return Err(WebauthnError::AuthenticationFailure);
    }
    Ok(super::authentication::AuthenticationResult::Raw(
        super::authentication::RawAuthenticationResult {
            credential_id: credential.credential_id().to_vec().into(),
            counter: data.counter,
            user_verified: data.user_verified,
            backup_eligible: data.backup_eligible,
            backup_state: data.backup_state,
        },
    ))
}

impl RawCredential {
    pub(super) fn apply_authentication(
        &mut self,
        result: &super::authentication::RawAuthenticationResult,
    ) {
        let Self::SourceRawKey {
            counter,
            backup_eligible,
            backup_state,
            ..
        } = self;
        *counter = result.counter;
        *backup_eligible = result.backup_eligible;
        *backup_state = result.backup_state;
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;

    fn decode(hex: &str) -> Result<(Cbor, usize), WebauthnError> {
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        decode_first(&bytes)
    }

    #[test]
    fn decoder_follows_the_pinned_value_contract() {
        let integer_map =
            std::collections::BTreeMap::from([(Cbor::Integer(1), Cbor::Text("a".into()))]);
        for (hex, expected, consumed) in [
            ("f4", Cbor::Bool(false), 1),
            ("f5", Cbor::Bool(true), 1),
            ("f6", Cbor::Null, 1),
            ("f7", Cbor::Null, 1),
            ("f97c00", Cbor::Float(f64::INFINITY), 3),
            ("f9fc00", Cbor::Float(f64::NEG_INFINITY), 3),
            ("fa40000000", Cbor::Integer(2), 5),
            ("fa3fc00000", Cbor::Float(1.5), 5),
            ("fb3ff8000000000000", Cbor::Float(1.5), 9),
            ("1b0000000000000100", Cbor::Integer(256), 9),
            (
                "3b001ffffffffffffe",
                Cbor::Integer(-9_007_199_254_740_991),
                9,
            ),
            (
                "3b001fffffffffffff",
                Cbor::Float(-9_007_199_254_740_992.0),
                9,
            ),
            ("c16161", Cbor::Tag(1, Box::new(Cbor::Text("a".into()))), 3),
            ("64efbbbf61", Cbor::Text("a".into()), 5),
            ("43ff", Cbor::Bytes(vec![0xff]), 4),
            ("a1fb3ff00000000000006161", Cbor::Map(integer_map), 12),
        ] {
            let (value, length) = decode(hex).unwrap();
            assert_eq!((value, length), (expected, consumed), "{hex}");
        }
        let (nan, _) = decode("f97e00").unwrap();
        assert!(matches!(nan, Cbor::Float(value) if value.is_nan()));
        for malformed in [
            "f93c00",
            "f8",
            "1c",
            "1817",
            "1b0020000000000000",
            "a2016161016162",
            "a2f97e006161f97e006162",
            "a1f56161",
            "e0",
            "9a7fffffff",
            "",
        ] {
            assert!(decode(malformed).is_err(), "{malformed}");
        }
        let nested = "81".repeat(128) + "00";
        assert!(decode(&nested).is_err());
    }

    #[test]
    fn extension_conversion_and_reencoded_lengths() {
        let entry = |value| Cbor::Array(vec![Cbor::Text("k".into()), value]);
        let nested = Cbor::Map(std::collections::BTreeMap::from([(
            Cbor::Text("credProps".into()),
            Cbor::Map(std::collections::BTreeMap::from([(
                Cbor::Text("rk".into()),
                Cbor::Bool(true),
            )])),
        )]));
        for (value, possible) in [
            (nested.clone(), true),
            (Cbor::Text("text".into()), true),
            (Cbor::Bytes(Vec::new()), true),
            (Cbor::Bytes(vec![1]), false),
            (
                Cbor::Array(vec![entry(nested.clone()), Cbor::Text("x".into())]),
                true,
            ),
            (
                Cbor::Array(vec![entry(Cbor::Map(Default::default()))]),
                true,
            ),
            (Cbor::Array(vec![Cbor::Integer(1)]), false),
            (Cbor::Integer(1), false),
        ] {
            assert_eq!(extension_conversion_possible(&value), possible, "{value:?}");
        }
        for (value, length) in [
            (Cbor::Integer(-25), 2),
            (Cbor::Float(1.5), 5),
            (Cbor::Float(1.1), 9),
            (Cbor::Float(f64::INFINITY), 5),
            (Cbor::Float(4_294_967_296.0), 9),
            (Cbor::Text("é".into()), 3),
            (Cbor::Tag(300, Box::new(Cbor::Null)), 4),
            (nested, 16),
        ] {
            assert_eq!(source_encoded_length(&value).unwrap(), length, "{value:?}");
        }
    }
}
// LCOV_EXCL_STOP
