//! Source admits unrecognized OKP curves under none attestation. This validates
//! the ceremony, not possession of a usable signing key, and stores raw facts.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::utils::json::{JsValue, from_slice};
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value as Cbor;
use webauthn_rs::prelude::{Passkey, RegisterPublicKeyCredential};
use webauthn_rs_core::{crypto::compute_sha256, error::WebauthnError};

use super::webauthn::PasskeySnapshot;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RawNonePolicy {
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(super) enum RawCredential {
    SourceRawNone {
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
        let Self::SourceRawNone { credential_id, .. } = self;
        credential_id
    }
    pub(super) fn public_key(&self) -> &[u8] {
        let Self::SourceRawNone { public_key, .. } = self;
        public_key
    }
    pub(super) fn aaguid(&self) -> [u8; 16] {
        let Self::SourceRawNone { aaguid, .. } = self;
        *aaguid
    }
    pub(super) fn has_unsupported_curve(&self) -> bool {
        decode_first(self.public_key()).is_ok_and(|(key, _)| curve_eight(&key))
    }
    pub(super) fn snapshot(&self) -> better_auth_core::AuthResult<PasskeySnapshot> {
        let Self::SourceRawNone {
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

fn malformed() -> WebauthnError {
    WebauthnError::ParseNOMFailure
}
fn text<'a>(map: &'a std::collections::BTreeMap<Cbor, Cbor>, key: &str) -> Option<&'a Cbor> {
    map.get(&Cbor::Text(key.into()))
}
// The value decoder accepts indefinite CBOR, but pinned Tiny-CBOR does not.
// Inspect exactly one item's framing before decoding its values. The bounded
// recursion/checked lengths never allocate or inspect unrelated outer tail.
fn definite_item_end(bytes: &[u8], offset: usize, depth: usize) -> Result<usize, WebauthnError> {
    if depth >= 128 {
        return Err(malformed());
    }
    let header = *bytes.get(offset).ok_or_else(malformed)?;
    let major = header >> 5;
    let additional = header & 31;
    if additional >= 28 {
        return Err(malformed());
    }
    let mut cursor = offset.checked_add(1).ok_or_else(malformed)?;
    if major == 7 {
        let extra = match additional {
            20..=23 => 0,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(malformed()),
        };
        let end = cursor.checked_add(extra).ok_or_else(malformed)?;
        return bytes.get(cursor..end).map(|_| end).ok_or_else(malformed);
    }
    let argument = if additional < 24 {
        u64::from(additional)
    } else {
        let extra = 1usize << (additional - 24);
        let end = cursor.checked_add(extra).ok_or_else(malformed)?;
        let value = bytes
            .get(cursor..end)
            .ok_or_else(malformed)?
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        if value < 24 {
            return Err(malformed());
        }
        cursor = end;
        value
    };
    match major {
        0 | 1 => Ok(cursor),
        2 | 3 => {
            let length = usize::try_from(argument).map_err(|_| malformed())?;
            let end = cursor.checked_add(length).ok_or_else(malformed)?;
            bytes.get(cursor..end).map(|_| end).ok_or_else(malformed)
        }
        4 | 5 => {
            let count = usize::try_from(argument)
                .map_err(|_| malformed())?
                .checked_mul(if major == 5 { 2 } else { 1 })
                .ok_or_else(malformed)?;
            if count > bytes.len().saturating_sub(cursor) {
                return Err(malformed());
            }
            for _ in 0..count {
                cursor = definite_item_end(bytes, cursor, depth + 1)?;
            }
            Ok(cursor)
        }
        6 => definite_item_end(bytes, cursor, depth + 1),
        _ => Err(malformed()),
    }
}
fn decode_first(bytes: &[u8]) -> Result<(Cbor, usize), WebauthnError> {
    let expected_end = definite_item_end(bytes, 0, 0)?;
    let mut decoder = serde_cbor_2::Deserializer::from_slice(bytes);
    let value = Cbor::deserialize(&mut decoder).map_err(|_| malformed())?;
    if decoder.byte_offset() != expected_end {
        return Err(malformed());
    }
    Ok((value, decoder.byte_offset()))
}
fn curve_eight(value: &Cbor) -> bool {
    let Cbor::Map(map) = value else { return false };
    [(1, 1), (3, -8), (-1, 8)]
        .iter()
        .all(|(key, expected)| map.get(&Cbor::Integer(*key)) == Some(&Cbor::Integer(*expected)))
}
// Source converts extensions with `for (const [key, value] of input)` and
// recursively converts Map values. Strings and arrays of iterable entries are
// consequently legal; scalar entries throw before registration can finish.
fn extension_conversion_possible(value: &Cbor) -> bool {
    match value {
        Cbor::Map(entries) => entries
            .values()
            .all(|value| !matches!(value, Cbor::Map(_)) || extension_conversion_possible(value)),
        Cbor::Text(_) => true,
        Cbor::Bytes(bytes) => bytes.is_empty(),
        Cbor::Array(entries) => entries.iter().all(|entry| match entry {
            Cbor::Array(values) => values.get(1).is_none_or(|value| {
                !matches!(value, Cbor::Map(_)) || extension_conversion_possible(value)
            }),
            Cbor::Text(_) | Cbor::Bytes(_) | Cbor::Map(_) => true,
            _ => false,
        }),
        _ => false,
    }
}
fn argument_length(value: u128) -> usize {
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
fn source_encoded_length(value: &Cbor) -> Result<usize, WebauthnError> {
    let sum = |initial: usize, values: Vec<&Cbor>| {
        values.into_iter().try_fold(initial, |length, value| {
            length
                .checked_add(source_encoded_length(value)?)
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
                let integer = value.to_string().parse::<i128>().map_err(|_| malformed())?;
                source_encoded_length(&Cbor::Integer(integer))
            } else {
                // This conversion tests Source's IEEE float32 round-trip; it
                // never supplies an identity, counter or authorization value.
                Ok(
                    if !value.is_finite() || f64::from(*value as f32) == *value {
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
        Cbor::Text(value) => argument_length(value.len() as u128)
            .checked_add(value.len())
            .ok_or_else(malformed),
        Cbor::Array(values) => sum(
            argument_length(values.len() as u128),
            values.iter().collect(),
        ),
        Cbor::Map(values) => sum(
            argument_length(values.len() as u128),
            values
                .iter()
                .flat_map(|(key, value)| [key, value])
                .collect(),
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
pub(super) fn register_raw_none(
    registration: &RegisterPublicKeyCredential,
    original: &JsValue,
    policy: &RawNonePolicy,
) -> Result<Option<RawCredential>, WebauthnError> {
    // Source decodes the first outer CBOR item; outer trailing bytes are legal.
    let attestation_bytes = registration.response.attestation_object.as_ref();
    if attestation_bytes.first().is_none_or(|byte| byte >> 5 != 5) {
        return Err(malformed());
    }
    let (Cbor::Map(object), _) = decode_first(attestation_bytes)? else {
        return Err(malformed());
    };
    if text(&object, "fmt") != Some(&Cbor::Text("none".into())) {
        return Ok(None);
    }
    let Some(Cbor::Bytes(data)) = text(&object, "authData") else {
        return Err(malformed());
    };
    let Some(length) = data.get(53..55) else {
        return Err(malformed());
    };
    let id_length = usize::from(u16::from_be_bytes(
        length.try_into().map_err(|_| malformed())?,
    ));
    let key_start = 55 + id_length;
    let Some(key_bytes) = data.get(key_start..) else {
        return Err(malformed());
    };
    if key_bytes.first().is_none_or(|byte| byte >> 5 != 5) {
        return Err(malformed());
    }
    let (key, key_length) = decode_first(key_bytes)?;
    if !curve_eight(&key) {
        return Ok(None);
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
    if client.get("origin").and_then(JsValue::as_str) != Some(policy.origin.as_str()) {
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
    if matches!(text(&object, "attStmt"), None | Some(Cbor::Null))
        || matches!(text(&object, "attStmt"), Some(Cbor::Map(map)) if !map.is_empty())
    {
        return Err(WebauthnError::AttestationStatementMapInvalid);
    }
    let counter = u32::from_be_bytes(
        data.get(33..37)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    );
    let aaguid = data
        .get(37..53)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(Some(RawCredential::SourceRawNone {
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
