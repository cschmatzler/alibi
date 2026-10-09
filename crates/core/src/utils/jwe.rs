//! Authenticated direct-key JWE shared by account and session cookies.
use crate::{
    AuthError, AuthResult,
    utils::json::{JsValue, parse_value},
};
use aes_gcm::aes::{
    Aes256,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use base64::{
    Engine, alphabet,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD as BASE64},
    },
};
use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hybrid_array::Array;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};

const INFO: &[u8] = b"BetterAuth.js Generated Encryption Key";

fn invalid() -> AuthError {
    AuthError::bad_request("Invalid encrypted cookie")
}

fn decode_segment(value: &str) -> AuthResult<Vec<u8>> {
    // Pinned JOSE uses base64url followed by atob: only these five ASCII
    // whitespace characters are ignored; padding is optional but exact.
    let compact: Vec<_> = value
        .bytes()
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\x0c' | b'\r' | b' '))
        .collect();
    let unpadded = compact
        .iter()
        .rposition(|byte| *byte != b'=')
        .map_or(0, |index| index + 1);
    let padding = compact.len() - unpadded;
    if padding != 0 && (compact.len() % 4 != 0 || padding != (4 - unpadded % 4) % 4) {
        return Err(invalid());
    }
    GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(compact.get(..unpadded).ok_or_else(invalid)?)
    .map_err(|_error| invalid())
}

fn key(secret: &str, salt: &str) -> AuthResult<[u8; 64]> {
    let mut key = [0; 64];
    Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret.as_bytes())
        .expand(INFO, &mut key)
        .map_err(|_error| invalid())?;
    Ok(key)
}

fn thumbprint(key: &[u8]) -> String {
    let canonical = format!("{{\"k\":\"{}\",\"kty\":\"oct\"}}", BASE64.encode(key));
    BASE64.encode(Sha256::digest(canonical.as_bytes()))
}

fn authentication(
    key: &[u8],
    header: &str,
    iv: &[u8],
    ciphertext: &[u8],
) -> AuthResult<Hmac<Sha512>> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key.get(..32).ok_or_else(invalid)?)
        .map_err(|_error| invalid())?;
    mac.update(header.as_bytes());
    mac.update(iv);
    mac.update(ciphertext);
    mac.update(
        &(u64::try_from(header.len())
            .map_err(|_error| invalid())?
            .checked_mul(8)
            .ok_or_else(invalid)?)
        .to_be_bytes(),
    );
    Ok(mac)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn encode(
    secret: &str,
    salt: &str,
    payload: &serde_json::Value,
    max_age: f64,
) -> AuthResult<String> {
    let key = key(secret, salt)?;
    let header = BASE64.encode(serde_json::to_vec(
        &json!({"alg":"dir","enc":"A256CBC-HS512","kid":thumbprint(&key)}),
    )?);
    let now = Utc::now().timestamp();
    let mut claims = serde_json::to_value(payload)?;
    let claims = claims.as_object_mut().ok_or_else(invalid)?;
    drop(claims.insert("iat".into(), json!(now)));
    let expiry = serde_json::Number::from(now).as_f64().ok_or_else(invalid)? + max_age;
    if !expiry.is_finite() {
        return Err(AuthError::internal(
            "Invalid encrypted-cookie expiration time",
        ));
    }
    drop(claims.insert("exp".into(), json!(expiry)));
    drop(claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string())));
    let mut ciphertext = crate::utils::json::to_vec(claims)?;
    let padding = 16 - ciphertext.len() % 16;
    ciphertext.resize(
        ciphertext.len() + padding,
        u8::try_from(padding).map_err(|error| AuthError::Internal(error.to_string()))?,
    );
    let mut iv = [0; 16];
    rand::fill(&mut iv);
    let cipher =
        Aes256::new_from_slice(key.get(32..).ok_or_else(invalid)?).map_err(|_error| invalid())?;
    let mut previous = iv;
    for block in ciphertext.as_chunks_mut::<16>().0 {
        for (byte, previous_2_3) in block.iter_mut().zip(previous) {
            *byte ^= previous_2_3;
        }
        let block_array: &mut Array<u8, _> = block.into();
        cipher.encrypt_block(block_array);
        previous.copy_from_slice(block);
    }
    let tag = authentication(&key, &header, &iv, &ciphertext)?
        .finalize()
        .into_bytes();
    Ok(format!(
        "{header}..{}.{}.{}",
        BASE64.encode(iv),
        BASE64.encode(ciphertext),
        BASE64.encode(tag.get(..32).ok_or_else(invalid)?)
    ))
}

/// Authenticate the protected header, ciphertext and registered time claims.
///
/// # Errors
/// Returns an error for malformed, unauthenticated or expired data.
pub fn decode(secret: &str, salt: &str, token: &str) -> AuthResult<serde_json::Value> {
    // Cookie values arrive URI-encoded; the source cookie parser decodes them
    // before JOSE sees the protected header and its authenticated spelling.
    let token = percent_encoding::percent_decode_str(token)
        .decode_utf8()
        .map_err(|_error| invalid())?;
    decode_parsed(secret, salt, &token)
}

/// Authenticate a compact JWE after the owning cookie parser decoded its value.
///
/// # Errors
/// Returns an error for malformed, unauthenticated or expired data.
pub fn decode_parsed(secret: &str, salt: &str, token: &str) -> AuthResult<serde_json::Value> {
    let parts: Vec<_> = token.split('.').collect();
    let [header, encrypted_key, iv, ciphertext, tag] = parts.as_slice() else {
        return Err(invalid());
    };
    if !encrypted_key.is_empty() {
        return Err(invalid());
    }
    let key = key(secret, salt)?;
    let header_bytes = decode_segment(header)?;
    let header_data = parse_value(std::str::from_utf8(&header_bytes).map_err(|_error| invalid())?)
        .map_err(|_error| invalid())?;
    if header_data.get("alg").and_then(JsValue::as_str) != Some("dir")
        || header_data.get("enc").and_then(JsValue::as_str) != Some("A256CBC-HS512")
        || header_data.get("crit").is_some()
        || header_data
            .get("zip")
            .is_some_and(|zip| zip.as_str() != Some("DEF"))
    {
        return Err(invalid());
    }
    if let Some(kid) = header_data.get("kid")
        && kid.as_str() != Some(thumbprint(&key).as_str())
    {
        return Err(invalid());
    }
    let iv = decode_segment(iv)?;
    let mut ciphertext = decode_segment(ciphertext)?;
    let tag = decode_segment(tag)?;
    if iv.len() != 16 || ciphertext.is_empty() || ciphertext.len() % 16 != 0 || tag.len() != 32 {
        return Err(invalid());
    }
    authentication(&key, header, &iv, &ciphertext)?
        .verify_truncated_left(&tag)
        .map_err(|_error| invalid())?;
    let cipher =
        Aes256::new_from_slice(key.get(32..).ok_or_else(invalid)?).map_err(|_error| invalid())?;
    let mut previous: [u8; 16] = iv.try_into().map_err(|_error| invalid())?;
    for block in ciphertext.as_chunks_mut::<16>().0 {
        let mut encrypted = [0; 16];
        encrypted.copy_from_slice(block);
        let block_array: &mut Array<u8, _> = block.into();
        cipher.decrypt_block(block_array);
        for (byte, previous_2) in block.iter_mut().zip(previous) {
            *byte ^= previous_2;
        }
        previous = encrypted;
    }
    let padding = usize::from(*ciphertext.last().ok_or_else(invalid)?);
    if padding == 0
        || padding > 16
        || ciphertext
            .get(ciphertext.len().saturating_sub(padding)..)
            .ok_or_else(invalid)?
            .iter()
            .any(|byte| usize::from(*byte) != padding)
    {
        return Err(invalid());
    }
    ciphertext.truncate(ciphertext.len() - padding);
    if header_data.get("zip").is_some() {
        // JOSE 6.2.12 authenticates and decrypts before bounded raw DEFLATE.
        let mut inflated = Vec::with_capacity(250_001);
        let mut inflater = flate2::Decompress::new(false);
        let status = inflater
            .decompress_vec(&ciphertext, &mut inflated, flate2::FlushDecompress::Finish)
            .map_err(|_error| invalid())?;
        if status != flate2::Status::StreamEnd || inflated.len() > 250_000 {
            return Err(invalid());
        }
        ciphertext = inflated;
    }
    let claims = parse_value(std::str::from_utf8(&ciphertext).map_err(|_error| invalid())?)
        .map_err(|_error| invalid())?;
    let now = serde_json::Number::from(Utc::now().timestamp())
        .as_f64()
        .ok_or_else(invalid)?;
    for name in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(name) {
            let value = value.as_f64().ok_or_else(invalid)?;
            if name == "exp" && value <= now - 15.0 || name == "nbf" && value > now + 15.0 {
                return Err(invalid());
            }
        }
    }
    crate::utils::json::from_slice(&ciphertext).map_err(|_error| invalid())
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test fixtures index known-length tokens"
    )]
    use super::*;
    use std::io::Write as _;

    const SECRET: &str = "jwe-test-secret";
    const SALT: &str = "jwe-test-salt";

    fn seal(header: &serde_json::Value, plaintext: &[u8]) -> String {
        let key = key(SECRET, SALT).unwrap();
        let header = BASE64.encode(serde_json::to_vec(header).unwrap());
        let mut ciphertext = plaintext.to_vec();
        let padding = 16 - ciphertext.len() % 16;
        ciphertext.resize(ciphertext.len() + padding, u8::try_from(padding).unwrap());
        let iv = [7u8; 16];
        let cipher = Aes256::new_from_slice(&key[32..]).unwrap();
        let mut previous = iv;
        for block in ciphertext.as_chunks_mut::<16>().0 {
            for (byte, previous) in block.iter_mut().zip(previous) {
                *byte ^= previous;
            }
            let block_array: &mut Array<u8, _> = block.into();
            cipher.encrypt_block(block_array);
            previous.copy_from_slice(block);
        }
        let tag = authentication(&key, &header, &iv, &ciphertext)
            .unwrap()
            .finalize()
            .into_bytes();
        format!(
            "{header}..{}.{}.{}",
            BASE64.encode(iv),
            BASE64.encode(ciphertext),
            BASE64.encode(&tag[..32])
        )
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn header_with_zip() -> serde_json::Value {
        json!({"alg":"dir","enc":"A256CBC-HS512","zip":"DEF"})
    }

    #[test]
    fn deflated_payload_roundtrips() {
        let claims = br#"{"sub":"user-1"}"#;
        let token = seal(&header_with_zip(), &deflate(claims));
        assert_eq!(
            decode_parsed(SECRET, SALT, &token).unwrap(),
            json!({"sub":"user-1"})
        );
    }

    #[test]
    fn rejects_corrupt_and_oversized_deflate_streams() {
        let garbage = seal(&header_with_zip(), &[0xff, 0xff, 0xff, 0xff]);
        assert!(decode_parsed(SECRET, SALT, &garbage).is_err());

        let truncated = seal(&header_with_zip(), &deflate(br#"{"sub":"user-1"}"#)[..4]);
        assert!(decode_parsed(SECRET, SALT, &truncated).is_err());

        let big = format!(r#"{{"v":"{}"}}"#, "a".repeat(250_001));
        let oversized = seal(&header_with_zip(), &deflate(big.as_bytes()));
        assert!(decode_parsed(SECRET, SALT, &oversized).is_err());
    }

    #[test]
    fn rejects_malformed_compact_tokens() {
        let valid = encode(SECRET, SALT, &json!({"a":1}), 60.0).unwrap();
        assert!(decode_parsed(SECRET, SALT, &valid).is_ok());
        assert!(decode_parsed(SECRET, SALT, "a.b.c").is_err());
        assert!(decode_parsed(SECRET, SALT, "a.b.c.d.e").is_err());

        let mut parts: Vec<_> = valid.split('.').collect();
        let short_iv = BASE64.encode([0u8; 8]);
        parts[2] = &short_iv;
        assert!(decode_parsed(SECRET, SALT, &parts.join(".")).is_err());

        let mut parts: Vec<_> = valid.split('.').collect();
        let bad_padding = format!("{}==", parts[3]);
        parts[3] = &bad_padding;
        assert!(decode_parsed(SECRET, SALT, &parts.join(".")).is_err());
    }
}
// LCOV_EXCL_STOP
