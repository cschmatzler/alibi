//! Pinned Better Auth account-cookie JWE: dir with A256CBC-HS512.
#[cfg(test)]
mod tests;

use super::state::AccountCookiePayload;

use aes_gcm::aes::{
    Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};

use base64::{
    Engine, alphabet,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD as BASE64},
    },
};

use better_auth_core::{
    AuthError, AuthResult,
    utils::json::{JsValue, parse_value},
};

use chrono::Utc;

use hkdf::Hkdf;

use hmac::{Hmac, Mac};

use rand::{RngCore, rngs::OsRng};

use serde_json::json;

use sha2::{Digest, Sha256, Sha512};

const INFO: &[u8] = b"BetterAuth.js Generated Encryption Key";

fn invalid() -> AuthError {
    AuthError::bad_request("Account not found")
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

fn key(secret: &str) -> AuthResult<[u8; 64]> {
    let mut key = [0; 64];
    Hkdf::<Sha256>::new(Some(b"better-auth-account"), secret.as_bytes())
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
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key.get(..32).ok_or_else(invalid)?)
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
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub(super) fn encode(
    secret: &str,
    payload: &AccountCookiePayload,
    max_age: f64,
) -> AuthResult<String> {
    let key = key(secret)?;
    let header = BASE64.encode(serde_json::to_vec(
        &json!({"alg":"dir","enc":"A256CBC-HS512","kid":thumbprint(&key)}),
    )?);
    let now = Utc::now().timestamp();
    let mut claims = serde_json::to_value(payload)?;
    let claims = claims.as_object_mut().ok_or_else(invalid)?;
    drop(claims.insert("iat".into(), json!(now)));
    let expiry = now as f64 + max_age;
    if !expiry.is_finite() {
        return Err(AuthError::internal(
            "Invalid account-cookie expiration time",
        ));
    }
    drop(claims.insert("exp".into(), json!(expiry)));
    drop(claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string())));
    let mut ciphertext = better_auth_core::utils::json::to_vec(claims)?;
    let padding = 16 - ciphertext.len() % 16;
    ciphertext.resize(
        ciphertext.len() + padding,
        u8::try_from(padding).map_err(|error| AuthError::Internal(error.to_string()))?,
    );
    let mut iv = [0; 16];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256::new_from_slice(&key[32..]).map_err(|_error| invalid())?;
    let mut previous = iv;
    for block in ciphertext.as_chunks_mut::<16>().0 {
        for (byte, previous_2_3) in block.iter_mut().zip(previous) {
            *byte ^= previous_2_3;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
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

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn decode(secret: &str, token: &str) -> AuthResult<AccountCookiePayload> {
    // Cookie values arrive URI-encoded; the source cookie parser decodes them
    // before JOSE sees the protected header and its authenticated spelling.
    let token = urlencoding::decode(token).map_err(|_error| invalid())?;
    let parts: Vec<_> = token.split('.').collect();
    let [header, encrypted_key, iv, ciphertext, tag] = parts.as_slice() else {
        return Err(invalid());
    };
    if !encrypted_key.is_empty() {
        return Err(invalid());
    }
    let key = key(secret)?;
    let header_bytes = decode_segment(header)?;
    let header_data = parse_value(std::str::from_utf8(&header_bytes).map_err(|_error| invalid())?)
        .map_err(|_error| invalid())?;
    if header_data.get("alg").and_then(JsValue::as_str) != Some("dir")
        || header_data.get("enc").and_then(JsValue::as_str) != Some("A256CBC-HS512")
        || header_data.get("crit").is_some()
        || header_data.get("zip").is_some()
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
    let cipher = Aes256::new_from_slice(&key[32..]).map_err(|_error| invalid())?;
    let mut previous: [u8; 16] = iv.try_into().map_err(|_error| invalid())?;
    for block in ciphertext.as_chunks_mut::<16>().0 {
        let mut encrypted = [0; 16];
        encrypted.copy_from_slice(block);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
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
    let claims = parse_value(std::str::from_utf8(&ciphertext).map_err(|_error| invalid())?)
        .map_err(|_error| invalid())?;
    let now = Utc::now().timestamp() as f64;
    for name in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(name) {
            let value = value.as_f64().ok_or_else(invalid)?;
            if name == "exp" && value <= now - 15.0 || name == "nbf" && value > now + 15.0 {
                return Err(invalid());
            }
        }
    }
    better_auth_core::utils::json::from_slice(&ciphertext).map_err(|_error| invalid())
}
