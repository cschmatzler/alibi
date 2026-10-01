//! Pinned Better Auth account-cookie JWE: dir with A256CBC-HS512.
use super::state::AccountCookiePayload;
use aes_gcm::aes::{
    Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use better_auth_core::{
    AuthError, AuthResult,
    utils::json::{JsValue, parse_value},
};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};

const INFO: &[u8] = b"BetterAuth.js Generated Encryption Key";
fn invalid() -> AuthError {
    AuthError::bad_request("Account not found")
}
fn key(secret: &str) -> AuthResult<[u8; 64]> {
    let mut key = [0; 64];
    Hkdf::<Sha256>::new(Some(b"better-auth-account"), secret.as_bytes())
        .expand(INFO, &mut key)
        .map_err(|_| invalid())?;
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
        .map_err(|_| invalid())?;
    mac.update(header.as_bytes());
    mac.update(iv);
    mac.update(ciphertext);
    mac.update(&((header.len() as u64) * 8).to_be_bytes());
    Ok(mac)
}
pub(super) fn encode(
    secret: &str,
    payload: &AccountCookiePayload,
    max_age: Duration,
) -> AuthResult<String> {
    let key = key(secret)?;
    let header = BASE64.encode(serde_json::to_vec(
        &json!({"alg":"dir","enc":"A256CBC-HS512","kid":thumbprint(&key)}),
    )?);
    let now = Utc::now().timestamp();
    let mut claims = serde_json::to_value(payload)?;
    let claims = claims.as_object_mut().ok_or_else(invalid)?;
    _ = claims.insert("iat".into(), json!(now));
    _ = claims.insert("exp".into(), json!(now + max_age.num_seconds()));
    _ = claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    let mut ciphertext = serde_json::to_vec(claims)?;
    let padding = 16 - ciphertext.len() % 16;
    ciphertext.resize(ciphertext.len() + padding, padding as u8);
    let mut iv = [0; 16];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256::new_from_slice(&key[32..]).map_err(|_| invalid())?;
    let mut previous = iv;
    for block in ciphertext.as_chunks_mut::<16>().0 {
        for (byte, previous) in block.iter_mut().zip(previous) {
            *byte ^= previous;
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
pub(super) fn decode(secret: &str, token: &str) -> AuthResult<AccountCookiePayload> {
    let parts: Vec<_> = token.split('.').collect();
    let [header, encrypted_key, iv, ciphertext, tag] = parts.as_slice() else {
        return Err(invalid());
    };
    if !encrypted_key.is_empty() {
        return Err(invalid());
    }
    let key = key(secret)?;
    let header_bytes = BASE64.decode(header).map_err(|_| invalid())?;
    let header_data = parse_value(std::str::from_utf8(&header_bytes).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
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
    let iv = BASE64.decode(iv).map_err(|_| invalid())?;
    let mut ciphertext = BASE64.decode(ciphertext).map_err(|_| invalid())?;
    let tag = BASE64.decode(tag).map_err(|_| invalid())?;
    if iv.len() != 16 || ciphertext.is_empty() || ciphertext.len() % 16 != 0 || tag.len() != 32 {
        return Err(invalid());
    }
    authentication(&key, header, &iv, &ciphertext)?
        .verify_truncated_left(&tag)
        .map_err(|_| invalid())?;
    let cipher = Aes256::new_from_slice(&key[32..]).map_err(|_| invalid())?;
    let mut previous: [u8; 16] = iv.try_into().map_err(|_| invalid())?;
    for block in ciphertext.as_chunks_mut::<16>().0 {
        let mut encrypted = [0; 16];
        encrypted.copy_from_slice(block);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for (byte, previous) in block.iter_mut().zip(previous) {
            *byte ^= previous;
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
    let claims = parse_value(std::str::from_utf8(&ciphertext).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let now = Utc::now().timestamp() as f64;
    for name in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(name) {
            let value = value.as_f64().ok_or_else(invalid)?;
            if name == "exp" && value <= now - 15.0 || name == "nbf" && value > now + 15.0 {
                return Err(invalid());
            }
        }
    }
    better_auth_core::utils::json::from_slice(&ciphertext).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_cookie_accepts_pinned_encrypted_vectors_and_rejects_unauthenticated_values() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("account-cookie-vectors.json")).unwrap();
        let secret = vectors["secret"].as_str().unwrap();
        for name in ["valid", "noKid"] {
            let decoded = crate::plugins::oauth::state::decode_account_cookie_value(
                secret,
                vectors[name].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), vectors["payload"]);
        }
        for name in ["wrongSalt", "wrongSecret", "expired", "gcm", "jws"] {
            assert!(
                crate::plugins::oauth::state::decode_account_cookie_value(
                    secret,
                    vectors[name].as_str().unwrap()
                )
                .is_err(),
                "{name} must not resolve a provider account"
            );
        }
        let original = vectors["valid"].as_str().unwrap();
        for segment in [0, 2, 3, 4] {
            let mut parts: Vec<_> = original.split('.').map(str::to_owned).collect();
            let mut bytes = BASE64.decode(&parts[segment]).unwrap();
            bytes[0] ^= 1;
            parts[segment] = BASE64.encode(bytes);
            assert!(
                crate::plugins::oauth::state::decode_account_cookie_value(secret, &parts.join("."))
                    .is_err(),
                "changed segment {segment} must not authenticate"
            );
        }
    }
}
