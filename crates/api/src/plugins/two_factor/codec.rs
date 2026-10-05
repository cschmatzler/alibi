use super::*;
pub(in crate::plugins::two_factor) fn derive_encryption_key(
    secret: &str,
) -> AuthResult<Key<Aes256Gcm>> {
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(ENCRYPTION_INFO, &mut okm).map_err(|error| {
        AuthError::internal(format!("Failed to derive encryption key: {error}"))
    })?;
    Ok(Key::<Aes256Gcm>::from(okm))
}

pub(in crate::plugins::two_factor) fn encrypt_value(
    secret: &better_auth_core::AuthConfig,
    plaintext: &str,
) -> AuthResult<String> {
    super::super::token_crypto::encrypt_with_config(plaintext, secret)
}

pub(in crate::plugins::two_factor) fn decrypt_value(
    secret: &better_auth_core::AuthConfig,
    encrypted: &str,
) -> AuthResult<String> {
    // New factor rows use the pinned runtime's XChaCha/hex encoding. Installed
    // Rust rows retain an authenticated AES/HKDF reader; legacy writes are gone.
    super::super::token_crypto::decrypt_with_config(encrypted, secret).or_else(|error| {
        if secret.managed_secrets.is_some() {
            return Err(error);
        }
        decrypt_legacy_value(secret.current_secret(), encrypted)
    })
}

pub(in crate::plugins::two_factor) fn decrypt_legacy_value(
    secret: &str,
    encrypted: &str,
) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let bytes = URL_SAFE_NO_PAD.decode(encrypted).map_err(|error| {
        AuthError::internal(format!(
            "Failed to decode encrypted two-factor data: {error}"
        ))
    })?;
    if bytes.len() < 12 {
        return Err(AuthError::internal(
            "Encrypted two-factor payload is missing the nonce",
        ));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let nonce: &Nonce<aes_gcm::aead::consts::U12> = nonce_bytes
        .try_into()
        .map_err(|_error| AuthError::Encryption("Invalid nonce".into()))?;
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|error| {
        AuthError::internal(format!("Failed to decrypt two-factor data: {error}"))
    })?;
    String::from_utf8(plaintext).map_err(|error| {
        AuthError::internal(format!("Two-factor plaintext is not valid UTF-8: {error}"))
    })
}
