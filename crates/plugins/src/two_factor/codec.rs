use alibi_core::AuthResult;

pub(in crate::two_factor) fn encrypt_value(
    config: &alibi_core::AuthConfig,
    plaintext: &str,
) -> AuthResult<String> {
    super::super::token_crypto::encrypt_with_config(plaintext, config)
}

pub(in crate::two_factor) fn decrypt_value(
    config: &alibi_core::AuthConfig,
    encrypted: &str,
) -> AuthResult<String> {
    super::super::token_crypto::decrypt_with_config(encrypted, config)
}
