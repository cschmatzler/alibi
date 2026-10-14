//! Application cipher allow-lists exercise independently produced real ciphertext.
use alibi::plugins::SsoSamlEncryptionPolicy;
pub(crate) fn policy(mode: &str) -> SsoSamlEncryptionPolicy {
    let mut policy = SsoSamlEncryptionPolicy::default();
    if mode.contains("policy-key-denied") {
        policy.allowed_key_encryption_algorithms =
            Some(vec!["http://www.w3.org/2001/04/xmlenc#rsa-1_5".into()]);
    } else if mode.contains("policy-data-denied") {
        policy.allowed_data_encryption_algorithms =
            Some(vec!["http://www.w3.org/2009/xmlenc11#aes128-gcm".into()]);
    } else if mode.contains("policy-key-allowed") {
        policy.allowed_key_encryption_algorithms = Some(vec![
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".into(),
        ]);
    } else if mode.contains("policy-data-allowed") {
        policy.allowed_data_encryption_algorithms =
            Some(vec!["http://www.w3.org/2009/xmlenc11#aes256-gcm".into()]);
    } else if mode.contains("policy-key-empty") || mode.contains("policy-outer-key-denied") {
        policy.allowed_key_encryption_algorithms = Some(vec![]);
    } else if mode.contains("policy-data-empty") {
        policy.allowed_data_encryption_algorithms = Some(vec![]);
    }
    policy
}
