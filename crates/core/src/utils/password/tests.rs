use super::*;

#[tokio::test]
async fn scrypt_verifies_pinned_runtime_vectors_and_normalizes_unicode() {
    // Produced with pinned @better-auth/utils/password.node.mjs parameters.
    let plain = "00112233445566778899aabbccddeeff:73122e887cfc14f91396cdef78dfe4b9dec28d459037601c4904cedba5a637ab97b39b40c236df5d42881d0109ca8cf0f85e39dbaba2911c190915bd8f30fe85";
    let unicode = "00112233445566778899aabbccddeeff:d891432b268618420fb652f0515c0fcf5ae943c484f883e35d18a14c683ded87c0e469ab0cbdca84868fdb3680e7059018c0a6f90060eb0d866934dacfeae6a5";
    assert!(verify_password(None, "password123", plain).await.is_ok());
    assert!(matches!(
        verify_password(None, "incorrect", plain).await,
        Err(AuthError::InvalidCredentials)
    ));
    assert!(verify_password(None, "Ａuth-é-🔒", unicode).await.is_ok());
    assert!(
        verify_password(None, "Auth-e\u{301}-🔒", unicode)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn scrypt_uses_random_hex_salt_and_rejects_malformed_or_changed_hashes() {
    let first = hash_password(None, "password123").await.expect("hash");
    let second = hash_password(None, "password123").await.expect("hash");
    assert_ne!(first, second);
    assert_eq!(first.len(), 32 + 1 + 128);
    assert!(
        first
            .split(':')
            .all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    );
    assert!(verify_password(None, "password123", &first).await.is_ok());
    assert!(matches!(
        verify_password(None, "password123", "bad").await,
        Err(AuthError::PasswordHash(_))
    ));
    assert!(matches!(
        verify_password(None, "password123", ":key").await,
        Err(AuthError::PasswordHash(_))
    ));
    assert!(matches!(
        verify_password(None, "password123", "salt:").await,
        Err(AuthError::PasswordHash(_))
    ));
    let altered = format!("{first}0");
    assert!(matches!(
        verify_password(None, "password123", &altered).await,
        Err(AuthError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn password_length_matches_utf16_code_units() {
    let context = AuthContext::new(
        Arc::new(crate::AuthConfig::new(
            "password-tests-only-minimum-32-character-secret",
        )),
        crate::test_store::test_database().await,
    );
    assert!(validate_password("éééé", 8, 128, &context).is_err());
    assert!(validate_password("🔒🔒🔒🔒", 8, 8, &context).is_ok());
    assert!(validate_password("🔒🔒🔒🔒", 8, 7, &context).is_err());
}
