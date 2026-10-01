use super::*;

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
#[test]
fn test_encrypt_decrypt_roundtrip() {
    let secret = "a]vt!MFX8H-e!4igKa5)Tu.{ec:2$z%n";
    let plaintext = "ya29.a0AfH6SMBx-some-access-token";

    let encrypted = encrypt_token(plaintext, secret).unwrap();
    assert_ne!(encrypted, plaintext);

    let decrypted = decrypt_token(&encrypted, secret).unwrap();
    assert_eq!(decrypted, plaintext);
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
#[test]
fn test_maybe_encrypt_none() {
    let result = maybe_encrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
    assert!(result.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
#[test]
fn test_maybe_encrypt_disabled() {
    let token = "plain-token".to_owned();
    let result = maybe_encrypt(Some(token.clone()), false, "secret").unwrap();
    assert_eq!(result, Some(token));
}

// Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
#[test]
fn test_maybe_decrypt_none() {
    let result = maybe_decrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
    assert!(result.is_none());
}
