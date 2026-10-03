---
title: "Secrets and key rotation"
description: "Configure managed encryption keys and signed credentials."
---

Use managed secrets when you need to rotate encryption keys without immediately rejecting older encrypted records:

```rust
use better_auth::{AuthConfig, ManagedSecrets};

fn auth_config(current: &str, previous: &str) -> AuthConfig {
    let keys = ManagedSecrets::new(2, current).retain(1, previous);
    AuthConfig::default().managed_secrets(keys)
}
```

The current key must contain at least 32 bytes. Generate secrets with `openssl rand -base64 32` and store them outside source control.

## Rotate a key

1. Select a new version and key with `ManagedSecrets::new`.
2. Retain the old versions while encrypted factor secrets, OAuth credentials, JWKS keys, and outstanding proofs still need them.
3. Migrate or expire those records before removing the old versions.

New writes use the current version. Reading old ciphertext does not rewrite it. Removing a reader rejects its ciphertext and can lock out users whose factors still depend on it.

Signed cookies and verification JWTs use only the current key. Rotating it invalidates those signatures even when you retain the old encryption key.

## Migrate single-secret encryption

Add `.legacy(previous_secret)` to read ciphertext written before managed secrets. Remove it after migration. Managed mode ignores `AuthConfig.secret`; application callbacks should use `current_secret()`.

For OAuth token encryption, use `encrypt_token_with_config`, `decrypt_token_with_config`, `maybe_encrypt_with_config`, and `maybe_decrypt_with_config`. The older helpers that accept a single secret do not read the managed keyring.
