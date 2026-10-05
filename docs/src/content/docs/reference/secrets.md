---
title: "Secrets and key rotation"
description: "Configure the auth secret, rotate encryption keys with managed secrets, and understand what each key protects."
---

## One secret

The simplest configuration is a single secret of **at least 32 characters** (`build()` rejects anything shorter):

```rust
use better_auth::AuthConfig;

fn auth_config() -> Result<AuthConfig, std::env::VarError> {
    Ok(AuthConfig::new(std::env::var("BETTER_AUTH_SECRET")?))
}
```

Generate one with `openssl rand -base64 32` and keep it out of source control. The library never reads the environment on its own.

The secret does two jobs:

| Job | What | Rotation effect |
| --- | --- | --- |
| **Signing** | Session cookies, cookie caches (`Compact`/`Jwt`), verification JWTs (email verification links), OAuth state cookies, trusted-device and challenge cookies | Changing the secret **invalidates** every existing signature — users are signed out, links stop working |
| **Encryption** | OAuth access/refresh tokens, two-factor secrets and backup codes, encrypted OTPs, JWKS private keys, JWE session caches, OAuth proxy payloads | Existing ciphertext becomes unreadable unless the old key is kept as a *reader* |

## Managed secrets

To rotate **encryption** keys without losing data, use versioned keys:

```rust
use better_auth::{AuthConfig, ManagedSecrets};

fn auth_config(current: &str, previous: &str) -> AuthConfig {
    let keys = ManagedSecrets::new(2, current) // new writes use version 2
        .retain(1, previous);                  // version 1 remains a reader
    AuthConfig::default().managed_secrets(keys)
}
```

- `ManagedSecrets::new(version, key)` sets the **current** version used for all new ciphertext.
- `.retain(version, key)` keeps an older version readable. Reading old ciphertext does not rewrite it.
- `.legacy(key)` additionally reads *bare* ciphertext written before managed secrets existed (with the old single secret).
- `.retire(version)` drops a reader (the current version cannot be retired). Anything still encrypted with it becomes unreadable.

In managed mode `AuthConfig.secret` is ignored; use `config.current_secret()` in application callbacks that need the signing key. The current key must be at least 32 bytes.

**Signed values always use only the current key.** Cookies and verification JWTs signed under version 1 stop verifying as soon as version 2 becomes current, even though version 1 is still a reader for encryption.

## Rotate a key

1. Generate the new key and choose a new version number (`3`).
2. Deploy `ManagedSecrets::new(3, new).retain(2, current).retain(1, older)`. New writes use version 3; older ciphertext still decrypts. Users are signed out once (signatures changed).
3. Let records migrate or expire: tokens rewritten on refresh, OTP codes and verification values (minutes), two-factor secrets and OAuth tokens (when the user next re-saves or reconnects), JWKS keys (rotate through the [JWT plugin](/plugins/jwt/)).
4. Only then `.retire(…)` the old versions — retiring early locks out users whose factors still depend on them.

Moving from a plain single secret: start with `ManagedSecrets::new(1, new).legacy(old_secret)`; after the data has migrated, drop `.legacy`.

## Using the secret in your own code

For OAuth token encryption in your own tooling, use the helpers that understand managed keys: `encrypt_token_with_config`, `decrypt_token_with_config`, `maybe_encrypt_with_config` and `maybe_decrypt_with_config`. The older helpers that take a single secret string do not read the managed keyring.

## Operational advice

- Store secrets in your platform's secret manager, not in images or git.
- Use a **different secret per environment**; a staging secret must not open production cookies.
- Treat a leaked secret as a full compromise of signed state: rotate it immediately and expect everyone to sign in again.
- With the [OAuth proxy](/plugins/oauth-proxy/), hosts must agree on a shared `secret`.
