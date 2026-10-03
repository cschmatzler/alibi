---
title: "Two-factor authentication"
description: "TOTP, email OTP challenges, and backup codes for a second authentication factor."
---

`TwoFactorPlugin` adds a second authentication factor through TOTP, email OTP challenges, and backup codes.

## Setup

```bash
better-auth-rs generate --plugins two-factor -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::TwoFactorPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(TwoFactorPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

The backend exposes enrollment at `/two-factor/enable` and verification at `/two-factor/verify-totp`, `/two-factor/verify-otp`, and `/two-factor/verify-backup-code`.

Use `custom_send_otp` for email delivery. Keep old encryption keys available until encrypted factor secrets and outstanding proofs have migrated or expired; see [key rotation](/reference/secrets/).

## Frontend

See the official [Two-factor authentication guide](https://www.better-auth.com/docs/plugins/2fa).
