---
title: "Sign in with Ethereum"
description: "Use application-owned nonce and wallet verification policies."
---

`SiwePlugin` authenticates Ethereum wallet identities. The bundled verifier supports externally owned accounts; contract wallets need an application verifier.

## Setup

Generate the plugin schema and apply it with your application migrations:

```bash
better-auth-rs generate --plugins siwe -o src/auth_schema.rs
```

Build the auth instance with the generated schema and your configured store:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::siwe::{Eip191Verifier, RandomSiweNonce};
use better_auth::plugins::{SiweConfig, SiwePlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use std::sync::Arc;

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(SiwePlugin::new(SiweConfig::new(
            "app.example.com",
            Arc::new(RandomSiweNonce),
            Arc::new(Eip191Verifier),
        )))
        .build()
        .await
}
```

## Options

The domain must match your application's expected signing domain. Implement `SiweVerifier` for chain-specific RPC or ERC-1271 contract-wallet checks. `SiweConfig` also accepts an ENS lookup callback.

Disabling anonymous mode requires an email. Matching an email alone never links an existing identity to a wallet.

## Frontend

See the official [SIWE guide](https://www.better-auth.com/docs/plugins/siwe).
