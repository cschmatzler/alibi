---
title: "Sign in with Ethereum"
description: "Authenticate wallets with Sign-In with Ethereum (ERC-4361), with nonces, verification policies and ENS lookup."
---

`SiwePlugin` lets users sign in with an Ethereum wallet. The browser asks the wallet to sign an ERC-4361 message that contains a server-issued nonce; the server verifies the signature, links the wallet address to a user and issues a session. The bundled verifier supports **externally owned accounts** (EIP-191 personal sign); contract wallets and chain-specific checks are your responsibility through the `SiweVerifier` trait.

## Schema

```bash
alibi generate --plugins siwe -o src/auth_schema.rs
```

Adds the `wallet_address` table (`user_id`, `address`, `chain_id`, `is_primary`, `created_at`).

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::siwe::{Eip191Verifier, RandomSiweNonce};
use alibi::plugins::{SiweConfig, SiwePlugin};
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};
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

`SiweConfig::new(domain, nonce_provider, verifier)`; `domain` is the host wallets show to the user and that the signed message must contain.

## Flow and endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/siwe/nonce` (alias `/siwe/get-nonce`) | Issue a nonce (valid 15 minutes, single use) |
| `POST` | `/siwe/verify` | Verify `{ "message", "signature", "email"? }` and sign in |

1. The client requests a nonce: `POST /siwe/nonce` with an empty body → `{"nonce":"c2Vj…"}`.
2. The client builds the ERC-4361 message (domain, address, statement, URI, chain id, nonce) and has the wallet sign it.
3. The client posts `{"message":"…","signature":"0x…"}` to `/siwe/verify`. The server checks the domain, nonce and signature, consumes the nonce, finds or creates the user for the address and sets the session cookie.

```bash
curl -X POST http://localhost:3000/api/auth/siwe/nonce -H 'Origin: http://localhost:3000'
# {"nonce":"WT7pXf3sQ1uJ8Kc2LmRz0aVbNd4YhEgO"}
```

Nonces must be 8–250 ASCII alphanumeric characters. A first-time wallet gets a new user whose email is `<address>@<email_domain_name>` — or `<address>@siwe.placeholder.invalid` when you set no domain — whose name is the ENS name (when `ens_lookup` finds one) or the wallet address, and the address is stored as that user's primary wallet.

## Configuration

| `SiweConfig` field | Default | Effect |
| --- | --- | --- |
| `domain` | required | Expected message domain |
| `nonce_provider` | required | `SiweNonceProvider::get_nonce()`; `RandomSiweNonce` generates 32 random characters |
| `verifier` | required | `SiweVerifier::verify_message(SiweVerification)` — `Eip191Verifier` for EOAs |
| `email_domain_name` | none | Domain for generated emails (`<address>@<domain>`); without it, `<address>@siwe.placeholder.invalid` |
| `anonymous` | `true` | `true`: wallets need no email. `false`: `email` is required at verification |
| `ens_lookup` | none | `EnsLookup::lookup(address)` → `EnsProfile { name, avatar }` to fill the user's name and image |

When `anonymous` is `false`, an email is required — and an existing user with that email is **never** linked to a wallet by the email alone, so a stranger cannot take over an account by claiming its address.

### Support contract wallets (ERC-1271)

```rust
use async_trait::async_trait;
use alibi::plugins::siwe::{
    Eip191Verifier, SiweCallbackResult, SiweConfig, SiweVerification, SiweVerifier, RandomSiweNonce,
};
use std::sync::Arc;

struct Hybrid;

#[async_trait]
impl SiweVerifier for Hybrid {
    async fn verify_message(&self, input: SiweVerification) -> SiweCallbackResult<bool> {
        // Try the EOA check first; fall back to an `isValidSignature` call over your RPC.
        if Eip191Verifier.verify_message(input.clone()).await? {
            return Ok(true);
        }
        Ok(false) // call your JSON-RPC provider for chain `input.chain_id` here
    }
}

fn config() -> SiweConfig {
    SiweConfig::new("app.example.com", Arc::new(RandomSiweNonce), Arc::new(Hybrid))
}
```

`SiweVerification` provides the original `message`, the `signature`, the EIP-55 `address`, the numeric `chain_id` and a CAIP-122 `cacao` view. A callback can reject with `SiweCallbackError::Api(AuthResponse)` for a custom HTTP error or `Failed(message)` for provider failures, which become a generic `500`-style error.

## Security notes

- Nonces are bound to the server, expire after 15 minutes and are consumed on verification — replay fails.
- Always show wallet users **your** `domain` in the sign-in message; wallets warn on mismatches, and the server rejects them.
- Wallet addresses are case-insensitive hex; the server stores the EIP-55 checksummed form.

## Frontend

See the official [SIWE guide](https://www.better-auth.com/docs/plugins/siwe).
