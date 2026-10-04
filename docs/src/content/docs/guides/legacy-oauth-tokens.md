---
title: "Legacy OAuth token conversion"
description: "Operator guide: convert OAuth token rows written by early better-auth-rs versions to the current Better Auth 1.7.7 format."
---

This is an **operator procedure** for installations that stored OAuth provider tokens with an earlier version of this library. New installations never need it, and nothing converts rows automatically.

## When you need it

Better Auth 1.7.7 stores **access and refresh tokens** encrypted in its "Source" format and **ID tokens in plain text**. Earlier better-auth-rs versions wrote AES-256-GCM ciphertext for all three fields, with HKDF-SHA256 (`better-auth-oauth-token-encryption`) and standard base64 (`12-byte nonce || ciphertext || tag`). Current readers neither recognize that older format nor upgrade it, so linked-provider tokens from those installations cannot be read until they are converted — or the user reconnects the provider.

Conversion is an explicit, native **administrative capability**. It is not an HTTP endpoint, and it does not claim differential parity with an upstream upgrade API.

## Before you start

1. **Back up the database.**
2. **Establish historical ownership** of every account row from trusted installation records. Legacy ciphertext has **no authenticated owner binding**: the current owner of the row, a token that decrypts successfully, the provider subject, or the shape of the ciphertext prove nothing about who the token historically belonged to.
3. If ownership or the original secret cannot be established, **do not convert that row.** Have the user reconnect the provider through your application's authenticated account-linking flow instead.
4. Use a **private, application-owned administrative program**. Do not expose this capability to client requests, and do not wrap the physical adapter with account output transformations.
5. Check what the stores support: the physical SQLx and SeaORM stores implement `OAuthTokenConversionStore` for application-owned `AuthEntity` account models. Handwritten account models must explicitly provide `oauth_token_columns()` (access, refresh, ID order); models without this mapping fail closed.
6. Review database triggers on the `accounts` table (see [Triggers](#triggers)).

## Procedure

For each reviewed row, build a `TrustedOAuthTokenManifest` containing:

- the exact physical row id, owner id, provider id and provider account id;
- the nullable token values observed in the row;
- an **independent classification of every field** as `LegacyNative`, `Plain`, `Source` or `Absent`.

Never classify by trying keys or inspecting string shape.

| Classification | Meaning |
| --- | --- |
| `LegacyNative` | Old AES-256-GCM ciphertext written by an earlier version |
| `Plain` | Plain text (current ID tokens; mixed installations may also hold plain access/refresh tokens) |
| `Source` | Current encrypted format. Valid for access and refresh tokens only |
| `Absent` | SQL `NULL` — **not** an empty string |

```rust nocheck
use better_auth::plugins::oauth_token_conversion::{
    OAuthTokenConversion, OAuthTokenSnapshot, OAuthTokenValues,
    TokenEncoding, TrustedOAuthTokenManifest,
};

// These values come from your private, reviewed ownership manifest and a
// physical snapshot. Read secrets from your normal private secret provider.
let manifest = TrustedOAuthTokenManifest {
    observed: OAuthTokenSnapshot {
        id: reviewed_row_id,
        user_id: independently_verified_owner_id,
        provider_id: reviewed_provider_id,
        account_id: reviewed_provider_account_id,
        tokens: OAuthTokenValues {
            access_token: observed_access_token,
            refresh_token: observed_refresh_token,
            id_token: observed_id_token,
        },
    },
    access_encoding: TokenEncoding::LegacyNative,
    refresh_encoding: TokenEncoding::LegacyNative,
    id_encoding: TokenEncoding::LegacyNative,
};
// Destination config must have account.encrypt_oauth_tokens = true. Managed
// secrets, if configured, select the new Source envelope's current version.
let plan = OAuthTokenConversion::prepare(manifest, &original_secret, &config)?;
let applied = plan.apply(&physical_store).await?;
```

`apply` returns `true` when the row was converted and `false` when a conflict made it skip the write (see below).

## What preparation does

Preparation authenticates **every** classified encrypted field before any write. A wrong secret, tampering, invalid UTF-8, or a NULL/classification mismatch rejects that row. Then:

- plain access/refresh tokens are encrypted with the destination config;
- legacy access/refresh tokens are decrypted and re-encrypted in the Source format;
- authenticated `Source` values are retained **byte for byte**;
- ID tokens become plain.

Preparation errors contain no token or secret values. The manifest and plan types deliberately omit `Debug` to reduce accidental credential logging — keep them private.

## What apply does

Apply performs **one atomic compare-and-swap per account, in an explicit transaction**. It matches the observed identity, owner and all three nullable token values; if a concurrent token refresh, reassignment, identity change, deletion or token change happened in between, it returns `false` and writes nothing.

- Only the three token columns are written. Timestamps, expirations, passwords, scope and application-owned columns are preserved.
- Account-update hooks are intentionally **bypassed**, so they cannot mutate this operator-controlled write.
- There is no transaction across a multi-row manifest; each row stands alone.

### Triggers

Database triggers still run. The adapter rolls back its transaction on a statement error — including SQLite `RAISE(FAIL)` after a trigger has already changed a token. Review installation-specific triggers before operating on real rows.

## Failure and retry

- A failed statement can be retried with the same plan.
- After a successful apply, re-applying the original legacy plan returns `false` and does not overwrite newer state.
- If the result is uncertain because the connection was lost, take a **new physical snapshot** and reconcile it against the reviewed manifest before retrying.
- For an already-converted row, mark access/refresh as `Source` and the ID token as `Plain`; it validates and applies without changing token bytes.
- A conflict is never resolved by accepting a new owner automatically. Reconcile ownership and classifications explicitly, then prepare another plan.
- Exact-value CAS cannot detect an ABA change that restored every observed value. Stop writers for the maintenance window if historical write sequencing matters.

## What is tested

The focused native regression uses disposable populated SQLite databases and real application-owned models with both adapters. It covers legacy decryption, Source authentication, plain/NULL handling, failure rollback, retries, side-pool refresh/reassignment/identity changes, and untouched physical columns. It does not migrate real users. The pinned runtime's token encoding and reader behavior are unchanged.

See also [Social sign-on → token storage](/authentication/social-sign-on/#token-storage) and [Secrets and key rotation](/reference/secrets/).
