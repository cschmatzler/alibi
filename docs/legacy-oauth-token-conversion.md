# Converting legacy native OAuth token rows

Better Auth 1.7.6 uses Source-format encrypted access/refresh tokens and plain
ID tokens. Earlier better-auth-rs installations wrote AES-256-GCM ciphertext
for all three fields, with HKDF-SHA256 (`better-auth-oauth-token-encryption`) and
standard base64 (`12-byte nonce || ciphertext || tag`). Live readers do not
recognize or automatically upgrade that older format.

Use `better_auth::plugins::oauth_token_conversion::OAuthTokenConversion` in a
private application-owned administrative program. There is no HTTP endpoint.
The physical SQLx and SeaORM stores implement `OAuthTokenConversionStore` for
application-owned `AuthEntity` account models. Handwritten account models must
explicitly provide `oauth_token_columns()` (access, refresh, ID order); models
without this mapping fail closed. Do not wrap the physical adapter with account
output transformations or expose this capability to client requests.

Before converting, back up the database and establish historical account
ownership from trusted installation records. **Legacy ciphertext has no
authenticated owner binding.** A current database owner, successfully decrypted
token, provider subject, or ciphertext shape cannot establish historical
ownership. If ownership or the original secret cannot be established, do not
convert that row; require the user to reconnect the provider through your
application's authenticated account-linking flow.

For each reviewed row, supply a `TrustedOAuthTokenManifest` containing its exact
physical row ID, owner ID, provider ID, provider account ID, and nullable token
values. Independently classify **every** field as `LegacyNative`, `Plain`,
`Source`, or `Absent`. Never classify by trying keys or inspecting string shape.
`Absent` means SQL NULL, not an empty string. `Source` is valid for access and
refresh tokens only; current ID tokens are `Plain`. A mixed installation can
explicitly mark plaintext or absent fields alongside legacy ciphertext.

```rust,ignore
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

Preparation authenticates all classified encrypted fields before any write.
Wrong secret, tamper, invalid UTF-8, or a NULL/classification mismatch rejects
that row. Plain access/refresh tokens are encrypted with the destination config;
legacy access/refresh tokens are decrypted and encrypted in Source format;
authenticated `Source` values are retained byte for byte. ID tokens become plain.
Preparation errors contain no token or secret values. Manifest and plan types
omit `Debug` to reduce accidental credential logging; keep them private.

Apply performs **one atomic compare-and-swap per account**, matching the observed
identity, owner, and all three nullable token values. A concurrent refresh,
reassignment, identity change, deletion, or token change makes it return `false`.
Only the three token columns are written: timestamps, expirations, passwords,
scope, and application-owned columns are preserved. Account-update hooks are
intentionally bypassed so they cannot mutate this operator-controlled write.
Database triggers still run; an ordinary statement failure rolls back all three
columns. Review installation-specific triggers before operating on real rows.
This is not a transaction across a multi-row manifest.

A failed statement can be retried with the same plan. After a successful apply,
reapplying the original legacy plan returns `false` and does not overwrite newer
state. If the result is uncertain because the connection was lost, inspect a
new physical snapshot and reconcile it against the reviewed manifest before
retrying. For an already-converted row, explicitly mark access/refresh `Source`
and ID `Plain`; it can be validated and applied without changing token bytes.
A conflict is never resolved by accepting a new owner automatically. Reconcile
ownership and classifications explicitly before preparing another plan. Exact
value CAS cannot detect an ABA change that restored every observed value; stop
writers for the maintenance window if historical write sequencing matters.

The focused native regression uses disposable populated SQLite databases and
real application-owned models with both adapters. It covers legacy decryption,
Source authentication, plain/NULL handling, failure rollback, retries, side-pool
refresh/reassignment/identity changes, and untouched physical columns. It does
not migrate real users or claim a differential Source upgrade API: conversion
is an explicit native administrative capability. Existing pinned runtime token
encoding and reader behavior remain unchanged.
