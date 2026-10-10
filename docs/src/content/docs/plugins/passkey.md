---
title: "Passkey"
description: "WebAuthn passkeys: register, authenticate, manage credentials, and run passkey-first sign-up."
---

`PasskeyPlugin` implements the server side of WebAuthn. The browser creates and uses credentials with `navigator.credentials`; the server generates challenges, verifies attestations and assertions, stores public keys and issues sessions. Verification is built on `webauthn-rs` and covers the common attestation formats.

## Schema

```bash
alibi generate --plugins passkey -o src/auth_schema.rs
```

Adds the `passkeys` table (credential id, public key, counter, device type, backup state, transports, AAGUID, user id, name).

## Setup

Enable the opt-in `passkey` Cargo feature alongside your framework and database features:

```toml
alibi = { version = "0.4.0", features = ["axum", "passkey"] }
```

Passkey verification requires OpenSSL even when the `rustls` feature is selected. Applications without `passkey` can use Rustls without linking OpenSSL.

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::PasskeyPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            PasskeyPlugin::new()
                .rp_id("example.com")
                .rp_name("My application")
                .origin("https://app.example.com"),
        )
        .build()
        .await
}
```

- **`rp_id`** is the *relying party id*: the registrable domain the credential is bound to (`example.com`). It must equal, or be a registrable parent of, the origin's host. Changing it later orphans every existing passkey.
- **`origin`** is the exact origin that runs the WebAuthn ceremony (scheme, host, port). Use `https://` outside local development; `localhost` (with `http://localhost:3000`) is allowed for development.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/passkey/generate-register-options` | session (fresh) | Options for `navigator.credentials.create()`; query: `name`, `authenticatorAttachment` (`platform` or `cross-platform`), `context` |
| `POST` | `/passkey/verify-registration` | session | Verify the attestation and store the passkey. Body: `response`, optional `name`, `createSession` |
| `GET` | `/passkey/generate-authenticate-options` | — | Options for `navigator.credentials.get()` |
| `POST` | `/passkey/verify-authentication` | — | Verify the assertion, update the counter, issue a session. Body: `response` |
| `GET` | `/passkey/list-user-passkeys` | session | The user's passkeys |
| `POST` | `/passkey/update-passkey` | session | Rename: `{"id","name"}` |
| `POST` | `/passkey/delete-passkey` | session | Delete: `{"id"}` |

Both `generate-*` endpoints store the challenge for `challenge_ttl_secs` (default 300) and set a `better-auth-passkey` cookie that the matching `verify-*` call must send back; challenges are single use.

Registering a passkey for an existing user requires a **fresh** session ([`fresh_age`](/concepts/session-management/#session-freshness)); an older session gets `403 SESSION_NOT_FRESH`.

### Browser flow

With the official client (`@better-auth/passkey`) this is one call each:

```ts
await authClient.passkey.addPasskey({ name: "MacBook" });    // register
await authClient.signIn.passkey();                            // authenticate
```

Without the client, the same two steps with raw WebAuthn: `GET /passkey/generate-register-options` → `navigator.credentials.create({ publicKey })` → `POST /passkey/verify-registration` with the credential serialized as JSON, and the same for authentication with `get()`.

## Configuration

`PasskeyConfig` builder methods:

| Option | Default | Effect |
| --- | --- | --- |
| `rp_id(…)` | empty | Relying party id |
| `rp_name(…)` | `Better Auth` | Name shown by the authenticator |
| `origin(…)` | empty | Expected origin (empty falls back to the request origin) |
| `origins(Vec<String>)` | empty | Explicit allowlist of origins accepted in the signed client data |
| `authenticator_selection(PasskeyAuthenticatorSelection)` | preferred | Override `resident_key`, `user_verification`, and `authenticator_attachment` |
| `challenge_ttl_secs(…)` | `300` | Challenge lifetime |
| `web_authn_challenge_cookie(…)` | `better-auth-passkey` | Challenge cookie name |
| `attestation_root_certificates(…)` | built-ins | Per-format PEM roots (`BTreeMap<String, Vec<String>>`) for attestation verification; unspecified formats keep the published defaults |
| `registration(PasskeyRegistrationConfig)` | session required | Passkey-first registration (below) |
| `authentication(PasskeyAuthenticationConfig)` | none | Post-verification callback |

Both `PasskeyRegistrationConfig` and `PasskeyAuthenticationConfig` accept `extensions: Option<PasskeyExtensions>`. Use `Static(serde_json::Value)` for fixed WebAuthn inputs or `Resolver(Arc<dyn PasskeyExtensionsResolver>)` for an asynchronous application policy. Resolvers receive the request, auth configuration, context extensions, and authenticated user projection. They run before challenge creation; API rejections preserve their code and message, while ordinary failures return an empty 500. Registration always includes `credProps: true`, matching the upstream options generator.

### Passkey-first registration

By default registering a passkey needs a signed-in user. To let someone **create an account with a passkey** (no password, no prior session), disable `require_session` and tell the server which identity the new credential belongs to:

```rust
use async_trait::async_trait;
use alibi::plugins::{
    PasskeyConfig, PasskeyPlugin, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationUser, PasskeyUserResolver,
};
use alibi::AuthResult;
use std::sync::Arc;

struct InviteResolver;

#[async_trait]
impl PasskeyUserResolver for InviteResolver {
    // `requested_context` is the `context` query parameter, e.g. an invite token.
    async fn resolve_user(
        &self,
        _context: &PasskeyRegistrationContext<'_>,
        requested_context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationUser>> {
        let Some(invite) = requested_context else { return Ok(None) };
        // Look up the invite in your own storage here.
        Ok(Some(PasskeyRegistrationUser {
            id: format!("user-for-{invite}"),
            name: "new.user@example.com".into(),
            display_name: Some("New user".into()),
        }))
    }
}

fn plugin() -> PasskeyPlugin {
    PasskeyPlugin::with_config(PasskeyConfig {
        rp_id: "example.com".into(),
        origin: "https://app.example.com".into(),
        registration: PasskeyRegistrationConfig {
            require_session: false,
            resolve_user: Some(Arc::new(InviteResolver)),
            after_verification: None,
        },
        ..Default::default()
    })
}
```

Without a session, an unusable resolver result fails with `400 RESOLVED_USER_INVALID`; a missing resolver with `400 RESOLVE_USER_REQUIRED`. The optional `PasskeyRegistrationAfterVerification` callback runs after the credential verifies; it can return a `PasskeyRegistrationOverride` to reassign the passkey to another `user_id` or rename it — this is where you create the real user for a passkey-first sign-up. `PasskeyAuthenticationAfterVerification` runs after a successful assertion, before the counter and session are written. These traits take decoded client data as a `JsValue` from `alibi::utils::json`.

## Security notes

- Passkeys are phishing-resistant because the browser binds each credential to `rp_id`. Treat `rp_id` and `origin` as part of your security configuration.
- A `None` attestation proves nothing about the device; use it for consumer sign-in, and require stricter attestation (and restrict `attestation_root_certificates`) for high-assurance use.
- The signature counter is stored and checked; a replayed assertion is rejected.
- List the user's passkeys in your account settings so they can remove lost devices.

## Frontend

See the official [Passkey guide](https://www.better-auth.com/docs/plugins/passkey).
