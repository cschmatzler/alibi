---
title: "JWT"
description: "Issue signed JSON Web Tokens for other services and publish a JWKS for them to verify with."
---

Session tokens are opaque and only meaningful to this server. When another service — an API gateway, a microservice, a third-party backend — must verify identity **without calling you**, issue a JWT: a short-lived, signed token that carries the user's claims. `JwtPlugin` signs with a managed asymmetric key pair and publishes the public keys at a JWKS endpoint.

JWTs complement database sessions; they do not replace them. The session cookie stays your source of truth in the browser, and the JWT is for service-to-service calls.

## Schema

```bash
alibi generate --plugins jwt -o src/auth_schema.rs
```

Adds the `jwks` table (`public_key`, `private_key`, `alg`, `crv`, `created_at`, `expires_at`). Private keys are encrypted with the auth [secret](/reference/secrets/) unless you disable that.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::jwt::JwtPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(JwtPlugin::new())
        .build()
        .await
}
```

The first key pair is generated on first use.

## Endpoints

| Method | Path | Auth | Result |
| --- | --- | --- | --- |
| `GET` | `/token` | session | `{"token":"<jwt>"}` for the current user |
| `GET` | `/jwks` (configurable) | none | The public key set |

```bash
curl -b cookies.txt http://localhost:3000/api/auth/token
# {"token":"eyJhbGciOiJFZERTQSIsImtpZCI6IjQ1NmNkYTE2…"}

curl http://localhost:3000/api/auth/jwks
# {"keys":[{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","x":"OBhSpeRa3AjdEi-2jstuYK50VtXK0r2WfpQTgYwResc","kid":"456cda16-28f8-44f0-b043-57715adadbe8"}]}
```

Decoded, the default token looks like:

```json
// header
{"alg":"EdDSA","kid":"456cda16-28f8-44f0-b043-57715adadbe8"}
// payload
{"iat":1791108700,"exp":1791109600,"id":"35c48e8c-…","sub":"35c48e8c-…","name":"Ada","email":"ada@example.com","emailVerified":false,"image":null,"createdAt":"…","updatedAt":"…","iss":"http://localhost:3000","aud":"http://localhost:3000"}
```

The payload is the user object plus `sub`, `iss`, `aud` (both default to the base URL), `iat` and `exp` (15 minutes).

Every `GET /get-session` response also carries the JWT in a `set-auth-jwt` response header (exposed for CORS), so a client can obtain one without an extra round trip; turn that off with `disable_setting_jwt_header`.

## Verify in another service

Fetch the JWKS (cache it by `kid`), then verify signature, `iss`, `aud` and `exp`. In Rust with the `jsonwebtoken` crate:

```rust
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

fn verify(token: &str, jwk_x: &str) -> Result<serde_json::Value, jsonwebtoken::errors::Error> {
    let header = decode_header(token)?;
    assert_eq!(header.alg, Algorithm::EdDSA);
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["https://auth.example.com"]);
    validation.set_audience(&["https://api.example.com"]);
    let key = DecodingKey::from_ed_components(jwk_x)?;
    Ok(decode::<serde_json::Value>(token, &key, &validation)?.claims)
}
```

In any language, use a JWKS-aware library and validate issuer and audience. Never accept `alg: none` or let the token choose the algorithm.

## Configuration

`JwtPluginConfig` (with `JwtPlugin::with_config`):

| Field | Default | Effect |
| --- | --- | --- |
| `jwks_path` | `/jwks` | Where the key set is served |
| `key_pair` | `EdDSA` (Ed25519) | `JwtKeyPairConfig { algorithm, modulus_length }`; algorithms `EdDSA`, `ES256`, `ES512`, `PS256`, `RS256` |
| `additional_key_pairs` | none | Extra algorithms published alongside the primary key |
| `rotation_interval` | none | Rotate the signing key after this long; old keys stay published for `grace_period` |
| `grace_period` | 30 days | How long retired keys remain verifiable |
| `disable_private_key_encryption` | `false` | Store private keys unencrypted (not recommended) |
| `disable_setting_jwt_header` | `false` | Do not add `set-auth-jwt` to session responses |
| `session_cookie_cache` | `false` | Use the local JWT keyring to sign [JWT cookie caches](/concepts/cookies/#cache-the-session-in-a-cookie) |
| `claims` | issuer/audience = base URL, 15 min | `JwtClaimsConfig { issuer, audience, expiration }` (`JwtExpiration::After(Duration)` etc.) |
| `define_payload` | user fields | `DefineJwtPayload`: build the claim set from `JwtSession { user, session }` |
| `define_subject` | user id | `DefineJwtSubject` |
| `keyring` | database | `JwtKeyring`: your own key storage |
| `remote_signer`, `remote_url` | none | `SignRemoteJwt`: delegate signing to an HSM/KMS or remote service |

```rust
use async_trait::async_trait;
use alibi::plugins::jwt::{
    DefineJwtPayload, JwtAlgorithm, JwtAudience, JwtClaimsConfig, JwtExpiration, JwtKeyPairConfig,
    JwtPlugin, JwtPluginConfig, JwtSession,
};
use alibi::AuthResult;
use chrono::Duration;
use serde_json::{Map, Value, json};
use std::sync::Arc;

struct MinimalClaims;

#[async_trait]
impl DefineJwtPayload for MinimalClaims {
    // Keep tokens small: only what downstream services need.
    async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>> {
        let mut claims = Map::new();
        claims.insert("email".into(), json!(session.user.email));
        claims.insert("sid".into(), json!(session.session.id));
        Ok(claims)
    }
}

fn jwt() -> JwtPlugin {
    JwtPlugin::with_config(JwtPluginConfig {
        key_pair: JwtKeyPairConfig { algorithm: JwtAlgorithm::Es256, modulus_length: None },
        rotation_interval: Some(Duration::days(30)),
        claims: JwtClaimsConfig {
            issuer: Some("https://auth.example.com".into()),
            audience: Some(JwtAudience::One("https://api.example.com".into())),
            expiration: JwtExpiration::After(Duration::minutes(10)),
        },
        define_payload: Some(Arc::new(MinimalClaims)),
        ..Default::default()
    })
}
```

## Server-only operations

Sign arbitrary payloads and verify tokens from your own code through [`dispatch_endpoint`](/guides/server-side-calls/) — useful for service tokens and webhooks:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::BetterAuth;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::jwt::JwtPlugin;

async fn check(
    auth: &BetterAuth<AppAuthSchema>,
    token: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, Box<dyn std::error::Error>> {
    let output = auth
        .dispatch_endpoint(JwtPlugin::verify_endpoint(token, None), EndpointOptions::default())
        .await?
        .decode()?;
    Ok(output.payload) // None when the signature or claims are invalid
}
```

`JwtPlugin::sign_endpoint(payload)` signs a JSON payload with the current key; `token_endpoint()` and `jwks_endpoint()` mirror the HTTP routes.

## Security notes

- Rotate keys (`rotation_interval`) and keep `grace_period` at least as long as your longest-lived token.
- Keep tokens short-lived; JWTs cannot be revoked before `exp`. Use the session for anything that needs immediate logout.
- Put only the claims consumers need into the token — the default payload is the whole user object.
- Without a database ([No database](/databases/no-database/)), JWKS rows live in memory and keys change on restart.

## Frontend

See the official [JWT guide](https://www.better-auth.com/docs/plugins/jwt).
