# Pinned encrypted-key interoperability fixture

`typescript-1.7.7-encrypted-jwk.json` contains a JWK row encrypted by the
published Better Auth 1.7.7 runtime, plus the exact EdDSA token it signed. The
secret and identity are local test values. The Rust test imports that unchanged
row into SQLite and exercises the public typed signing API; it compares the
result to the upstream signature and rejects a changed encryption secret.

Regenerate deliberately from the repository root after installing the frozen
reference-server dependencies:

```sh
devenv shell -- bun tests/fixtures/jwt/generate-typescript-fixture.mjs > tests/fixtures/jwt/typescript-1.7.7-encrypted-jwk.json
```

Generation creates a real random key and cipher nonce, so review fixture changes.
The generator invokes a private server-only endpoint; no public auth route is
added. Do not generate this reference fixture with Rust encryption or signing.
