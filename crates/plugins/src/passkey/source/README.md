# Passkey verification extensions

The registry `webauthn-rs` and `webauthn-rs-core` 0.5.4 crates supply protocol
types, challenge generation, COSE/OpenSSL key
conversion, certificate extension checks and signed TPM structure parsing.
They are pinned to keep the current ceremony protocol stable.

This private module owns the additional Better Auth / SimpleWebAuthn ceremony
policy. Upstream's public verifier cannot express its client-data admission,
certificate trust, SafetyNet, extended RSA and TPM rules. We verify original
client-data and authenticator bytes; we never rewrite a signed payload and retry
the registry verifier under weaker policy.

Only the extensions and the narrow private parsing/verification operations they
need live here. The upstream crates, high-level wrapper, fake credential
generator, general core verifier and upstream test suite are not copied.

`credential.rs` represents credentials reconstructed from the current TypeScript
columns, including variable-length RSA exponents. Authentication and registration
read only the current ceremony state. Older serialized credential blobs and
registry challenge variants are unsupported.
