# Passkey verification extensions

The registry `webauthn-rs` and `webauthn-rs-core` 0.5.4 crates supply protocol
types, challenge generation, legacy ceremony verification, COSE/OpenSSL key
conversion, certificate extension checks and signed TPM structure parsing.
They are pinned because their serialized challenge and credential formats are
part of our existing persisted data contract.

This private module owns the additional Better Auth / SimpleWebAuthn ceremony
policy. Upstream's public verifier cannot express its client-data admission,
certificate trust, SafetyNet, extended RSA and TPM rules. We verify original
client-data and authenticator bytes; we never rewrite a signed payload and retry
the registry verifier under weaker policy.

Only the extensions and the narrow private parsing/verification operations they
need live here. The upstream crates, high-level wrapper, fake credential
generator, general core verifier and upstream test suite are not copied.

`credential.rs` preserves the previously issued core credential shape, including
variable-length RSA exponents. `raw_none.rs` retains its existing raw credential
codec. New ceremonies use the local verifier; already-issued legacy ceremonies
use the registry verifier. Protocol types exposed by application callbacks stay
the registry types. Reading policy from serialized registry states and building
the registry authentication result through its supported serialization preserve
these boundaries without patching dependency internals.

The retained verification routines derive from webauthn-rs 0.5.4, upstream commit
`282d95f20648090bc131cdd33cdced336c33c3d1`, by William Brown and Michael Farrell,
and the Better Auth extensions formerly maintained in the repository's fork.
Derived files remain MPL-2.0; see `LICENSE.md`. The API package declares both
licenses. The pinned verifier has empty default certificate-root lists; configured
application trust anchors and their validation rules are preserved.

`tests.rs` verifies independently signed certificate vectors, original-byte
binding, trust rejection and a credential serialized by the removed fork.
Public handler/store tests separately own challenge consumption and persistence.
Run them with `cargo nextest run -E 'test(passkey)'`.
