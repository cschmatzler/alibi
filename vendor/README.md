# WebAuthn verifier extension

`webauthn-rs` and `webauthn-rs-core` are copied from crates.io 0.5.4, upstream
commit `282d95f20648090bc131cdd33cdced336c33c3d1`. They retain upstream authors,
notices and the MPL-2.0 license in each directory. Modified files remain MPL-2.0.
The wrapper's source is unchanged. Both packages have distinct Better Auth
package names so path and published dependencies use the same credential types;
a root-only Cargo patch would not propagate to downstream library consumers.

The core extension is opt-in for newly issued Better Auth Source-policy
ceremonies. Its default behavior remains upstream's, including the historical
registration and authentication state policy. The extension ignores the
`crossOrigin` client-data field in parsed policy, never changes the original
bytes covered by signatures, and implements the pinned SimpleWebAuthn 13.3.3
certificate roots and SafetyNet verification contract. Roots are copied from
that MIT-licensed published package; attribution accompanies the PEM files.

Review modifications against the pinned registry package, rather than treating
unmodified upstream code as newly authored verifier logic.
