# Stage-specific Ed448 passkey policy

This capability follows frozen Ed25519 admission6f7df290. Actual published
@better-auth/passkey1.7.6/SimpleWebAuthn13.3.3 runtime distinguishes a none
attestation from packed self-attestation. A genuine Ed448 OKP credential
(kty1/alg-8/curve7, public key57bytes) enrolls with none attestation, invokes the
registration callback, and can create the resolved owner's session. A later
genuine114-byte Ed448 signed assertion is coded400 AUTHENTICATION_FAILED because
Source's OKP signature helper only supports curve6. Genuine packed Ed448
self-attestation throws into coded500 FAILED_TO_VERIFY_REGISTRATION before the
callback or credential/session creation. Signature corruption and a one-byte
signature retain those same stage-specific curve failures; each challenge burns.

## Actual runtime and production boundary

`/tmp/passkey-ed448-source-oracle.log` retains actual official-client handler
responses, complete proofs/callback inputs and real SQLite rows for both paths.
Node's genuine Ed448 fixture key/signatures were needed for that separate probe
because Bun1.4.2 key generation does not support Ed448. Static executable code
and separate argv (never shell or evaluated input) generate only a local synthetic
key/proof. Initial fixture argv setup failure remains in
`/tmp/passkey-ed448-source-oracle-setup-error.log`, excluded from production proof.
Committed SDK helper uses already pinned noble-curves2.0.1 Ed448 directly;
no Node process or new package belongs to the tests or production.

Production is confined to the existing NEW-Core completion methods in
passkey/webauthn.rs. Before packed self-attestation (exact fmt packed, no x5c),
non-mutating original CBOR inspection feeds the public typed
AuthenticatorData<Registration> parser and reads its genuine acd.credential_pk.
Only OKP/EDDSA with a curve other than6 is rejected with typed
COSEKeyEDDSAInvalidCurve; its existing registration catch is coded500.
None attestation retains its original Core protocol/credential verification and
allows the genuine Ed448 credential. Authentication inspects the genuine stored
typed Credential.cred.key and rejects unsupported OKP curves with the same typed
error into its existing400 before callback/counter/session writes.

No request key/ID/owner is substituted, no signed byte/state is rewritten, no
weaker retry exists, and no rejected proof gains authority. Valid Ed25519/ES256
proofs still reach one genuine original-byte Core verifier. Pending historical
high-level ceremonies retain their original path/policy. Certificate-backed
attestations and other formats do not enter this exact packed-self guard.
No public API, shared store, entity, dependency, lock, fixture server, comparator
or inventory change belongs to this capability.

## Primary tests and meaningful failures

Two new official-client owners reuse the existing real enrollment helpers rather
than new application seams. Actual authenticated-owner signed enrollment proof
selects the registration owner after sign-out. None registration submits foreign
client owner/context fields, but the callback, stored row and real issued session
belong to the original owner. Callback input equals the full actual serialized
SDK registration request locally. Full public passkey rows are retained, followed
by actual sign-out and whole owner/foreign state snapshots.

Authentication goes through the already existing passkey-auth-accept application
profile: its genuine configured afterVerification event array stays empty for
genuine114-byte, false114-byte and short1-byte assertions. All three400, no cookie,
no saved counter/session/owner change, replay400. The failed assertions have
counter1 while the retained credential remains0. Complete captured serialized
requests/replays equal the actual issued proof. Foreign state stays unchanged.
This explicitly proves no authentication callback instead of relying on a profile
without one. Existing configured-callback positive owners in the full family
prevent a blanket rejection from satisfying that control.

Packed self-attestation submits a genuine Ed448 signature, then a corrupted
signature and a one-byte signature. Their actual decoded CBOR signature lengths
are asserted114/114/1; every attempt500 with no callback verification receipt,
credential/session write or cookie. Only the actual resolver receipt appears;
replay400 and full owner/foreign observations remain unchanged. The genuine packed
proof succeeded in the baseline Rust verifier, independently proving the fixture
was a real cryptographic success rather than an unrelated malformed input.

All actual primary transport entries remain. Existing reversible observations
retain every clientDataJSON/CBOR field and exact local re-encoding bytes; signature
bytes retain the existing token graph, and generated handles are tied exactly
to original registration options.user.id with encoded/decoded-ID preservation.
No digest, array sorting, ignored field or comparator exception is introduced.

`/tmp/passkey-ed448-sdk-before-final.log` is0/2 against frozen6f7df290: Rust
unexpectedly accepts genuine Ed448 login and packed self-attestation while Source
rejects at the measured phases. `/tmp/passkey-ed448-source-self-final.log` is the
initial strengthened Source-to-Source2/314 control. Final focused2/320 and full
passkey33/3456 pass in `/tmp/passkey-ed448-sdk-final.log` and
`/tmp/passkey-ed448-family-final.log`. Source repetition6/960 passes in
`...source-repeat-final.log`. Existing native passkey11 (including historical
pending state codec/policy) pass in `...native-final.log`; required client TSC,
API and fixture strict Clippy, formatting and diff checks pass in
`...typecheck-final.log`, `...clippy-final.log`, `...fixture-clippy-final.log` and
`...format-final.log`. No redundant primitive native curve test is added: the
SDK protocol/lifecycle owners detect both real incorrect admissions.

## Explicit next gaps

Actual Source probe `/tmp/passkey-unsupported-curve-source-oracle.log` shows
unknown curve8 with a32-byte OKP key: none registration admits it, later login400,
packed500. Core rejects that registration because it cannot create the typed key.
`/tmp/passkey-okp-algorithm-mismatch-source-oracle.log` shows a real Ed25519 key
(curve6) declaring alg-7: Source none/packed registration and genuine Ed25519
login all succeed. Core rejects this incompatible key/algorithm pairing. These
require a distinct raw-key/verification representation contract; this commit does
not fabricate a typed Credential or normalize original signed bytes to conceal
them. Float/string COSE tags, wider algorithms/curves/key encodings, attestation
certificates/extensions and historical pending policies retain their existing
unclosed boundaries. No universal EdDSA or passkey parity is claimed.
Coordinator owns canonical gates, inventory, dependency integration and publication.
