# Advertised Ed25519 registration and authentication

Pinned `@better-auth/passkey@1.7.6` advertises COSE algorithms [-8,-7,-257].
Its SimpleWebAuthn13.3.3 verifier accepts genuine Ed25519 OKP credentials,
including none attestation and packed self-attestation with UV absent. Our new
Core registration state still used locked webauthn-rs-core0.5.4's secure_algs,
which contains only ES256 and RS256. The library's typed OKP/OpenSSL Ed25519
signature implementation already exists: the allowed list rejected the genuine
credential after verification. This was an actual advertised capability gap.

## Production scope

Only newly issued Core registration states now receive the exact advertised
list EDDSA, ES256, RS256. Existing public options stay unchanged. The genuine
stored state and single original-byte attestation verification remain authoritative;
original owner, credential ID/key, transports, callback order, atomic enrollment
and session issuance retain their existing behavior. No weakened verification,
retry, request-selected principal, dependency upgrade or crypto implementation
is added. Historical pending states retain their original algorithm/UV policy
until consumed or expired. No dependency, lock, inventory or shared store change
belongs to this capability commit.

Source treats both a valid-length false Ed25519 signature and a one-byte signature
as false verification: packed registration is coded400 FAILED_TO_VERIFY_REGISTRATION,
and authentication is coded401 AUTHENTICATION_FAILED. This differs from malformed
ES256 DER, which throws during registration and returns coded500. The existing
Core typed invalid-signature branch produces the Ed25519 response without broad
exception remapping. Its comment now names the algorithm-dependent distinction.

## Meaningful primary proof

The existing registration lifecycle table gains two algorithm-specific owners,
none and genuine signed packed Ed25519 attestation. The software authenticator's
typed algorithm choice defaults to its original ES256 key. Ed25519 uses a genuine
32-byte OKP public key (kty1/alg-8/curve6) and raw64-byte signatures over the actual
authenticator data and SHA256 of original clientDataJSON. No callback receipt or
verification result is supplied by this helper.

Actual authenticated-owner enrollment proof is issued by the existing application
fixture, then registration resolves that owner after sign-out. Client foreign
user/context fields cannot choose another account. Full callback input equals
the actual serialized official-client registration request, and actual rows and
session token/ID/user ownership are retained. A later genuine Ed25519 assertion
creates the original owner's session and advances the stored public counter to1.
Foreign account/session/user state remains unchanged. Registration replay burns
the same challenge and is400.

The existing invalid-proof owner additionally exercises Ed25519 false64-byte and
malformed1-byte packed signatures and an actual foreign signed session. Rejected
attempts do not run the verification callback or write credentials/sessions; the
whole observed owner/foreign state remains unchanged and each challenge is consumed.
The packed Ed25519 owner then submits false64-byte and malformed1-byte signed
assertions with counter2: both401, replay400, saved counter/credential/session and
owner state unchanged. Exact captured serialized request bodies equal those
actual submitted proofs, including replay. All complete primary transport traces
remain in comparison.

Client data and attestation CBOR remain reversible, exact local byte round-trips;
all keys, algorithms and authenticator data remain. Authentication proofs retain
all fields. Generated handles are tied to actual registration options.user.id,
with exact base64url/decoded-ID roundtrip; signature bytes use the existing token
bijection in both submitted and proof observations. Literal signature lengths64
and1 are asserted locally. No comparator exception, digest or observation drop
is added. The first Source-self run failed only an initially literal generated
userHandle observation; the corrected reversible identity container uses the
existing prior authentication-policy observation contract. That setup correction
is excluded from production baseline evidence.

## Exact evidence

`/tmp/passkey-eddsa-source-oracle.log` retains actual pinned official-client
registration options, complete genuine proofs, callback inputs and real SQLite
rows, replay and later signed authentication. None/packed UV absent, packed UV
present and backed credentials succeed; independent false/malformed signatures,
UP/RP/backup flags/challenge/origin/key controls distinguish rejection stages.
This standalone script is an investigation artifact, not a new gate owner.

Before the production repair, the two new Ed25519 owners fail0/2 on the frozen
3bd147e binary with intended registration500 instead of success:
`/tmp/passkey-eddsa-sdk-before-corrected.log`. Source-self corrected6/1032 passes
in `/tmp/passkey-eddsa-source-self-corrected.log`; the earlier raw-handle setup
failure is preserved separately in `...source-self-before.log`.

Final focused6/958 and whole passkey31/3136 pass in
`/tmp/passkey-eddsa-sdk-final.log` and `/tmp/passkey-eddsa-family-final.log`.
Repeated Source-to-Source12/1916 passes in `...source-repeat-final.log`.
Existing native passkey11 tests pass in `...native-final.log`, preserving the
separate historical pending-state codec/policy risk. No redundant primitive
native Ed25519 test is added because the official-client lifecycle is its primary
owner. API and fixture strict Clippy, required client TypeScript, formatting and
diff checks pass in `...clippy-final.log`, `...fixture-clippy-final.log`,
`...typecheck-final.log` and `...format-final.log`.

## Explicit remaining boundaries

This proof closes Ed25519 curve6 within the existing advertised algorithms. It
does not establish all EdDSA curves or every possible key encoding. Locked Core
also parses/verifies Ed448 curve7, while Source verifyOKP accepts only curve6 and
throws for other curves. An independent genuine Ed448 Node-generated fixture probe through the actual
pinned Bun handler (`/tmp/passkey-ed448-source-oracle.log`) confirms that none
registration succeeds and writes a credential/callback, but later genuine Ed448
authentication is400. Packed Ed448 self-attestation is500 before callback/write;
registration replay is400 in both cases. Bun1.4.2 itself cannot generate an
Ed448 fixture key; the probe uses static Node code and argv (no shell/evaluated
input) solely for genuine local key/signature generation. The initial Node argv
setup failure is preserved in `...source-oracle-setup-error.log`, excluded from
runtime evidence. The current advertised list change does not add an
Ed448-specific policy guard, and these Source distinctions are not exercised
by this commit's SDK owners. Unsupported curve/OKP algorithm mismatch is next.
Other wider attestation/certificates, extensions/tokenBinding/crossOrigin,
uncaptured duplicate-exclusion branches and old pending-state policies retain
all limits recorded in passkey-registration-policy.md. This is not universal
algorithm or passkey parity. Coordinator owns canonical gates, inventory,
lock integration and publication.
