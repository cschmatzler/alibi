# Typed registration verification without a UV requirement

Pinned `@better-auth/passkey@1.7.6` generates preferred UV/none attestation
registration options and calls SimpleWebAuthn `verifyRegistrationResponse` with
`requireUserVerification:false`. Both none attestation and genuine ES256 packed
self-attestation with UV absent succeed; a subsequent real signed assertion uses
that registered key. The existing high-level webauthn-rs0.5.4 registration state
instead requires UV even though our public options already say preferred.

## Actual source evidence

`/tmp/passkey-registration-policy-oracle.log` retains complete official-client
observations from actual pinned handler/SQLite registration, callback and later
signed authentication. None/packed UV absent, packed UV present, and packed
UV-absent backup-eligible/backed-up credentials succeed. UP absent, invalid BS/BE,
wrong RP/challenge/origin host/port/case and malformed COSE throw: the source catch
returns coded500 FAILED_TO_VERIFY_REGISTRATION. A correctly DER-encoded but
cryptographically false packed signature makes verification return false and
returns the same code with400. The SDK owner additionally proves malformed DER
throws500, instead of being collapsed into that false-signature400.

## Bounded production contract

New registrations use the already locked direct webauthn-rs-core0.5.4 API:
new_challenge_register_builder, Preferred UV, None attestation, synchronized
credentials allowed, preserved existing exclude IDs and supported algorithms,
then generate_challenge_register. The existing renderer still emits the exact
Source wire choices, generated handle, options and extensions. No dependency
upgrade or new dependency/lock change belongs to this commit.

The original stored outer user_id/user/context fields retain server authority.
The state field accepts the historical PasskeyRegistration encoding unchanged or
a new tagged `{kind:"core",state:RegistrationState}` encoding. Only newly issued
Core ceremonies select the new policy. Legacy pending ceremonies keep their
original high-level Required policy and previous verification path until they
expire or are consumed. A distinct native owner serializes a real old high-level
challenge in its historical outer encoding, decodes it through the new wrapper,
and verifies a real ES256 COSE none attestation: UV present succeeds and UV absent
still fails specifically UserNotVerified. This proves codec/policy preservation;
it does not claim an actual live-process software-upgrade deployment test.

Core completion checks the original clientDataJSON's raw origin against the exact
configured string, then performs ONE register_credential against the genuine
stored state and original response. It converts the actual typed Credential to
Passkey via the existing public feature. No private state surgery, weakened retry,
request-derived key/owner or synthetic verified flag exists. Core retains UP,
RP hash, challenge, COSE and attestation-signature checks and rejects invalid
BS=true/BE=false. Only Core's typed AttestationStatementSigInvalid maps to source's
false-verification400; malformed DER and other verifier exceptions preserve500.
All existing callback/application-error/transaction/session ordering remains.

## Primary tests and evidence

Four dedicated official-client owners cover none UV absent, packed UV absent,
packed UV absent with backup flags, and real invalid-proof/foreign-owner controls.
The positive owners use actual authenticated-owner-issued signed enrollment proof,
then sign out, use actual resolver context, verify, await callback and create the
original owner's session. Forged client user/context fields cannot choose the
foreign account. Full callback input equals the actual captured serialized SDK
request locally. Complete results, full signed enrollment token, actual transport
traces, public credential rows/current sessions and complete owner/foreign
observations are retained. Both session phases independently compare actual
getSession token/id/owner with the issued result. Real later ES256 UV-absent login
advances the persisted counter to1. Foreign user/account/session state is unchanged.

Callback/request clientDataJSON and CBOR attestation observations are reversible:
exact bytes equal their decode/re-encode locally; every map key, algorithm,
authenticator byte and attestation field remains. Only actual packed signature
bytes use the existing opaque-token bijection in both submitted and callback
observations. No hash/digest/comparator exception or transport-field removal is
added. None attestation is not described as proving a registration signature;
packed self-attestation and later signed authentication prove actual key use.

Invalid valid-DER signature, malformed DER, missing UP, invalid BS/BE, wrong RP,
raw origin host/port/case, challenge, malformed key and actual foreign signed
session are distinguished before callbacks/writes. Every attempt consumes its
challenge; replay is400 CHALLENGE_NOT_FOUND. Real storage shows no passkey/session
write; whole owner/foreign state remains unchanged. Actual captured signed cookies
select the foreign session guard; no manufactured caller authority is supplied.

Before production repair, `/tmp/passkey-registration-source-sdk-before.log` is
0/4 with intended failures: all3 UV-absent registrations500 instead of success,
and valid-DER packed signature500 instead of400. Final focused and whole-family
Whole passkey SDK passes29/2782 in
`/tmp/passkey-registration-source-family-final.log`; repeated Source-to-Source
new owners pass8/1208 in `...source-oracle-repeat-final.log`. Native11 passes in
`...source-native-final.log`; required client TypeScript and API/fixture strict
Clippy pass in `...source-typecheck-final.log`, `...source-clippy-final.log` and
`...source-fixture-clippy-final.log`. Repeated Rust-to-Rust reset passes2/28 in
`/tmp/passkey-registration-receipts-reset-rust-repeat-final.log`. The distinct fixture
receipt-reset prerequisite is cbe4a9619317c81499e6001c0bfecabc531abb36. Old stale
receipt, wrong Buffer CBOR input and missing foreign challenge-cookie setup
failures in oracle-before/first oracle-final are excluded as setup, not production
baseline. The first native compile lacked a test-only point-conversion trait and
was corrected before the meaningful native run.

## Explicit remaining boundaries

The current public wire advertises EDDSA(-8)/ES256(-7)/RS256(-257), while the
inherited locked high-level secure_algs verification list only enables ES256 and
RS256. This is a concrete advertised/allowed mismatch, not a claim of full
algorithm parity. Core has typed OKP/EdDSA crypto support; genuine Source EdDSA
lifecycle and safe allowance integration are a separate next investigation.
Certificate-backed/wider attestation formats, extensions/tokenBinding/crossOrigin,
unusual key types/RP settings, callback deletion/no-row behavior and source's
uncaptured duplicate-exclusion behavior remain outside this bounded proof.
Legacy pending state retains its old origin/UV policy; only new Core ceremonies
have exact raw origin and preferred verification. Arbitrary callback tasks and
live process upgrade are unclaimed. Current reference standalone strict checking
has an inherited generic Auth-map variance (same parent diagnostic); required
client-project TypeScript and actual Source runtime owners pass without suppression.
An additional all-test-target Clippy experiment is outside the existing gate's
Clippy target selection and initially reported1299 test unwrap/expect warnings, including the new
legacy owner's initial unwrap calls. No suppression was added; the new owner was
changed to propagate errors. Older warnings remain outside the normal Clippy
target selection. Production/fixture strict checks are green.
Coordinator owns inventory/canonical gates/locks/integration/publication.
