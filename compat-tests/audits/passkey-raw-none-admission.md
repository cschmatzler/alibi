# Bounded raw OKP curve8 none admission

Pinned @better-auth/passkey1.7.6 and SimpleWebAuthn13.3.3 admit an OKP key
declaring kty1/alg-8/crv8 under none attestation. Its32-byte x value in the real
fixture is an Ed25519 public key, but the original declared curve stays8. None
attestation validates the registration ceremony without proving key possession.
Later authentication rejects400 AUTHENTICATION_FAILED, and packed self-attestation
rejects500 FAILED_TO_VERIFY_REGISTRATION. Core0.5.4 cannot construct a typed
credential for this unsupported curve, so the former Rust none path rejected500.
This capability implements that exact measured raw-key branch; it does not claim
all raw COSE admission or EdDSA parity.

## Production and authority boundary

Only fresh registration challenges use the new coreRawNone verifier variant. It
stores the unchanged genuine Core state together with its actual issued challenge,
configured RP ID and literal configured origin. Original core and legacy variants
continue to decode and use their original verification policies until expiry.
Before calling Core, only fmt none with literal integer Map fields1=1,3=-8,-1=8
selects the private raw branch. Other keys/formats still reach the existing genuine
verifier; a failed verifier never retries with rewritten or weaker input.

The raw branch checks the actual response id/rawId/type, clientData type/challenge/
literal origin/tokenBinding, actual RP hash, UP and AT, invalid BS without BE,
credential-ID length, counter, AAGUID and CBOR framing. Source's cursor advances
by re-encoded key/extension lengths. Checked length arithmetic follows that rule,
including rejection of nonminimal key bytes that leave authenticator-data bytes.
Source rejects leftover authenticator data but permits tail after the first outer
attestation CBOR item. Both behaviors are retained. A private framing precheck
rejects reserved and indefinite headers that Tiny-CBOR rejects while serde_cbor
otherwise accepts. It reads exactly the first item, uses checked offsets/counts,
allocates no framing buffer, and caps nesting128 before serde value decoding.

The original COSE bytes, credential ID, counter, backup flags, AAGUID and transports
are stored in a private sourceRawNone codec in the existing hidden credential
column. No fake Core Credential or AuthenticationResult is constructed. Normal
public row fields and existing callback/transaction/session behavior are reused.
The original enrollment owner/context comes exclusively from the already issued
server challenge. Foreign body userId/context cannot select another user. Existing
authenticated ownership checks and atomic challenge consumption still run before
the parser. On login the original stored raw curve is rejected before callbacks,
counter updates or session creation. Old flat typed credentials still decode.
No public callback/result type, store, schema, dependency, lock, inventory or
comparator change belongs to this commit.

Source's None verifier reads only attStmt.size>0: nonempty Maps reject, null/missing
reject, but arrays/strings/numbers pass. Its extension conversion destructures
iterable entries: nested Maps, strings and arrays of pairs pass, while numbers and
arrays of numeric entries throw. Production preserves these observed branches,
rather than imposing a stricter Map-only rule unrelated to Source behavior.

## Primary evidence

Actual official-client/handler/Bun SQLite probes retain full responses, callback
inputs and persisted rows. `/tmp/passkey-unsupported-curve-source-oracle.log`
proves raw none admission and later auth400/packed500. The31-case
`/tmp/passkey-raw-none-source-definite-final.log` proves ceremony rejection,
primitive statements, iterable extensions, counter25, nonminimal key rejection,
indefinite outer/statement rejection, legal outer tail and every replay400.
Its earlier statement-indefinite setup used a nonempty statement instead of the
intended empty statement; `/tmp/passkey-raw-none-source-definite-before.log`
preserves that setup error and is not final behavioral evidence.

Four official-client owners retain all primary transports and serialized requests.
The none owner uses real signed authenticated-owner enrollment authority after
sign-out, submits foreign body authority, then confirms callback bytes, raw key
curve/algorithm, returned/listed persisted metadata, issued session token/id and
current session. It retains counter25, nested extensions and legal outer tail.
After sign-out, genuine Ed25519 signatures over the original curve8 facts,
false64-byte and short1-byte signatures all reject400 with no cookie/callback/
counter/session/foreign write; assertions use counter26, independently avoiding
an accidental stale-counter denial. Each replay rejects400.

The packed owner submits actual64/64/1-byte genuine/false/short signatures; all
reject500 before verification callbacks or writes. The raw protocol owner rejects
bad presence/backup flags/RP/origin/challenge/client type/tokenBinding, statements,
nonminimal key/indefinite framing, trailing/missing/scalar extensions, credential
type, actual foreign authenticated owner and real persisted expiry. Whole owner/
foreign state and SQL passkeys/sessions/challenges stay unchanged; every challenge
burns. Legal primitive/iterable owners use distinct real device IDs encoded before
proof generation, confirm actual callback input and resolved owner session, then
sign out and retain all stored rows. Distinct IDs avoid the separate Source/Rust
duplicate-credential storage difference; that behavior is not repaired here.

Canonical clientData/CBOR observations still assert complete byte round-trips.
Malformed CBOR controls retain full original base64 bytes; noncanonical decoded
values retain both decoded values and full original bytes. Those actual none
proof bytes are shared by both runs through the existing deterministic device key
and RP. No digest, field omission, entropy exemption or new comparison rule exists.
Original local proof/callback equality and actual transport traces remain.

Two distinct native contracts address hidden protocol risks. The public handler
really generates a challenge, consumes an actual none response and writes real
migrated SQLite. Readback preserves exact key/ID/counter/AAGUID/transports in the
hidden raw codec, keeps that codec out of public output, and cannot become a Core
credential. A real historical high-level generated registration state uses its
old outer encoding and genuine ES256 none proof: UVtrue succeeds while UVfalse
retains required-UV rejection. A real old Core generated state retains Preferred
UV acceptance for both proofs; the old typed credential codec still decodes.
Live-process upgrade/expiry across binaries is not claimed by these tests.

Frozen old-production before evidence is
`/tmp/passkey-raw-none-sdk-meaningful-before-final.log`:2 denials pass and2 legal
raw-none owners fail at unexpected500. The pre-framing current raw binary wrongly
accepted an indefinite outer item in `/tmp/passkey-raw-none-framing-sdk-before.log`;
the exact Source controls reject500. Final focused4/1456 passes in `/tmp/passkey-raw-none-sdk-final.log`; repeated
Source-to-Source12/4368 passes in `/tmp/passkey-raw-none-source-repeat-final.log`.
Native12 pass in `/tmp/passkey-raw-none-native-final.log`. Client TSC, production
API lib strict Clippy, fixture strict Clippy and formatting pass in
`...typecheck-final.log`, `...clippy-final.log`, `...fixture-clippy-final.log`
and `...format-final.log`. Full passkey37/5168 passes in `/tmp/passkey-raw-none-family-final.log`.

## Explicit remaining limits

Actual source alg-7/crv6 Ed25519 none/packed/login success remains a separate
representation/verification capability, proved in
`/tmp/passkey-okp-algorithm-mismatch-source-oracle.log`. Other unknown curves,
tagged/duplicate or exotic noncanonical COSE values, Firefox's malformed-map
workaround, unusual non-string response fields, malformed transport values,
certificate attestations and wider callback result fields are not closed here.
The128 nesting limit is bounded Rust behavior; Source nesting-limit equivalence is
unproved. Original raw key storage follows the observed canonical integer/byte
COSE fixtures; normalization of exotic typed key values is not claimed. Trusted
publicKey-only updates versus the hidden credential snapshot are unproved and may
require a distinct storage-authority repair. No broad fallback conceals them.

An exploratory strict Clippy run over all API test targets exposes1292 existing
test expect/unwrap lint failures in `/tmp/passkey-raw-none-native-clippy-final.log`.
They are not suppressed or treated as a passing check. An exploratory reference
`tsc --noEmit` invocation has no project tsconfig and prints compiler help; it is
excluded as a setup-only check. Source files are unchanged and actual pinned
Source-self execution supplies runtime evidence. Required production API
lib and fixture strict Clippy, actual native tests and TypeScript remain the
bounded checks for this feature. Coordinator owns canonical gates and publication.
