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
exotic noncanonical COSE reencoding and unmeasured tagged selector values, Firefox's malformed-map
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


## Decoder review and measured repair

Independent review of frozen 36208658 found that the general Rust CBOR decoder
collapsed duplicate map keys, accepted non-string/non-number keys and finite
half-floats, accepted integers beyond the pinned safe range, stripped tags and
rejected lossy UTF-8. Real pinned registration probes confirm the admission
contract, not merely the dependency parser. Duplicate outer fmt/authData,
boolean/array keys, integer/float aliases, repeated NaN and signed-zero aliases,
finite half statements and an integer above MAX_SAFE_INTEGER all reject with
500 before credential/callback/session writes. A half Infinity statement, a
literal tagged statement and an ignored malformed-UTF8 text key really enroll.

The revised private decoder implements the measured Tiny-CBOR value contract
while retaining checked cursor arithmetic and the existing bounded nesting.
It preserves literal tags and SameValueZero key identity, limits decoded length
arguments to Source's supported range and uses lossy text decoding. It does not
change dependency versions/features or the historical verifier. Null/undefined
use one private stand-in only where the consuming checks reject both or observe
an identical one-byte reencoding length; original proof/key bytes remain retained.
BOM and truncated payload cursor details were checked directly against installed
Tiny-CBOR; those additional parser observations are not claimed API evidence.

The primary original-proof SDK owner now has 29 rejection controls; its legal
owner has six actual enrollment/callback/session transitions. Meaningful old
production fails at duplicate-fmt acceptance in
`/tmp/raw-none-decoder-before.log` and at lossy-text rejection in
`/tmp/raw-none-decoder-lossy-before.log`. Expanded Source-self passes two owners /
1,632 assertions; repaired dual-runtime four raw owners / 1,998 assertions and
whole passkey family 37 / 5,710 assertions pass. Twelve native tests, production
strict Clippy, locked fixture build and client TypeScript pass. Nineteen inventory
requirements are additive; all earlier requirements remain enforced. Phone-owner
independent review of the decoder is clear; it found a current-request-origin
blocker repaired below. The next canonical integration gate is pending.

Exotic COSE values may reencode to different bytes in Source while this raw codec
retains original key bytes; that public-key normalization capability remains
explicitly open. These measured outer-value controls do not claim to close it,
unmeasured tagged selectors, arbitrary nesting, duplicate credential storage or
trusted raw-public-key-only mutation. Strict wire comparison remains unchanged.

## Current verification origin follow-up

Independent phone-owner review of frozen `9172910c` found one new raw-branch
origin mismatch. With plugin origin omitted, published registration derives its
expected origin from the current HTTP request's Origin header. The raw verifier
instead checked the generation-time base URL saved in its policy. A trusted
alternate Origin consequently admitted a mismatching base proof and rejected
its matching alternate proof. The typed verifier already receives the current
resolved origin. This follow-up passes that same origin into the private raw
verifier. Challenge, RP ID, enrollment owner and historical serialized policy
remain unchanged; the historical origin field remains readable but does not
replace current configured/request-origin resolution. No global Origin guard,
parser, challenge operation, callback contract or cookie mapping changes.

Actual fresh published-runtime HTTP probes are retained in
`/tmp/passkey-raw-none-origin-review.ts` and `.log`: the alternate origin is
explicitly trusted, base-proof/alternate-header rejects500 with no credential,
alternate-proof/alternate-header admits200 and writes the actual owner row,
and base/base admits200. Each reached challenge is consumed. A separate
`...origin-default-review.ts`/`.log` measures Source's hostname-casing behavior
under default trust; native global Origin casing semantics are a separate
boundary and are not repaired or claimed by this factor-local verifier fix.

Two literal profiles in the existing application enrollment fixtures reuse the
same genuine signed proof, resolver and after-verification callbacks. Both trust
exactly `http://localhost:49190` in addition to normal base trust; one omits plugin
origin, and the other explicitly configures its real base URL. No listener or
fabricated route response is needed at the alternate origin. Main registrations
and the existing profile behavior are unchanged. Two table-driven primary SDK
owners distinguish these configuration contracts without changing earlier
owners: both mismatch directions, legitimate base and alternate admission,
configured-origin precedence despite an alternate trusted request header,
real foreign authenticated-owner rejection, original callback proof/context,
issued cookie/session token ownership, challenge burn/replay and full foreign
user/account/session preservation.

A private application observer reads actual user-owned passkey SQL rows with
bound user IDs and physical row order. It retains every common published stock
passkey column, including creation dates, nullable fields and stored key/ID/
backup facts. Previous rows and foreign rows must remain byte-value identical
within each run. Native-only hidden credential/updated-at fields remain outside
the shared stock schema; the existing native SQLite raw-codec owner independently
protects the hidden representation. No synthetic admission, adapter replacement,
opaque proof digest or shared comparison exception is introduced.

Meaningful frozen-production before controls are preserved in
`/tmp/passkey-raw-origin-sdk-before.log`: actual `9172910c` plus only the
application fixture scaffold wrongly admits base-proof/alternate-header,
while the configured-origin control passes. In
`/tmp/passkey-raw-origin-sdk-before-admission.log`, only the same mode order is
changed to expose the other defect first: valid alternate-proof/alternate-header
wrongly rejects500 while its configured control passes. The normal final mode
order is restored. Source-to-Source passes two owners/740 assertions in
`/tmp/passkey-raw-origin-source-self-final.log`, and the repaired differential
passes two/740 in `/tmp/passkey-raw-origin-sdk-final.log`.

An initial new-owner setup incorrectly expected credentialID in the older narrow
state observer; `/tmp/passkey-raw-origin-source-self.log` preserves that schema
failure. The dedicated actual common-column observer replaces that assumption.
A subsequent stale test-name filter selected zero owners in
`/tmp/passkey-raw-origin-source-self-v2.log`; it is not represented as behavioral
verification. Final evidence names and counts above come from actual selected
owners. Existing canonical key/depth/custom transport/duplicate-credential and
raw-public-key mutation limits above still apply.

Final whole passkey verification passes 39 SDK scenarios/6,450 assertions in
`/tmp/passkey-raw-origin-family-final.log`; existing native passkey tests pass
12/12 in `/tmp/passkey-raw-origin-native-final.log`. Client TypeScript and strict
locked production API-lib and fixture Clippy pass in
`/tmp/passkey-raw-origin-typecheck-final.log`,
`/tmp/passkey-raw-origin-production-clippy-final.log` and
`/tmp/passkey-raw-origin-fixture-clippy-final.log`. Workspace/fixture formatting
and diff checks pass. The two prior-code before logs remain nonpassing evidence;
no full canonical gate, lock or inventory edits were made by this owner.
All focused application processes were stopped; frozen917 and the earlier SDK
storage/evidence freezes remain unchanged.

Coordinator independently reviewed frozen origin repair `6dd6a9bd`: only the already-resolved current verification origin enters the raw verifier; persisted challenge, RP and owner authority remain intact. The two complete SDK owners distinguish default and explicit-origin configurations, both mismatch directions, genuine owner rejection, callback proof, single-use challenge and actual bound SQL rows. Meaningful frozen917 failures and configured controls establish the defect independently. No global trusted-origin change is included. Eight additional inventory requirements cover both owners without removing the prior nineteen or any earlier evidence.
