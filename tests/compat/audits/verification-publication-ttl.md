# Verification publication TTL comparison

Issue #302 is a tests-only prerequisite for verification storage issue #174.
It changes the shared comparer and transport evidence, without native or
installed Source edits. #174's checkout retains its original comparer.

The installed Better Auth 1.7.6 internal adapter computes a verification TTL as
`max(floor((expiresAt - Date.now()) / 1000), 0)`. The unchanged Source-source
counterfactual retained literal default OTP/magic 300-second and one-time-token
180-second lifetimes. All 128 real publication-floor assertions passed, while
six TTL aliases failed in `/tmp/issue174-default-source-counterfactual-30.log`.

The new owner uses actual official SDK calls against two independent Source
HTTP servers, actual SQLite migrations, actual application secondary storage,
real password hashing, signed cookies and independent sessions. Its public
application token/OTP generators use shared genuine cryptographic randomness;
the durations are the unmodified plugin defaults. Both cache-only and mixed
storage remain primary configurations. A separate foreign actor issues a real
OTP, and the complete foreign physical rows and prior cache entries remain
unchanged. Every stored password is independently verified.

The exact GET `/__test/verification-publications` response is retained in the
transport trace. A receipt contains the actual incoming HTTP request, full
before-create candidate and admitted snapshot, raw serialized cache value,
parsed value, physical cache deadline, integer TTL and actual hook/set/storage
clocks. The full shared backend (including all unrelated session keys, raw
values, operation order, physical users/accounts/sessions/verifications) is
retained separately in each `/tmp/issue302-source-*.json` artifact. The
publication observer is a named projection; the backend diagnostic is not
claimed to have been normalized or compared by this prerequisite.

Admission requires one matching successful issuing request, the matching actor
and trace index across runtimes, exact request input and server request bounds
inside that request's transport window. The hook-to-set interval must be
inside the server request. Each default deadline must lie within its own
request plus exactly 300000 or 180000 milliseconds. The raw TTL must be an
integer floor attainable within the hook-to-set interval. The physical cache
deadline must equal its actual storage clock plus that exact TTL. The entire
raw JSON must be the canonical serialization of the admitted snapshot; the
full before candidate must be preserved. The globally hashed key is derived
independently from the actual OTP mailbox, delivered magic token or returned
transfer token. Transfer values must match a genuinely issued signed session.

Only complete copies of these actual observer records or their cache-set
records receive the bounded comparison. Full parsed values and all other
fields remain compared. Missing/changed intervals, malformed TTL types,
altered TTLs/deadlines/raw serialization, expired/zero TTL, cross-request and
actual foreign-producer records fail at the owning TTL path, including when a
forged observer is changed consistently. Unrelated records and application
fields remain literal, including `metadata`, `custom`, `additionalFields` and
`applicationData`. This is not a general one-second or scenario-wide tolerance.
The owner does not admit custom lifetimes, storage policies, arbitrary
observer endpoints or OAuth publications without the measured signed-state
and PKCE response binding below.

Credible pre-fix proof uses the exact unchanged main comparer on an actual
captured paired Source run: `/tmp/issue302-before-after.json` records three
literal TTL failures (observation, alias and complete observer trace) and zero
final differences for the same complete observations/windows. Both original
full raw artifacts are named there. This does not substitute a helper-derived
expected TTL or a synthetic primary fixture.

Measured before the final freeze: the two focused owners passed 244 assertions;
one predeclared ten-run stability matrix passed all 20 owners and 2440
assertions, with no clock/Source/fixture patch. The complete harness passed
78/78 and 1346 assertions before the final physical-cache-deadline assertions
were added. Its initial 77/78 result was dependency setup (reference
node_modules absent), repaired by the unchanged frozen-lockfile install.
Final immutable-head gates are pending. No production-coverage claim is made.

Independent review of44f found a real right-only-field loss in its admitted
outer/request/before/set dictionaries. Their iteration now uses complete key
unions with explicit presence checks, matching the snapshot dictionary. The
actual right-side Source application can add ordinary receipt fields before
HTTP observation, retaining a valid original response digest. The regression
asserts the precise extra-field path in every dictionary and the cache alias.
`/tmp/issue302-presence-before-after.json` records the exact actual Source pair:
44f misses all five owning fields, while the repair reports all five. Shape
comparisons also record the extra fields; they are not substituted for the
missing complete-body checks.

The exact observer's private HTTP RequestWindow now holds SHA256 of its
complete originally parsed response, separate from mutable compared output.
Admission first requires that original digest. Consistently changed observer
and alias clocks/deadlines remain rejected even when their fabricated interval
would fit inside the request. Missing/different/malformed digests and
nonfinite, nonnumeric, reversed or absent private request endpoints reject at
the owning TTL path. All full raw records remain present. This integrity
binding creates no hashing exemption for other response or application data.

The retained44f canonical terminated100 after1423/1426 SDK owners and91854
assertions. The failures were the existing174 reset proof length, ten session
expiry paths in organization addition observation5, and eighteen created/expiry
keyring aliases across legacy/manual/recovered observations. The latter were
observed as ~3.3s and ~2.4–2.7s phase offsets; exact new alias reproduction on
unchanged main is not claimed. Strict/default793/feature845/fixture2/harness78
and transport36 passed before that terminal SDK failure. Browser, docs and
coverage were unreached, with no passing claim.


The separate measured OAuth extension retains every original default300/180
owner unchanged. Two additional cache-only/mixed owners use actual Source
`genericOAuth` registration through the normal official `signIn.social` SDK
and the installed shared `generateState`/`generateGenericState` helper. State,
128-character code verifier, embedded deadline, physical ten-minute expiry
and 300-second signed state cookie are generated by unchanged Source. The
bounded local HTTP issuer checks actual client credentials, grant, redirect
URI and SHA256 PKCE before returning a real access token; its userinfo endpoint
requires that token. The real callback completes, deletes its own proof and
creates the expected physical account/user/session. A separate actual actor's
state and all foreign rows/cache remain unchanged. The full backend, remote
HTTP receipts, physical rows, original parsed observer and private windows
remain in each `/tmp/issue302-oauth600-source-*.json` artifact. Both paired
issuers use the same genuinely random authorization code; their Source state,
code verifier, state cookie, access tokens and physical IDs remain independent.

OAuth admission is restricted to these exact storage profile `sign-in/social`
issuing requests. It independently binds the original request input, complete
response URL, one 32-character state, one S256 challenge derived from the real
128-character verifier, canonical JSON payload and original signed state
cookie verified with the actual fixture secret. Both numeric embedded and
physical deadlines must lie in that request plus exactly600000ms. The existing
hook-to-set floor, cache deadline, raw JSON, observer digest and complete-field
checks apply unchanged. Only an admitted complete payload's proven generated
state/verifier/deadline and derived hash key receive their appropriate identity
or clock comparison; every other payload field and its presence remains
compared. Missing/invalid signed cookies, altered challenge, state/verifier or
embedded deadline, bad raw TTL/deadline/interval, changed original observer,
foreign producer and extra ordinary fields reject at their owning paths.
Unrelated application expiry/TTL fields retain literal comparison.

`/tmp/issue302-oauth600-before-after.json` retains two complete genuine Source
pairs and replays them against both untouched actual mainafb5184 and frozen328
before the extension. Actual raw TTLs are cache599/600 and mixed600/599. The
unchanged main comparer reports exactly three literal TTL aliases per pair
alongside its other complete-value differences. Frozen328 rejects the
unsupported600 receipts, including13 owning TTL paths per pair; this is
reported separately rather than called a literal-TTL baseline. The same
complete paired observations/windows have zero differences after the bounded
extension. The earlier `/tmp/issue174-source-source-oauth600.log` separately
retains three precise mixed600 TTL aliases from a real four-owner lifecycle
counterfactual; it is not claimed to reproduce different Source/native aliases.

After the extension, TypeScript and all80 harness owners pass with1833
assertions (`/tmp/issue302-oauth600-all-harness.log`); all four real publication
owners pass707 assertions (`/tmp/issue302-oauth600-third.log`). The first OAuth
fixture attempt used the existing account's mailbox and genuinely hit Source's
`account_not_linked` default, then was corrected to create a separate provider
identity. The second retained run's only comparison differences were two local
issuer authorization-code literals per mode; paired issuers now use a shared
cryptographically generated code. Neither setup result is called a production
regression. Final immutable-head canonical checks are pending.
