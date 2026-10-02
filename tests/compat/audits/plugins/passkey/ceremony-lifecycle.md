# Passkey ceremony freshness and single use

Pinned oracle: `@better-auth/passkey` 1.7.6, `dist/index.mjs`; Better Auth
`dist/api/routes/session.mjs`. Both registration endpoints use
`freshSessionMiddleware` by default. A configured `session.freshAge: 0` disables
the check. Validly authenticated stale sessions are rejected with 403
`SESSION_NOT_FRESH` before either challenge generation or consumption.

Both verification handlers call `internalAdapter.consumeVerificationValue`
after their endpoint schema, origin, and signed-cookie checks, before ceremony,
ownership, credential lookup, or cryptographic verification. Thus ownership,
unknown-credential and cryptographic failures retire the persisted generation.
Authentication uses a record schema; registration uses `z.any()`. Scalar,
array, and null authentication responses fail schema validation without retiring
the challenge. An invalid signature returns 401 `AUTHENTICATION_FAILED`, whereas
a challenge mismatch throws and returns 400 with that code. Registration
challenge mismatch returns 500 `FAILED_TO_VERIFY_REGISTRATION`; foreign
registration ownership returns 401 `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`.

Rust now uses the existing session freshness calculation and atomic
`consume_verification_by_identifier` contract. The verification store already
implements expiry cleanup and exactly one winner for concurrent consumption.
The successful path has no second deletion. No store contract, schema,
migration, comparator, allowlist, or global inventory changes are included.
Existing persisted state formats remain readable, and a well-formed challenge
for the opposite ceremony returns `CHALLENGE_NOT_FOUND` after consumption.

## Primary evidence

`tests/plugins/passkey/ceremony-lifecycle.test.ts` drives the actual official
`passkeyClient` transport with real ES256 WebAuthn attestations/assertions from
the existing synthetic authenticator. SQLite fixture controls read actual
credential owner/name/counter, user session counts and verification counts;
the only writes in the controls move persisted session/verification clocks.
Equivalent profiles configure freshness to one second or zero. The TS profile
uses the upstream username plugin to match fields exposed by the Rust fixture's
bundled user schema.

Four scenarios establish:

- Two concurrent submissions of the same valid real registration response commit
  exactly one credential, with the other response returning the precise
  `CHALLENGE_NOT_FOUND` error. After sign-out, two concurrent submissions of the
  same real signed assertion commit exactly one owner session and one counter
  update. A retry remains rejected. Both complete official-client results,
  including the winning session token, remain in the shared comparison graph.
  Separate instances of the existing tracing fetch capture each request; their
  complete one-entry traces are recorded through `ctx.recordTransport` in
  success/rejection order. This names unordered outcomes without treating
  network completion order as a protocol guarantee. No response, trace field,
  header, or cookie attribute is removed; the existing canonical trace comparison
  receives all four concurrent requests. Setup cookies come from actual
  `onSuccess` responses and the winning signed session cookie is independently
  used to read the real owner session.
- A wrong registration challenge leaves no credential and retires the challenge;
  replay of the original valid response fails, and a fresh generation succeeds.
  Authentication schema failures retain one generation for a later valid signed
  assertion. Invalid signatures, wrong challenges and unknown credential IDs
  then retire their generations without sessions or counter changes; each
  original valid assertion is rejected on retry. A final fresh assertion creates
  exactly one session for the credential's owner and persists its real counter.
- A foreign session carrying the owner's real signed challenge is rejected,
  creates no credential for either principal, and retires the owner's generation.
  The owner's retry fails. Actual expired verification rows and cross-ceremony
  submissions also retire the generation, with no extra sessions or credentials.
- Persisted stale sessions cannot generate or verify registration challenges
  with freshness enabled. Verification rejection retains the original generation
  so signing in again permits that exact valid response. Zero freshness permits
  the same old-session registration and persists the correct owner.

Before proof: `/tmp/passkey-lifecycle-baseline-final.log` runs the final tests
against unchanged production from `88ad6e0`, with equivalent new fixtures;
all three scenarios fail for rejected challenge retention, foreign-owner 403,
and accepted stale generation respectively. The narrower
`/tmp/passkey-lifecycle-schema-before-state.log` demonstrates actual improper
consumption of a schema-invalid authentication response before its guard was
added: verification count zero instead of one.

Initial after proof: `/tmp/passkey-lifecycle-sdk-final.log` has five scenarios /
212 assertions. Final after the overlapping-ceremony addition:
`/tmp/passkey-overlap-sdk-final.log` and genuine TS-to-TS
`/tmp/passkey-overlap-oracle-final.log` each have six scenarios / 306 assertions,
including both existing passkey scenarios. Client typecheck passes in
`/tmp/passkey-overlap-typecheck-final.log`.

The real endpoint overlap fails against unchanged production in
`/tmp/passkey-overlap-baseline.log` on its loser replay classification. Additional
actual HTTP/ES256 driver evidence isolates concurrent authentication:
`/tmp/passkey-overlap-auth-baseline.log` records two successful responses with
separate full session tokens and two persisted sessions in three of four races
against unchanged `88ad6e0`. The same probe against the actual pinned runtime
(`/tmp/passkey-overlap-auth-pinned.log`) and fixed Rust
(`/tmp/passkey-overlap-auth-fixed.log`) yields one 200, one 400 and one persisted
owner session in each of four races. The auxiliary probe is preserved as
`/tmp/passkey-overlap-auth-oracle.ts`; the official-client scenario is the primary
committed owner of this contract.
Existing distinct native passkey tests (10) pass in
`/tmp/passkey-lifecycle-native-final.log`; no duplicate native mirror was added.
Production API Clippy and client typecheck pass in
`/tmp/passkey-lifecycle-clippy-final.log` and
`/tmp/passkey-lifecycle-typecheck-final.log`. Locked fixture build is
`/tmp/passkey-lifecycle-build-final.log`. Focused proof only; coordinator owns
canonical gates and inventory.

## Remaining configurations and boundaries

This slice does not add unauthenticated registration/resolveUser callbacks,
afterVerification callbacks, registration createSession, configurable
authenticatorSelection/extensions, origin arrays, or advanced challenge-cookie
names. The existing Rust challenge cookie uses a signed JWT rather than the
upstream opaque HMAC cookie; the actual driver and account ownership paths are
tested here, while cookie format interoperability is a separate capability.
The official-client concurrent WebAuthn scenario exercises the actual bundled
SQLite runtimes; arbitrary custom adapters and schedulers are not claimed
universally. The underlying atomic verification contract has its own
installed-store concurrency coverage. Broader malformed JSON/media errors,
custom driver failure behavior and authentication metadata-update differences
are not asserted universally by this slice.
