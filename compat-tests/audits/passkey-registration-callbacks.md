# Passkey registration application callbacks (pinned 1.7.6)

Scope: `registration.requireSession`, guest `resolveUser`, registration
`afterVerification`, trusted existing-user attribution, and `createSession`.
Existing authenticated registration remains the default. This is a bounded
capability, not a claim that every passkey configuration is implemented.

## Source and actual oracle

Read the installed official `@better-auth/passkey@1.7.6` `dist/index.mjs`,
`index-B7Y0IgKK.d.mts`, and its error-code module. The source resolves an
existing session before invoking a guest resolver. `requireSession:false`
skips the freshness middleware even when a session exists. It stores resolved
user data and application context in the challenge, consumes that challenge
before owner/cryptographic checks, and calls `afterVerification` only after
verification. A current session prevents either stored-user or callback-user
reassignment. Truthy client names take precedence over callback names after
ECMAScript whitespace trimming; an empty callback user ID is absent.

For `createSession:true`, the callback runs inside `runWithTransaction`, then
the selected user is looked up before credential insertion. Credential and
session insertion belong to the same transaction. Missing users produce
`USER_NOT_FOUND`; a cancelled session hook produces `UNABLE_TO_CREATE_SESSION`.
An explicit APIError passes through; a generic callback exception becomes
`FAILED_TO_VERIFY_REGISTRATION`. A resolver exception instead produces an
empty 500 response. Failures after consumption cannot replay the challenge.

`/tmp/passkey-registration-oracle.log` independently exercises the installed
runtime with actual Bun SQLite, real ES256 software authenticator output, and
actual `auth.handler` requests. It establishes callback exception responses,
retained context despite client over-posting, missing-user behavior, existing
owner selection, created sessions, persisted rows, and replay rejection.
`/tmp/passkey-registration-validation-oracle.log` separately records actual
`createSession` null/number/string/array/object 400 validation responses.

## Public production contract

Immutable `PasskeyRegistrationConfig` defaults to `require_session:true` and
holds optional Arc resolver/after callbacks. Callbacks receive the actual
request, immutable AuthConfig, and typed ContextExtensions. Guest resolution
returns typed ID/name/display name. The after callback receives verified
credential ID, COSE public-key bytes, counter, AAGUID, device type, backup flag,
the original safe JsValue client response, resolved user, and stored context.
Its typed optional override permits trusted user attribution and naming.
Callback captures are redacted from Debug.

The stored state retains user/context, including a reader for prior Rust
challenges that contained only user_id. `createSession` validates as an optional
boolean before authentication/challenge use. New `AuthTransaction` owner lookup
and credential insertion methods have explicit fail-closed defaults. Memory,
PluginTransaction, and SeaORM wrappers implement them. SeaORM uses the active
transaction connection for both operations and reuses existing queued session
hooks; cancellation rolls back the credential. No migration/schema is needed.

An application store captured by a callback is **not** automatically rebound to
the transaction. Applications must not assume captured-store writes or external
side effects roll back with passkey/session writes; awaiting an independent
connection while holding a single-connection SQLite transaction can also block.
This slice proves selection of already existing users, not callback-created
users participating in an implicit ambient database transaction. The repository
MemoryStore remains a test utility, not evidence of production transactional
rollback for arbitrary adapters.

## Primary official-client evidence

Four added scenarios use the official createAuthClient/passkeyClient and
software ES256 authenticator against unchanged pinned TypeScript configuration
and actual Rust production dispatch. They protect distinct contracts:

- Authenticated application enrollment issuance derives a signed HS256 proof's
  userId exclusively from its real current session. Client userId fields cannot
  mint authority. After sign-out, a guest resolver stores an owner-bound
  provisional identity and context; the verified callback can select that
  existing owner. Returned and current session IDs/tokens, persisted credential,
  foreign owner's state, callback key bytes/counter/AAGUID/client response, and
  replay rejection are checked.
- Actual separately issued foreign proof, altered unsigned payload, expired
  signed proof, and authenticated owner reassignment cannot create a credential
  or session. Swapping another owner's proof with the same application context
  fails the persisted provisional-owner binding. A wrong cryptographic
  challenge burns the proof and never reaches the verified callback. Body
  context/user fields cannot replace stored state. Guests cannot issue proofs.
- Generic and explicit callback failures, missing selected users, and real
  public database-hook cancellation burn the challenge without credential or
  session writes. A fresh challenge then successfully registers the same
  credential, proving the cancellation did not leave a hidden credential.
  Client and callback name precedence are checked through actual storage.
- Missing resolver only rejects guests; actual authenticated registration still
  works. Invalid ID and invalid name are separate controls. Explicit/generic
  resolver errors have the pinned responses. `createSession:false` creates only
  the selected owner's credential, with no session cookie/current session.
  Invalid `createSession` values leave that exact challenge available for the
  later valid registration and never invoke the verified callback.

The fixture enrollment cookie and complete compact token remain in actual
transport/observations. Its signer/verifier reuse the existing production HMAC
primitive and the configured secret; no test-only production authentication
path or supplied owner ID exists. Expiry uses an actually signed expired JWT,
without external waits. Callback observations first assert exact equality with
all original response strings/bytes and the issuing origin. For comparison,
clientDataJSON is reversibly decoded (round-trip byte encoding asserted) and
its retained `origin` value represented as `{url:actualOrigin}`. Every decoded
key and challenge remains compared through existing semantics; no digest,
identity alias, comparator exemption, or trace suppression is added. Each
attempt has its own application context, so deterministic HS256 issuance does
not accidentally create schedule-dependent repeated-token observations.

## Baseline and focused validation

Baseline `/tmp/passkey-registration-baseline-sdk.log`: four intended failures
on clean local dependency base `7f66c6c`. Three guest generation requests return
401 instead of pinned 200, and missing resolver returns 401 instead of 400.
The baseline cannot express these new registration callbacks: its identical
application controller/state fixture uses the original default PasskeyPlugin;
passive typed declarations exist solely to compile that fixture. This proves
an unsupported capability, not a regression in an already supported config.
The isolated baseline does not fabricate registration outcomes or persistence.

Final logs:

- `/tmp/passkey-registration-oracle-final.log`: TS→TS, 4 scenarios / 428 assertions.
- `/tmp/passkey-registration-sdk-final.log`: TS→Rust, all 10 passkey scenarios /
  734 assertions (four new plus six existing freshness/ownership/overlap cases).
- `/tmp/passkey-registration-native-final.log`: 10 existing passkey native tests.
  The SDK is the primary owner of these new callback contracts; no private
  predicate/native mirror duplicates that stronger persistence/transport proof.
- `/tmp/passkey-registration-typecheck-final.log`: client TypeScript passes.
- `/tmp/passkey-registration-clippy-final.log`: production API + SeaORM passes.
- `/tmp/passkey-registration-fixture-clippy-final.log` and
  `/tmp/passkey-registration-fixture-build-final.log`: actual fixture passes.

No full gate, browser sweep, inventory, lockfile, schema, or comparator change.
The fixture adds only existing-version direct base64 activation; coordinator
owns the single existing package entry in the fixture lockfile and final wiring.
Local ancestors 278c86f/d179441/7f66c6c are already separately frozen passkey and
transport prerequisites, not part of this capability's selective integration.

## Remaining boundaries

Authentication afterVerification, WebAuthn extensions/resolvers, configurable
challenge cookie encoding, broad response/name/media validation variants,
custom schema/additional-field profiles, alternate stores/cache/secondary
storage, and arbitrary callback side-effect rollback remain unproved here.
Typed Rust callback return values cannot represent invalid JavaScript non-string
IDs/names or rejected Promise/panic behavior. Explicit structured callback errors
use AuthError::Upstream; generic failures use AuthError::Internal. This does not
claim that every Rust AuthError subtype reproduces arbitrary JavaScript APIError
objects. Existing source cookie-cache behavior is outside this profile.

Central integration onto newer session.additional_fields must retain that
branch's CreateSession default/transform contract when applying this slice.
