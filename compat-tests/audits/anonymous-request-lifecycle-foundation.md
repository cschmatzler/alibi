# Original completed sessions and trusted OAuth context

Pinned reference: Better Auth 1.7.6 `cookies/index.mjs` (`setNewSession`),
`plugins/anonymous/index.mjs` (`resolveAnonymousSession`, before/after hooks),
`api/state/oauth.mjs` and `state.mjs`. This prerequisite uses the prepared
anonymous plugin as the first production consumer. It does not implement
cookie-cache production or cached session reads.

## Request isolation and original snapshots

`AuthRequest` has clone-shared typed `RequestExtensions`; `RequestHookContext`
shares the same state within one public dispatch. The existing public
`BetterAuth::handle_request` reconstruction creates a fresh extension Arc for
every dispatch. It does not clear an Arc shared with another caller/request.
An application can attach data during a trusted plugin hook; caller-attached
extensions are discarded before that hook runs. No response body, request
claim, or caller-selected user can construct the private session/context types.

The actual common issuer records its original raw `S::User` and `S::Session`.
Direct email signup records the actual created snapshots inside its transaction
after successful session creation, before commit. A failed transaction cannot
produce a completed-response consumer because the real session cookie is
absent. Anonymous issuance retains its original created user even if a
session lifecycle hook changes the stored user. Anonymous completed-response
processing uses this original pair only when a real nonempty session cookie is
present. Sensitive authorization still reads an authoritative stored session;
the completed snapshot is a callback observation, not session authority.

The primary SDK owner is `anonymous upgrade transfers original completed user
and session snapshots before cleanup`. Its real session-create after hook
changes the stored new user's name; the callback must receive the original
name, while the subsequent current-session read must expose the changed name.
The prepared draft fails on that exact callback name, not on endpoint absence.
The fixture/tests accompany the dependent anonymous capability rather than
duplicating its assertions at another boundary.

## Trusted OAuth context and legacy state codecs

Only the anonymous plugin's trusted before hook captures an authenticated
anonymous ID, at `/sign-in/social`. State issuance reserves `serverContext` and
`_serverContextProof` against client additional data. Ordinary additional data
continues to be serialized. The issued state ID and canonical JSON context are
authenticated by HMAC-SHA256 with domain
`better-auth-rs:oauth:server-context:v1\0`, checked big-endian byte lengths, and
the current auth secret. The payload contains its original typed context and
base64url proof. No dependency, schema, or external state was added.

This native provenance guard is necessary because historical native state
serialization permitted arbitrary client values under these names. A plain
version marker would also have been forgeable in historical additional data.
Parsing preserves the old JSON representation without interpreting it as
authority. Constant-time proof verification happens only after ordinary state
lookup, cookie correlation, consumption, and payload expiry checks. Typed
context parsing happens after verification. Missing/invalid proofs prevent
recovered authority; ordinary legacy OAuth still completes and real anonymous
cookie fallback remains available. Copying a genuine proof to another issued
state does not authenticate that state.

Source does not need this native historical-codec guard because its context was
server-owned. Existing database-state codecs also differ: Source's signed
state cookie and literal verification identifier versus native JWT cookie and
`oauth:` identifier. This change does not claim literal cookie/storage codec
parity. Secret rotation, nondefault cookie state strategy, multiple active
anonymous-session selection order, and custom application server-context
schemas remain outside the measured slice.

## Independent native evidence

`tests/anonymous_request_extensions_tests.rs` invokes real public email signup
and signin, database hooks, and persistence. It proves concurrent reused clones
cannot share/erase dispatch authority, and sequential success/failure/signin
cannot inherit caller or prior state. An incorrect public reset control fails
both tests at the caller-state guard:
`/tmp/anonymous-request-extensions-incorrect-reset.log`.

`tests/anonymous_oauth_context_tests.rs` creates actual anonymous accounts,
issues real OAuth state using their signed cookies, and uses an independent
local HTTP token/user-info provider. It tests genuine recovery without the
anonymous cookie, client context stripping, changed owner, a proof copied from
another state, malformed legacy JSON types, wrong cookie, expiry, and replay.
Ordinary legacy callbacks still create only the provider owner's account and
session. Foreign user/session facts remain unchanged, and wrong cookie/expiry
do not reach the provider. An intentionally unchecked-HMAC implementation
fails at the altered-owner callback:
`/tmp/anonymous-context-unchecked-provenance-control.log`.

The prepared anonymous draft's exact official-client before proof is
`/tmp/anonymous-sdk-meaningful-before.log`: original snapshot wrong, user cancel
403 instead of 500, and cookie-less OAuth callback has no transfer receipt.
One independent basic issue/delete owner already passed. These are separate
from the earlier fixture setup corrections (callback context argument and SDK
Date versus JSON assertion representation).

Public native request tests cover in-process dispatch reuse, not live process
upgrades. JSON preservation is a legacy state accommodation, not permission to
inject verified context through public request extensions.

Final foundation-only validation (anonymous cancellation/browser preference
changes temporarily excluded while running):

- `/tmp/anonymous-foundation-only-native-final.log`: three native owners pass.
- `/tmp/anonymous-foundation-native-clippy-final.log`: strict native Clippy.
- `/tmp/anonymous-foundation-only-sdk-final.log`: two official-client owners,
  original snapshots and cookie-less recovered ownership, pass 102 assertions.
- `/tmp/anonymous-foundation-only-clippy-final.log`: strict workspace lib Clippy.
- `/tmp/anonymous-typecheck-final.log`: client TypeScript check.
- `/tmp/anonymous-foundation-only-fixture-build.log`: actual current-tree fixture.

The temporary PKCE checked-index repair is its own prerequisite commit, not
part of this foundation. No inventory, comparator, dependency, lockfile,
database schema, or cookie-cache changes are included here.
