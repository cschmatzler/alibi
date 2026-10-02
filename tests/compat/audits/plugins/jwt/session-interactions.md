# Managed JWT and session-read interactions

The oracle remains the published Better Auth 1.7.6 runtime. This slice builds on
the independently reviewed merge of the frozen managed-JWT and session-read
implementations; it adds no public authentication endpoint or key-storage model.

## Upstream contract

`plugins/jwt/index.mjs` applies normal `sessionMiddleware` to `GET /token`.
`api/routes/session.mjs` forwards nested session cookies and replaces middleware
context with the complete returned session snapshot. Consequently, an aged
session is refreshed before JWT payload and subject callbacks run. A deferred
read can pass an explicit `needsRefresh: true` or `false`; a browser preference
or nonempty `disableRefresh` query suppresses that field as well as renewal.

Direct `GET /get-session` has a different observable hook context: it records
the original adapter snapshot before refresh or expiry validation. Its returned
body can therefore contain a newer expiry than the JWT header's payload callback
observes. That original context also survives expired-row cleanup and refresh
errors. This matches the pinned implementation, including a JWT response header
on an expired-session null response; the header context never authorizes
`GET /token` or another sensitive operation. The original direct context has no
`needsRefresh` field.

The JWT response hook combines `access-control-expose-headers` with an ordered
JavaScript `Set`: trim entries, drop empty entries, remove exact duplicates,
preserve case-distinct names and their first position, and include `set-auth-jwt`.

The API-key plugin's validated virtual session can authorize `/token` ahead of a
different user's signed cookie. Its early response for direct `/get-session`
bypasses after hooks in the pinned dispatcher; that response has no JWT header.
Invalid API-key credentials cannot fall back to the competing signed cookie.

## Implementation contracts

- `AuthContext::require_session_with_refresh_state` runs the same authenticated
  read as `require_session`, retaining the optional deferred response field.
  The existing helper delegates to it without another database read.
- `SessionManager::read_loaded_session` applies validation, refresh and cleanup
  to the session handler's actual store snapshot. The ordinary token-based
  reader delegates after its lookup; both keep the established error behavior.
- A request-local original session snapshot supplies completed-response hooks.
  External dispatch reconstructs request context, discarding caller-supplied
  snapshots. This observation may contain an expired or deleted row and is
  explicitly separate from session authorization.
- JWT payload and subject callbacks share the one authenticated snapshot. The
  response hook signs the original direct-handler snapshot without another
  session lookup, refresh or authentication attempt.

## Evidence and ownership

Owner: `behavior_audit`; integration and final gate: coordinator. The SQLite,
JWT, session-read and ordered response-lifecycle prerequisites retain their
original owners and evidence.

| Contract | Primary evidence |
| --- | --- |
| Normal renewal, query coercion, browser preference and deferred true/false/absent fields | `JWT token middleware signs persisted refresh and browser preference branches` |
| Original direct-hook context, expiry cleanup/retention, exact exposed-header order, expired token refusal | `JWT session headers preserve original refresh expiry cleanup and exposed header order` |
| API-key owner versus a foreign cookie, no virtual session persistence, invalid-key refusal | `JWT API key principal owns signing while foreign cookies and persisted sessions remain unchanged` |
| One renewal with no duplicate write; refused/failed refresh cannot issue an authenticated token | Real public-builder SQLite tests in `tests/jwt_session_tests.rs`, using actual SQL triggers |
| Caller-supplied completed-hook context cannot issue a JWT | Public-dispatch SQLite test; intentionally preserving the supplied snapshot makes its header assertion fail |
| Exact ordered header deduplication | Pinned real-runtime probe plus complete native and official-client response headers |

All official-client scenarios verify signatures with pinned JOSE 6.2.12 and
compare complete claims, persisted owners, session identities and expiry values.
Fixture-only state reads use the selected initialized profile and its real store;
they do not refresh sessions or manufacture authentication receipts. Configuration
profiles cover normal, disabled-refresh and deferred-refresh modes. The native
table additionally covers truly signed empty preferences and combined deferred
and disabled refresh. Existing session policy and concurrency/deletion tests are
retained and run against the factored reader.

The tests failed on the previous implementation's missing renewal and duplicate
header entries. A separate guard-removal control failed because an unauthenticated
request acquired an actual JWT response header. The previously untested full
API-key response exposed a harness defect: its random stored prefix was compared
literally. The reviewed correction links that prefix to actual observed issuance
while retaining length, configured prefix, row identity, ownership, rotation,
metadata content and complete transport shapes. No comparison exception was added.

The existing inventory requirements remain unchanged. The coordinator will add
these requirements through the shared additive evidence schema before publishing:

- `GET /token`, state: `JWT token middleware signs persisted refresh and browser preference branches`.
- `GET /token`, authorization: `JWT API key principal owns signing while foreign cookies and persisted sessions remain unchanged`.
- `GET /get-session`, state: `JWT session headers preserve original refresh expiry cleanup and exposed header order`.
- `GET /token`, rejection: `JWT session headers preserve original refresh expiry cleanup and exposed header order`.

Focused validation on the clean extraction from `ae4aa46` passes five new native
public-dispatch SQLite tests, eighteen existing JWT unit tests, eight existing
session refresh/policy tests, eleven JWT official-client scenarios with 1,064
assertions, and twenty-eight passwordless/one-time-token official-client scenarios
with 1,060 assertions. TypeScript checking, all thirty-four strict harness tests,
and Rust formatting pass. Final integrated canonical validation and measured
coverage remain the coordinator's work.

The current `ae4aa46` baseline demonstrably fails three native regressions:
normal `/token` writes no refresh, exposed headers retain duplicates, and failed
refresh still allows authenticated JWT issuance. Its API-key owner control passes.
The caller-snapshot case needs the new snapshot API and therefore runs as a guard
mutation on the fixed tree: intentionally carrying caller-supplied snapshots
through dispatch yields a JWT header on an unauthenticated null response and
fails the rejection assertion. Restoring unconditional context reconstruction
passes all five native tests again.

Focused logs live outside the repository:
`/tmp/jwt-session-extract-{native-final,jwt-native,siblings,sdk,consumers,types,harness,clippy}.log`;
the failing controls are `/tmp/jwt-session-before-extract-native.log` and
`/tmp/jwt-session-extract-snapshot-mutant.log`. Consumer checks start fresh actual
TS and Rust fixture processes on ephemeral ports with `COMPAT_COVERAGE=0`.

### Review checklist

- Public dispatch unconditionally discards supplied session snapshots, virtual
  sessions and queued headers before trusted handlers or hooks establish them.
- `/token` uses only a validated virtual principal or the authenticated durable
  reader; the original completed-hook context never supplies authorization.
- A foreign signed cookie cannot change API-key JWT ownership, and an invalid
  API key cannot fall back to that cookie. Both stored session owners remain
  unchanged; virtual sessions create no durable session row.
- Payload and custom subject callbacks see the same authenticated snapshot,
  including deferred refresh state. SQL triggers independently count one renewal
  and prove rejected writes leave expiry unchanged.
- Direct hooks preserve original schema-projected user/session values through
  renewal, expiry cleanup and errors without rereading or refreshing the row.
- OTP, magic-link and OTT consumer scenarios pass against the integrated nullable
  defaults and store wrappers. Existing refresh-policy, concurrent-deletion,
  signed-empty-token and authority regressions remain green.
- Strict comparison, capability inventory, locks, exports and migrations are
  unchanged. Fixture controls inspect actual initialized profile storage.

No authorization or persistence defect remains identified in this scoped slice.
The current master and extraction focused runner expose only their existing
Rust orchestrator selectors. The separate dirty integration worktree at
`/home/cschmatzler/.t3/worktrees/better-auth-rs/t3code-33d12558` advertises
`passwordless` in `client-tests/run-against-both.sh` without its corresponding
`passwordless_client_compat` test. That mismatch belongs to the unpublished
integration work, not this extraction or current master. This slice invokes the
actual passwordless scenario directory through fresh fixture processes;
coordinator owns additional focused selectors when those capabilities land.

## Remaining boundaries

Managed JWT-backed cookie caching, stateless sessions and secondary-storage-only
session adapters remain separate integration work. This slice does not claim
those modes from the normal durable SQLite session-read evidence. Provider JWT
validation, OAuth proxy and One Tap likewise have distinct audience, issuer,
state and account-binding contracts.
