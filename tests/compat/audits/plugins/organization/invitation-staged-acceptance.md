# Organization invitation staged acceptance — Better Auth 1.7.6

This capability follows the published invitation acceptance lifecycle. It depends
on membership policy checkpoint `b7e29c28` and the duplicate-member storage/FK
prerequisites already in that checkpoint. The pending-invitation creation error
supplement `69b23fb4` is a separate dependency; this slice leaves that creation
handler unchanged. No comparator, dependency, schema, or lock change belongs to this capability.
Coordinator review adds 74 explicit successful, rejected, authorization and
state-transition requirements without replacing earlier inventory evidence.

## Source observations and production contract

Pinned `better-auth/dist/plugins/organization/routes/crud-invites.mjs` accepts a
pending, unexpired invitation after authenticated-recipient, verified-email, and
membership-capacity admission. Its before callback receives the original user,
invitation and stored organization. The conditional pending-to-accepted status
write commits before the subsequent member/team/session transaction. Source
`adapter.mjs` implements the claim with exact invitation ID and expected status.

Inside that transaction, Source finds each organization-scoped team and invokes
its configured maximum-members callback using the original authenticated session
and user. Team insertion precedes the one-team active-team/session-cookie write;
member creation and active-organization selection follow. No membership capacity
recheck or organization/user-pair deduplication runs inside this new HTTP flow.
An error rolls back these transaction writes, then conditionally resets accepted
to pending outside the transaction. A reset failure replaces the transaction
error and leaves accepted status intact. The after callback runs after commit,
outside that reset boundary; its rejection retains the committed member, team and
current-session selection.

`/tmp/organization-invitation-phase-probe.mjs` and `.log` preserve nine actual
published-runtime lifecycles: team-full, member/session SQL ABORT, reset SQL ABORT,
after-callback rejection, existing-member duplicate acceptance, same-invitation
contention, different-recipient preadmission at capacity two, and invitation
creation at capacity. They include actual handler responses, callback receipts,
physical rows and replay/foreign-recipient controls.

`/tmp/organization-invitation-errors-probe.mjs` and `.log` preserve four actual
application-error distinctions. Uncaught ordinary before/after errors produce an
empty HTTP 500. After ordinary failure, writes remain committed but generated
cookies are absent. Explicit application API errors retain their status, public
code/message and, after commit, generated cookies, including explicit API 500.
The HTTP mapper here handles only acceptance-owned Internal/Database errors;
trusted store errors retain their types and genuine application/domain errors
remain unchanged. Its cookie ledger removes only exactly owned queued cookie
occurrences and leaves preexisting application headers intact.

`/tmp/organization-invitation-remember-probe.mjs` and `.log` preserve three actual
signed `rememberMe:false` lifecycles. A one-team acceptance emits both the session
and signed `dont_remember` preference cookies without Max-Age/Expires. Ordinary
after failure removes both; explicit API 500 retains both. The implementation
uses the existing signed-cookie and cookie-construction utilities and records
both generated cookies for the same bounded error mapping.

## Public storage and callback API

`InvitationStore::update_invitation_status_if_status` returns the exact updated
row, or None for missing ID/status mismatch. Its default fails closed. SeaORM
binds exact ID and expected status in one UPDATE RETURNING; unsupported RETURNING
backends fail before mutation. PluginStore forwards the operation.

Five additive `AuthTransaction` methods cover scoped team lookup, capacity-aware
team admission, member creation, and token-scoped active team/organization
selection. Their defaults fail closed; PluginTransaction forwards them. SeaORM
uses the actual existing transaction connection and generic associated session
model/active-model bindings. The old trusted `accept_invitation_with_teams`
signature and combined transaction behavior remain available and unchanged.

Organization configuration accepts immutable before/after invitation acceptance
contexts through `OrganizationInvitationAcceptanceHooks`. The before context
contains invitation, original user and stored organization; the after context
adds the actual committed member. Callback return values cannot patch inputs,
matching Source's ignored callback returns. Existing callers default to no hooks.

## Primary proof and regression controls

The official-client primary owner is
`tests/plugins/organization/invitation-staging.test.ts`. Its shared setup uses
real signup, organization/team/invitation creation, a separate owned sibling
session and a foreign user/organization. All original owner/peer/member/team/
invitation/session columns and dates observed by the application are retained.
Raw HTTP status/body/media and every actual transport trace are compared. The
application fixture owns genuine asynchronous callbacks and SQL ABORT triggers;
it does not synthesize membership, acceptance, status, permission, or rollback.

Fifteen phase-table cases cover before, team-limit and after application errors,
ordinary errors, explicit API 500, team capacity and member/team/session/reset SQL
vetoes. Two existing-member cases exercise teams on/off, retaining the first
actual admin row while adding a distinct accepted member row. Two concurrency
cases hold both genuine before hooks after admission, then release requests in
application order: same invitation has one status claimant; different recipients
retain their earlier count admission and reach three physical members at capacity
two. Both pending request responses and both release transports are retained.
Expiry rejects before callbacks; three browser-session cases protect both cookie
stages. Every owner includes genuine no-session/foreign or expiry-order controls,
unchanged peer state and replay or retry.

Before/after callbacks and endpoint state capture full SQL snapshots. Inside the
transaction, the configured team callback reads only actual scoped invitation
ID/status. Native's independent query-only observer sees the committed claim,
not Source-only uncommitted member/team writes. The observed ID remains tied to
the original authenticated email and organization. No dirty-read option is used.
The process-local named-memory SQLite fixture retains one writer connection and
one independent read-only observer. A real driver proof owns committed-status
visibility during held transaction, denied observer writes and rollback. The
existing single-connection retirement proof remains separate, so an observer
cannot mask writer retirement regressions.

Meaningful failures are preserved:

- `/tmp/invitation-staged-before-b7.log`: old real b7 handler/store plus only the
  new callable callback/config fixture scaffold fails 18 owners; expiry passes.
  Failures include absent before/after callbacks, pending rather than committed
  status at team callback, and old no-team duplicate rejection. No timeout.
- `/tmp/invitation-staged-cookie-before.log`: staged flow before the preference
  repair fails actual successful and explicit-500 browser-cookie counts. All
  other local stage/state assertions pass; the strict comparison also discovers
  the old acceptance guest/invitation error-code/message fallback differences.
  Scoped Source error messages and existing organization session middleware now
  repair those responses, without changing global error handling.
- `/tmp/invitation-staged-reset-precedence-before.log`: an isolated incorrect
  implementation ignores the conditional reset error. Exactly the new
  SQL-reset-API case fails (original application 403 returned instead of reset
  empty 500); all other 22 owners pass. The correct implementation passes the
  same 23-owner file. This distinct case protects observable reset-error
  precedence rather than comparing two indistinguishable internal 500 failures.
- Initial Source startup shebang and observer URI/physical-database failures are
  retained as setup controls, not behavioral proof. A later native bind
  collision is likewise retained in final-v2 startup output; verified unused
  isolated ports 42721/42724 produced final-v3 and full-family proofs. The original single-pool
  callback-observer attempt deadlocked; it was stopped and replaced by the
  proven independent status-only observer, preserving the transaction boundary.

Distinct native public-store proofs exercise two independent SQLite connections
for single-winner status claim with full returned-row preservation, real member
SQL ABORT after team/session writes, conditional reset veto/no-op and successful
retry. The manual numeric custom session schema uses its real table/ID/active-org
columns; unsupported active-team binding rejects and rolls back prior team work,
while an unrelated session remains unchanged. These tests cover public primitive
atomicity/custom model contracts that the application serial-release owner cannot.

## Focused validation

- Source-only primary: 23 scenarios / 2532 assertions,
  `/tmp/invitation-staged-source-self-final.log`.
- Source/Rust primary: 23 scenarios / 2532 assertions,
  `/tmp/invitation-staged-differential-final-v3.log`.
- SeaORM native family: 64 tests,
  `/tmp/invitation-staged-seaorm-native-final.log`.
- Manual custom numeric session primary: one test,
  `/tmp/invitation-staged-custom-schema-native-final-v2.log`.
- Actual fixture observer/retirement driver: two tests,
  `/tmp/invitation-staged-sqlite-observer-native-v3.log`.
- Complete organization/extensions/OpenAPI family: 145 scenarios / 12850
  assertions, `/tmp/invitation-staged-family-final-v2.log`.
- API native family: 335 tests, `/tmp/invitation-staged-api-native-final-v2.log`.
- All manual legacy-schema native owners: seven tests,
  `/tmp/invitation-staged-custom-schema-family-final.log`. The existing unrelated
  unused `Option` result warning in that file remains visible; this slice adds no
  new unused-result warning.
- Production strict Clippy: `/tmp/invitation-staged-production-clippy-final.log`.
- Fixture strict Clippy: `/tmp/invitation-staged-fixture-clippy-final-v2.log`.
- rustls/SeaORM/Axum consumer compilation:
  `/tmp/invitation-staged-consumer-rustls-final.log`.
- TypeScript: `/tmp/invitation-staged-typecheck-final-v2.log`; formatting and
  `git diff --check` pass. Full canonical gates remain coordinator-owned.

## Bounds

SQLite is the runtime/storage proof. PostgreSQL RETURNING has an implementation
path but no claimed runtime equivalence; MySQL RETURNING fails closed before the
claim write. Custom stores must implement the additive operations; no silently
successful fallback is provided. The old combined trusted operation preserves
its existing semantics rather than claiming the new Source HTTP stages.

Session cache formats/chunks and other generated cache cookies, exotic signed
preference encodings, arbitrary application headers after ordinary error, and
API-key virtual-session interaction are not exercised by these owners. Multiple
teams and application SQL snapshots of their intermediate uncommitted writes,
callback cancellation/disconnect, malformed guest body ordering, installed custom
joined fields, nonfinite/extreme date behavior and dynamic pending-invitation
adapter pages remain separate boundaries. This slice adds no global serializer,
parser, error, cleanup, transaction or cookie-policy exception.
