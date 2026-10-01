# Admin guest rejection wire

This bounded change follows origin/master `095e33de`. The runtime and official
client remain pinned to Better Auth 1.7.6. It changes no public API, shared error
mapper, authentication policy, schema, migration, dependency, inventory or
comparison rule.

## Source contract and repair

Published `plugins/admin/routes.mjs` throws a body-less APIError when an HTTP
caller has no valid session. Its shared admin middleware, create-user,
stop-impersonating and has-permission branches all return an empty 401 response
with `Content-Type: application/json` for valid requests. A genuine HTTP official
client observes `{data:null,error:{status:401,statusText:"Unauthorized"}}` with
no message or code. An in-process custom fetch instead exposes the source
Response's uppercase status text; the SDK scenarios use actual HTTP servers.

The independent actual handler/SQLite oracle is
`/tmp/admin-permission-oracle/guest-wire.ts`, with results in
`/tmp/admin-guest-wire-oracle.log`. All fifteen routes were exercised with missing,
altered issued and revoked issued cookies. User, account and session snapshots
remained unchanged. The source validates malformed bodies before this rejection;
that separate ordering discrepancy is deliberately unchanged here.

The private admin session helper now returns an optional authenticated pair.
Only `Unauthenticated` and `SessionNotFound` become absence. Other returned
errors propagate unchanged. Each route emits the body-less response for absence;
stop-impersonating uses the same local helper and remove-user's prior special case
is consolidated. Shared session extraction, refresh and queued cleanup headers
remain unchanged. This does not expand claims about virtual sessions or errors
already mapped by the existing shared reader.

## Primary owner and meaningful failures

One parameterized official-client owner covers missing, tampered and revoked
sessions across all fifteen valid admin methods. The tampered proof retains an
actual known administrator's token and valid cookie/base64 encoding, altering
only one signature character. The revoked proof is an actual issued cookie
captured before successful public sign-out. No fixture manufactures authority.

Every rejection checks the complete SDK result, actual empty raw body and JSON
content type, and all existing fixture state observations for administrator,
target, ordinary user and retired user. Authoritative public user reads accompany
the fixture's narrower user projection, catching name/role/ban changes. All
provided account/session fields and complete tokens are retained. Sequential
state reads preserve actual trace order; there is no sorting or suppression.

The owner also checks that attempted creation left no matching user, a real
ordinary user's authenticated ban remains 403 with its source code, an authorized
read succeeds, and legitimate ban/unban revoke only the target's sessions while
the administrator's original token remains current. Existing native admin tests
remain distinct storage/lifecycle controls; no duplicate helper test or test-only
production seam was added.

`/tmp/admin-guest-wire-sdk-before.log` contains the exact final owner on old
production: all three source cases complete, then each Rust case fails because
its first rejection adds `AUTHENTICATION_REQUIRED` and `Authentication required`.
The signature-preserving tamper control is included in this before proof.

## Focused evidence and limits

- Full focused admin family: 25 cases / 1,402 assertions pass,
  `/tmp/admin-guest-wire-sdk-final.log`.
- Native admin tests: 12 pass, `/tmp/admin-guest-wire-native-final.log`.
- Source-to-source complete HTTP SDK control: 3 cases / 474 assertions pass,
  `/tmp/admin-guest-wire-oracle-sdk-final.log`.
- Client TypeScript and strict API library Clippy pass:
  `/tmp/admin-guest-wire-typecheck.log` and `/tmp/admin-guest-wire-clippy-final.log`.
- Fixture strict Clippy reaches the unchanged parent diagnostic at
  `two_factor_policy_fixture.rs:254` (`collapsible_if`), recorded without
  suppression in `/tmp/admin-guest-wire-fixture-clippy-final.log`. The coordinator
  owns the already prepared baseline cleanup; this slice does not edit it.

Two whole-family runs passed all new guest owners but hit the previously tracked
timestamp anomaly in unchanged siblings. Full failed logs are preserved as
`/tmp/admin-guest-wire-sdk-timestamp-diagnostic.log` (role-input updatedAt) and
`/tmp/admin-guest-wire-sdk-fresh-timestamp-diagnostic.log` (empty-action public
read createdAt/updatedAt). Immediate actual source/Rust signup dates match system
time in `/tmp/admin-guest-wire-current-clock.log`. A green rerun does not close
that diagnostic; its provenance investigation follows this freeze. No timestamps
are widened or normalized. Schema-before-auth ordering is a separate proposal.

Only focused verification is run here; full gates, inventories, lockfiles and
publication remain coordinator-owned. The external autoreview tool named by
test-audit is unavailable in this environment.
