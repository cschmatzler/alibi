# Organization member removal database errors against Better Auth 1.7.6

This separate capability follows frozen removal hooks c787b768 and defaults
4cedcae7. It closes their recorded default Bun HTTP SQL-error response gap without
changing storage, callbacks, schema, configuration or the native helper contract.

Pinned `dist/plugins/organization/routes/crud-members.mjs:172-229` performs
permission/tenant guards, beforeRemoveMember, adapter deletion, current-token
selection clearing and afterRemoveMember in that order. The deletion transaction
is only the member/team operation (`adapter.mjs:305-350`); callbacks and session
selection remain outside it. The default Bun Kysely adapter enables transactions
(`@better-auth/kysely-adapter/dist/index.mjs:64-71`). Uncaught SQL failures from
these stages produce an empty HTTP 500 with no content type or cookie, whereas
explicit APIError 500 callbacks produce their public JSON code and message.

An independent unchanged-runtime probe exercises seven fresh actual SQLite
lifecycles in `/tmp/organization-member-remove-error-phases-probe.mjs` and `.log`:
before-callback user UPDATE veto, after-callback self-removal UPDATE veto with two
owners and selected sibling sessions, default member ABORT, default team ABORT,
member IGNORE and explicit before/after APIError 500. These are genuine adapter
operations and SQL errors, not a fixture returning an expected error response.
The probe establishes rollback and committed partial state independently of the
Rust handler. In particular, after-callback failure retains member/team deletion
and only the current activeOrganizationId clear, preserving activeTeamId and the
sibling selection. IGNORE retains the member while team cleanup commits.

Only handle_remove_member changes: after existing ordered body/media validation
and nested session resolution, a business-core AuthError::Database becomes an
empty AuthResponse 500. All other error variants propagate normally. Explicit
AuthError::Api and static Upstream errors retain their JSON behavior. The public
remove_member_with_headers operation still returns its actual AuthResult error;
there is no generic error-mapper or session-resolution catch expansion.

Four additional scenarios extend the existing primary official-client removal
owner rather than duplicating its authorization/storage tests. Their controlled
application fixtures configure actual callbacks, real SQL ABORT/IGNORE triggers
and an otherwise equivalent no-callback profile. Guard IDs must select a real
matching member and are inserted with parameterized SQL; fixed triggers scope
writes to that captured organization, member and user. The private guard table
is fixture infrastructure only. Callback receipts are emitted by the real
callbacks and read actual SQLite snapshots. A finally cleanup removes guards
also when an intentional baseline assertion fails.

The scenarios assert exact raw status/text/content-type/cookies plus complete
known user/account/session state and physical organization/member/team rows:

- Default member and later team vetoes return empty 500, roll back all scoped
  writes and deliver no callbacks. Guest/foreign denials retain their original
  errors and all state; clearing the guard permits a real successful retry.
- Before callback SQL failure preserves all rows; self after-callback SQL failure
  preserves the exact committed deletion/current-token-only clearing phase.
  Original callback snapshots, foreign team memberships and sibling selection
  remain exact. A genuine reinvitation/acceptance restores membership for retry.
- SQL IGNORE succeeds, retains the original member and releases actual team seats;
  a later retry deletes the member without releasing those seats twice.
- Explicit public before/after callback 500 errors retain JSON and their respective
  partial-write phases. This guards against catching every status-500 error.

The new source-self owner first passes 4 scenarios / 714 assertions
(`/tmp/org-member-removal-db-source-self.log`). The unchanged frozen Rust handler
with those same real SQL fixtures passes the IGNORE and explicit-public-500
controls, while both SQL-error owners fail solely because it returns
application/json {message:Internal server error}, rather than empty bytes
(`/tmp/org-member-removal-db-before-cleanup.log`, 2 pass / 2 fail, 557 assertions).
After the route-local repair, all fourteen primary cases pass / 2020 assertions
(`/tmp/org-member-removal-db-sdk-final.log`). No source/test edits occur during
Bun runs. Existing native public-store ABORT/IGNORE/missing/rollback owners remain
in the defaults prerequisite; the new SDK owner covers the distinct HTTP mapping
and callback write-phase boundary, without another coupled mock test.

The complete organization, extension and actual OpenAPI focused owners pass
113 SDK scenarios / 8524 assertions (`/tmp/org-member-removal-db-family-final.log`).
All 332 API library siblings pass (`/tmp/org-member-removal-db-api-final.log`).
Strict API library and actual fixture all-target Clippy, client TypeScript,
fixture build and both format checks pass in
`org-member-removal-db-{api-clippy,fixture-clippy,types-final,final-build,
format-final,fixture-format-final}.log`. No store implementation changes, new
native test duplication or expansion to a full workspace gate are made.

Boundaries remain explicit: this is the measured default Bun SQLite removal HTTP
Database-error contract, not a global parity claim for arbitrary internal errors,
other routes/backends, custom exception classes or onAPIError configuration.
Last-owner concurrency/CAS, custom joined columns, global server-API/API-key
dispatch and HTTP cancellation retain the prior separate boundaries. No SQL error
is synthesized, expected callback delivered by controls, or cookie/transport
suppressed. No comparator, clock, tolerance, dependency, lockfile, schema,
migration or inventory changes are made. The coordinator owns independent review,
canonical gates and publication. External test-audit autoreview is unavailable.
