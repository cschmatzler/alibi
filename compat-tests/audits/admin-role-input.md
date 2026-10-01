# Literal admin role input and create-role authority

The installed Better Auth 1.7.6 `plugins/admin/routes.mjs` validates each
requested role string literally against an explicitly configured role table.
It does not split comma strings or trim input elements before validation.
Without a configured table, empty strings and arrays are accepted. A configured
empty-string key is a legitimate role; an empty array has no elements to reject.
Successful arrays are joined with commas when persisted. The actual public
handler matrix is retained in `/tmp/admin-role-input-oracle.log`.

For create-user, the source removes `data.role` from ordinary application data
and computes `body.role ?? dataRole`. Every defined requested role, including
an empty string or array and nested null/object values, requires the acting
session's set-role permission before role validation or duplicate lookup.
This is an explicit presence check (`requestedRole !== undefined`), not a
truthiness check. A supplied top-level string/array wins over nested data.role.
The HTTP wrapper now applies that additional permission check, while the core
operation validates the effective role before duplicate lookup and stores only
ordinary data as native application metadata. Trusted native operations retain
their existing server-authorized semantics; no session-derived authority is
added to the core operation.

Four official-client scenarios are the primary role/authorization owner. Actual
immutable manager and creator configurations run the pinned plugin and the
Rust plugin against their normal SQLite stores. A read-only local state route
reads actual users, credential accounts and sessions in both runtimes; it does
not manufacture authority or outcomes. The scenarios cover literal string and
array rejection for set-role/update/create, configured empty keys, unconfigured
empty values, top-level precedence, nested roles, validation before duplicate
lookup, and creator-only escalation denial. Positive controls include default
creator enrollment, allowed role-array assignment and credential sign-in for
the newly created limited user. Rejections leave target and acting-owner rows,
issued tokens and existing sessions unchanged; failed creations leave no user,
account or session. Complete client results, transport traces, cookies and
persisted owner observations remain under the existing strict comparator.

`/tmp/admin-role-input-before.log` runs all four scenarios with the same final
fixtures against unchanged 6019827 production. Its four intended failures are:
configured comma role accepted, configured invalid create role accepted,
creator-only explicit escalation accepted, and unconfigured empty role wrongly
rejected. The source-to-source control passes 4 scenarios/316 assertions in
`/tmp/admin-role-input-oracle-sdk.log`. The repaired whole admin family passes
15 scenarios/460 assertions in `/tmp/admin-role-input-sdk-final.log`.

One distinct native public-plugin test protects application metadata persistence
that the standard pinned SDK fixture schema cannot expose. It creates a real
SQLite user through an authenticated request, requires reserved role removal,
retains ordinary nested metadata including the literal private RawValue key,
and checks created/acting ownership and existing sessions. The old owner fails
with the extra persisted role field in
`/tmp/admin-role-input-native-metadata-before.log`; the repaired 12-test admin
family passes in `/tmp/admin-role-input-native-family.log`. This does not mirror
the SDK permission cases or require a production test seam.

Strict API/SeaORM library and fixture Clippy, actual fixture build and TypeScript
checks are recorded in `/tmp/admin-role-input-{clippy,fixture-clippy,build,typecheck}-final.log`.
Formatting and diff checks are complete. The coordinator owns inventories,
locks, cross-branch integration and full gates.

Boundaries remain explicit: the native typed top-level optional role accepts
JSON null as absence whereas the source request schema rejects top-level null;
other object/coercion/prototype branches are not claimed closed. Source ban
fields in create data, arbitrary additional user schemas, trusted public server
API dispatch, callback roles, duplicate/email/password/account-insertion error
ordering and source-specific initialization timing are separate capabilities.
This change adds no schema, migration, lock, inventory, comparator or public
core contract.
