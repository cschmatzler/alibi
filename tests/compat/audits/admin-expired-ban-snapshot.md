# Expired-ban user snapshot during session creation

Pinned Better Auth 1.7.6 `plugins/admin/admin.mjs` clears an expired ban in its
session-create hook. The initiating operation retains its original user object:
`api/routes/sign-in.mjs` passes it to the cookie writer and returns it after
createSession; sign-up, `oauth2/link-account.mjs`, two-factor verification and
SIWE follow that same original-object pattern. Admin impersonation likewise
looks up its target before createSession and returns that original target.
The unban is a real persistence update, not a replacement of the operation's
response user snapshot.

Rust's common session issuer and admin impersonation previously replaced that
original entity with the unban update's returned entity. Both now retain the
original user while awaiting the same database update. Ban-error handling,
session insertion, stored unban fields, session projection and token binding
are unchanged. Subsequent authoritative reads still obtain the updated row.
This is eight lines of production changes in helpers.rs and admin/handlers.rs;
no public API, migration, schema, dependency or comparator change is needed.

Two official-client scenarios are the primary owners for the distinct normal
sign-in and admin impersonation paths. They use an integer -60 ban supported
by the preexisting API, so this prerequisite does not depend on new duration
configuration. Actual owner credentials authorize the ban and revoke existing
target sessions. Each complete successful response must retain the original
target ban fields and original updatedAt in JavaScript millisecond precision;
a separately authenticated owner reads the actual cleared
ban through public getUser, and current-session reads also show the cleared
user. Actual SQLite readback proves exactly one new target session, the issued
token and user ownership, unchanged credential ownership, and identical acting
owner and foreign user/session state. The reader's full login and current
session observations remain compared as well. No sleeps, fixed clocks, fake
authority, copied projection implementation or test-only production seam is
used; all raw request/response traces and cookie/token observations remain.

`/tmp/admin-expired-ban-before.log` runs unchanged da0cada production: both
scenarios fail specifically because their response user has the refreshed
false/null/null ban fields. The pinned source-to-source control passes two
scenarios/104 assertions in `/tmp/admin-expired-ban-oracle-sdk.log`. The repaired
whole 17-scenario/564-assertion admin family passes in `/tmp/admin-expired-ban-sdk-final.log`.
The existing 12 native admin tests, strict API/SeaORM and fixture Clippy, fixture
build and TypeScript proof are recorded in
`/tmp/admin-expired-ban-{native,clippy,fixture-clippy,build,typecheck}-final.log`.
The coordinator owns canonical gates, inventories and publication.

Scope limits: source's strict ban expiry comparison versus the preexisting
native <= comparison is not changed without an independent equality-boundary
proof. Custom store/adapter callback changes to unrelated fields and source
request-context absence semantics are unproven. Other common issuer callers
share this snapshot policy by source inspection; only the two specified paths
have new differential lifecycle proof. This does not establish universal
post-hook user projection or arbitrary callback-order parity.
