# Admin HTTP schema validation before session and permission checks

The published Better Auth 1.7.6 admin routes declare twelve POST body schemas and
two GET query schemas. `stop-impersonating` declares no body schema. Better-call
parses the router's allowed JSON media before endpoint invocation, validates the
declared schema before endpoint middleware, and only then performs authoritative
session lookup and permission checks. A malformed request therefore returns its
real JSON/schema/media error before an empty guest 401 or authenticated 403.

Source owners are `better-auth/dist/plugins/admin/routes.mjs`,
`better-auth/dist/api/index.mjs`, `better-call/dist/{router,utils,context,validator}.mjs`
and the installed zod 4.6.5 object/union/XOR implementations. The local actual HTTP
oracle `/tmp/admin-permission-oracle/schema-order.ts` records 229 source responses
in `/tmp/admin-schema-order-oracle.log`; all complete SQLite user/account/session
snapshots remain unchanged. Additional source probes preserve permission-alias
selection, duplicate-query behavior, body presence, coercion failures and the
exact email regex. Early TypeScript expectation mistakes (an extra XOR root issue
and escaped enum quotes) are setup errors, not Rust baseline evidence.

## Bounded production owner

`admin/validation.rs` is private to the admin HTTP handlers. It reuses the safe
`JsValue` parser, preserves declared issue order and exact wire messages, and
returns actual typed request values. Optional nulls are schema errors rather
than absence. Required coerced IDs reject missing values as `nonoptional`, accept
present JSON values through JavaScript String conversion, and retain the two
source nonempty checks on the set-password route. Empty strings elsewhere are
valid schema inputs. JSON objects with a non-callable own `toString` fail coercion,
including when nested in an array. Numbers keep JavaScript formatting before
finite DTO conversion; metadata is not used as authority.

Permission checking preserves the source XOR, including selecting one valid
alias while stripping an invalid alternative. A valid singular `permission`
then receives the source handler's message-only 400 before session lookup;
only plural `permissions` reaches the authenticated permission check. A caller's
body role/userId never replaces the actual session principal.

Every handler validates before its existing optional-session and permission
checks. The schema-less stop route still parses media/JSON. Query validation
retains missing versus empty IDs and the source's ordered enum issues. Valid
requests continue through the existing session cleanup, permission, store and
application error paths; this change adds no global error mapper or storage API.

Create-user schema accepts any string email and an empty name/password. The tiny
approved `create_user_core` change lowercases email and applies the pinned ASCII
zod email grammar after requested-role validation but before duplicate lookup
or writes, returning coded `INVALID_EMAIL`. Invalid emails cannot be persisted;
an unauthorized caller still receives its earlier 401/403. Empty password creates
no credential account, and successful empty-name creation remains legitimate.

## Primary proof and regressions

Six official-client scenarios own this contract. Three actual session modes
(missing, one-character tampered signature, and publicly revoked signed cookie)
exercise all body schemas, exact ordered field errors and absent cleanup cookies.
The authenticated media/JSON scenario reaches every POST operation, including
stop-impersonating. Query/permission controls protect empty-ID error ownership,
alias selection and foreign role/userId spoofing. The email owner checks denied
creation, role-before-email errors, precise granted email rejection and legitimate
lowercase empty-name/password persistence without accounts or sessions. Existing
real SQL fixture reads by each rejected email also require absent users, accounts
and sessions, so checking only the preexisting owners cannot hide an insertion.

Complete public user reads and stored user/account/session observations remain
unchanged after rejected batches. Positive controls retain authorized reads and
set-role writes; a nested-array ID returns the target's real issued session,
while an ordinary user's array-ID ban remains denied. Actual current sessions,
tokens, complete SDK results, HTTP errors and primary transport traces remain
observable. Expected errors come from the pinned runtime, not this validator.

The unchanged Rust binary is preserved at `/tmp/admin-schema-before-server`.
All six scenarios fail on that baseline for the intended production errors in
`/tmp/admin-schema-sdk-before.log`; the stronger complete-control rerun is retained
in `/tmp/admin-schema-sdk-before-complete.log` (six intended failures, 618 assertions). The genuine source-to-source comparator defect
for matching empty query IDs is separate: `/tmp/admin-schema-sdk-oracle-final.log`
passes five scenarios and fails only the three empty URL-query identity paths.
The coordinator's reviewed narrow prerequisite is `80a17211`; branch-local
`7f60e76e` adapts only its URL-origin traversal parameter to this earlier comparator
without the separate encrypted-cookie parameter. The feature commit contains no
harness hunks. No empty-ID control or transport observation is removed.

## Explicit boundaries

The current shared `AuthRequest.query` represents each key as one string, losing
duplicate values that better-call validates as arrays. Duplicate-query fidelity
needs a separate core representation change and is not claimed here. Fractional,
negative and nonnumeric list limits and other list filter/storage semantics also
remain their existing owners. This slice does not expand creation extra-field
authority/ban semantics, password policy, duplicate error mapping, arbitrary user
metadata persistence, trusted server API methods, global hook ordering, or all
framework body-stream conventions. Shared origin/rate/body middleware ordering
remains outside this route-local slice; actual source and client probes use the
existing transport's real Origin headers. The endpoint schemas expose no new server-only
or public method. Root owns capability inventory, dependency locks and full gates.

## Focused checks

* Production baseline: `/tmp/admin-schema-sdk-before.log`, six intended failures.
* Source/source and repaired production before the narrow harness prerequisite:
  `/tmp/admin-schema-sdk-oracle-with-controls.log` and
  `/tmp/admin-schema-sdk-after-before-harness.log`, five pass and only the known
  three matching empty-query trace failures.
* Existing admin native owner: `/tmp/admin-schema-native-final.log`, 12 pass.
* API strict Clippy: `/tmp/admin-schema-clippy-final.log`.
* TypeScript: `/tmp/admin-schema-typecheck-final.log`.
* Current-tree baseline/final fixture builds: `/tmp/admin-schema-build-before.log`
  and `/tmp/admin-schema-build-final.log`; binaries copied before/after changes.

Two concurrently launched manual checks accidentally shared a source server and
its reset boundary. Their setup failures are retained as
`/tmp/admin-schema-sdk-invalid-shared-reset.log` and
`/tmp/admin-schema-sdk-oracle-invalid-shared-reset.log`; they are excluded from
behavior evidence. All final server-pair runs are sequential.

Final focused evidence after the separate URL prerequisite:

* `/tmp/admin-schema-family-final.log`: all 34 admin scenarios pass 3024 assertions
  across 10 files, including all six new owners and the previous admin callbacks,
  durations, roles, timestamp and guest-wire controls.
* `/tmp/admin-schema-sdk-oracle-complete.log`: the same six new owners pass 1126
  assertions against two genuine pinned source servers, with complete traces.
* `/tmp/admin-schema-typecheck-complete.log`: current final TypeScript passes.
* `/tmp/admin-schema-url-harness-final.log`: all 33 comparator owners on this
  earlier parent pass 233 assertions, including the actual empty-query regression.
* `/tmp/admin-schema-fixture-clippy-final.log`: current fixture strict Clippy
  passes; `/tmp/admin-schema-clippy-final.log` covers the production API library.
* Existing native store/business controls remain 12/12 in
  `/tmp/admin-schema-native-final.log`; no duplicated private predicate tests or
  new production test seams were added.

The feature owns only admin mod/types/private validation, the approved tiny
create helper change, one official-client test module and this audit. Root owns
independent review, final integration, capability evidence and full gates.
