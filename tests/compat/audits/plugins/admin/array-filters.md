# Admin array filters against Better Auth 1.7.6

The official admin client's array filterValue becomes repeated query operands.
The pinned route validates string-or-string-array and awaits adapter findMany
and count only after signed-session/admin permission checks. Its query-error
catch returns {users:[],total:0}, omitting limit/offset even when supplied.

Source investigation uses the actual installed dist/plugins/admin/routes.mjs,
@better-auth/core/dist/db/adapter/factory.mjs and the bundled Kysely/SQLite
adapter. The standalone source probe is retained in
/tmp/admin-array-source-probe.log. Distinct observed behavior includes:

- in/not_in bind every array operand; order or duplicate operands cannot add
  duplicate result rows. Limit/offset select after filtering and total is unpaged.
- contains/starts_with/ends_with bind the comma-joined array into SQL LIKE.
  SQLite case/wildcard rules apply, including literal-looking % and _ input.
- eq/ne/lt/lte/gt/gte multiple operands produce actual SQLite row-value errors;
  the route returns its empty successful result without pagination fields.
- scalar in errors because the adapter requires an array. Scalar not_in is a
  singleton membership query. A boolean scalar string is transformed to true
  only for the exact string "true"; arrays retain their original string values.

Rust preserves the actual ordered query operands across Axum and dispatch,
uses the public UserFilterValue::{Scalar,Multiple} for idiomatic native list
parameters, and executes bound expressions against the configured SeaORM
model column. It removes only that already-executed filter from the shared
search/sort/page helper. There is no interpolated raw SQL or field-name injection.
SeaOrmUserModel::list_users_column provides bindings; AuthEntity derives its
application/plugin columns with their actual physical mappings. Manual models
retain default core bindings and can supply additional typed columns.
Actual boolean scalar binding uses the model's Boolean column definition.

Only the list_users adapter call is caught after authentication and permission
resolution; malformed route input, absent sessions and denied principals never
enter this success catch. No placeholder query result bypasses the store.

One official-client primary owner protects membership order/duplicates,
ID/email/boolean fields, SQL patterns/errors, scalar distinctions, paging and
legitimate retry. Every SDK result/user field/raw trace is retained, and complete
observed user/account/session snapshots are unchanged before/after the reads.
A guest gets 401; a real member gets 403. Actual random ID filter values needed
the separately reviewed narrow observed-identity URL comparator repair; other
fields, operators, array shape and unobserved values remain literal.

Before production repair the primary owner fails against the prior real Rust
fixture at expected Alpha/Beta membership (/tmp/admin-array-native-before-proof.log).
The expanded Source-to-Source boolean proof passes, while the intermediate
native scalar boolean implementation fails (/tmp/admin-array-native-boolean-before.log).
The final entire admin family passes 36 / 3,238 assertions in
/tmp/admin-array-family-boolean-final.log. There is no oracle behavior change.

A distinct native consumer exercises an application AuthEntity with a physically
renamed custom locale column through the public generic UserStore. It verifies
membership, unpaged total/paging, scalar Boolean coercion and retained application
rows. This custom-schema contract is unreachable through the bundled SDK fixture.
Independent review found a derive panic for raw identifiers and incorrect custom
enum-name binding. The repair delegates ordinary/raw column resolution to SeaORM
and honors explicit enum_name. The same real-store consumer proves enum-name-only,
physically renamed enum-name, and raw physically renamed fields. The actual
pre-repair compiler panic is retained in /tmp/admin-array-custom-binding-before.log;
three native owners pass in /tmp/admin-array-custom-binding-final.log.
The organization owner reviewed the full slice; the coordinator independently
reviewed this targeted macro repair. No production blocker remains.

Focused locked fixture, workspace optional compilation, strict Clippy, TypeScript
and native siblings pass in /tmp/admin-array-*.log; the coordinator owns the final
integrated gate and required evidence. No schema migration/dependency version or
lock change, comparison exception, coverage-floor change or skipped case is used.
The repository's native checks and independent review replace unavailable
external test-audit commands, not the required repository gate.

This establishes the observed database-backed string/boolean array branches.
It does not establish arbitrary custom numeric/date/JSON schema transformations,
undeclared plugin fields, all default sorting/paging/coercion or non-SQL adapters.
The generic in-memory helper provides logical array filtering and does not claim
SQLite wildcard or tuple-error behavior. Server-only numeric/boolean operands,
additional query consumers and wider provider/storage configurations remain
explicit subsequent capabilities.
