# Explicit admin-role configuration validation

Installed Better Auth 1.7.6 `plugins/admin/admin.mjs` validates adminRoles only
when supplied. The factory accepts an omitted adminRoles with roles:{} or a
custom table missing admin. An explicit ['admin'] with roles:{} rejects, while
an explicit [] accepts. Each explicit role is compared case-insensitively with
configured table keys (or builtin admin/user keys), without trimming; invalid
roles retain input order and duplicates in the error. The constructor oracle
`/tmp/admin-role-constructor-oracle.log` exercises those actual factory cases,
including uppercase, whitespace, empty arrays, and multiple invalid values.

The public native contract is now `AdminConfig.admin_roles: Option<Vec<String>>`,
default None. None retains the source effective admin target-classification role;
Some(empty) retains the explicit empty target role list. `AdminPlugin::on_init`
validates only Some, before its own user transforms and metadata registration,
returning AuthError::Config with the exact source detail message. The existing
single custom-role native constructor is adapted to Some. Permission matching
remains exact and case-sensitive; accepting an uppercase configuration role at
initialization does not rewrite stored/user role tokens or custom table keys.

One native public AuthBuilder test is the primary configuration owner. Nine
cases initialize an actual installed SQLite store. A genuine later application
plugin bootstraps a user through the public store. Invalid configurations must
return the exact Config detail and leave its bootstrap row absent; accepted
configurations actually run that initialization. Accepted instances then create
and read a real application user through their transformed trusted store,
confirming normal default role and ban behavior remain installed. Existing
user and issued session snapshots remain identical across all cases. This is
an observable application initialization/persistence boundary, not a private
predicate, fake constructor HTTP endpoint, call counter, or production test seam.

`/tmp/admin-role-constructor-native-before.log` runs the unchanged d5bde17 owner
with the same test. Its old Vec field receives the equivalent implicit/default
array at the configuration boundary because it cannot represent absence; it
accepts the first explicit invalid admin/empty table and the test fails with
'invalid-empty: invalid role configuration initialized'. The repaired Option
representation passes `/tmp/admin-role-constructor-native-final.log`.
The existing 11 native admin cases remain in
`/tmp/admin-role-constructor-native-family.log`; all 11 official-client admin
cases remain in `/tmp/admin-role-constructor-sdk-final.log`. Focused public-test
strict Clippy and actual fixture build are recorded in
`/tmp/admin-role-constructor-{clippy,build}-final.log`; formatting and diff checks
are also complete. The coordinator owns inventories, locks and canonical gates.

Timing boundary: source rejects during its synchronous plugin factory; Rust
rejects during asynchronous public AuthBuilder initialization. That is the
idiomatic native entry point, but earlier other-plugin initialization side
effects are not claimed equivalent. No rollback or universal initialization
ordering guarantee is introduced. Source also accepts adminRoles strings,
including empty-string truthiness differences and comma strings; the native
Vec contract covers configured arrays only. Non-ASCII JavaScript case mapping,
custom key/prototype role objects and callback-based role implementations are
not claimed closed. The sibling permission audit retains literal role-value
schema/validation and dynamic-message/duration gaps for later independent work.
No SDK constructor-control endpoint, lock, schema, migration, inventory,
comparator or dependency change belongs to this capability.
