# Member role lifecycle against Better Auth 1.7.6

Pinned `dist/plugins/organization/routes/crud-members.mjs:278-371` validates the
initial roles and their grants, resolves the raw organization and TARGET user,
then awaits before-update, adapter update and after-update callbacks. The before
context contains the original target membership and normalized requested role;
it does not supply the current actor or request. The after context contains the
actual updated member, previous role, original target user and raw organization.
The existing raw organization projection retains stored metadata JSON text.

`OrganizationConfig.member_role_hooks` is an immutable application-owned Arc.
`OrganizationMemberRoleHooks` exposes default no-op before/after methods over
immutable typed contexts. `OrganizationMemberRolePatch.role` supports string
patches: missing/empty values fall back to the normalized initial role; nonempty
values are stored verbatim without another role validation pass. This includes a
trusted callback assigning an unregistered role. The following ordinary request
uses the actual stored grants and is denied before callbacks if that role has no
update permission. No client request field controls callback mode or actor.

Before errors stop the adapter write; after errors retain it. Independent hook
writes are not rolled back by a new lifecycle transaction. Target user and
organization snapshots remain original across these writes; after-update uses
the actual updated member and the original previous role. No invented callback
actor/request arguments are added.

## Optional-row storage

The additive public `MemberStore::update_member_role_if_present` returns an
actual updated member or `None` for no row; other failures remain errors. Its
default and unsupported MemoryStore implementation fail closed with
NotImplemented. PluginStore forwards it. SeaOrmStore performs actual lookup and
`ActiveModelTrait::update`, preserving model before_save/after_save dispatch
(`sea-orm 2.0.0-rc.37 src/entity/active_model.rs:337-345`). Only an actual
RecordNotUpdated maps to absence; SQL/query/model errors remain errors. The
original `update_member_role` API and its missing-row error behavior remain
unchanged. The optional operation is selected only for configured role hooks.

A before hook can delete the real member. The actual subsequent adapter absence
returns source 400 MEMBER_NOT_FOUND and does not invoke the after callback. This
is not a manufactured missing-row receipt. Source probes
`/tmp/organization-member-role-hooks-lifecycle-probe.log` and
`/tmp/organization-member-role-hooks-ignore-probe.log` independently demonstrate
actual deletion and SQLite RAISE(IGNORE) yielding this rejection with only the
before callback. The ignored row retains its original stored role. The independent omitted-metadata
probe `/tmp/organization-member-role-hooks-absent-metadata-probe.log` also confirms
that this raw callback organization includes metadata null for a SQL NULL row;
it is distinct from parsed update-response omission.

`store/member_role_tests.rs` owns the separate native public-store boundary:
actual updated row/readback, SQL ABORT veto distinguished from absence, SQL
IGNORE zero-row result with the original row retained, real deletion followed by
absence, unchanged original API behavior, and preserved unrelated member and
organization rows. Bundled member ActiveModelBehavior is empty; the existing
schema API does not promise replacing the member model with a custom entity.

## Primary evidence

`tests/organization/member-role-hooks.test.ts` owns six meaningful
SDK scenarios: normalized callback input/empty and absent patch fallback,
unregistered nonempty patch and next-request denial; before/after error state;
foreign membership and role validation before callbacks; original target user
snapshots despite independent user/member writes; actual member deletion before
update; and a genuinely awaited callback before any SQL role change. Actual
receipts are emitted only by registered callbacks and capture physical SQLite
state at their phases. Foreign organizations, users, memberships and sibling
sessions retain their observed rows. No comparator or pinned auth implementation
is modified. Async release retains its complete separately traced transport
rather than suppressing or sorting concurrent exchanges.

Private application fixtures configure actual hook objects outside public auth
requests. The Rust fixture reuses the existing update fixture's private SQL
snapshot helper; this is test-support sharing, not a production export or seam.
The separate default role-normalization prerequisite owns string/array,
whitespace and duplicate storage behavior in the existing members SDK owner.

`/tmp/org-member-role-hooks-oracle.log`: 6 pinned source-self scenarios / 434
assertions. `/tmp/org-member-role-hooks-sdk-initial.log`: the 6 strict callback
scenarios and 4 existing/default member scenarios / 464 assertions pass.
`/tmp/org-member-role-hooks-sdk-before.log` removes only callback execution from
the native handler with the approved normalization prerequisite retained: five
scenarios fail for missing receipts, incorrect error/write phase, absent trusted
patches or missing-row behavior; the guards control still passes. The fixtures,
primary SDK owner and comparator are unchanged. The correct handler is restored
before final validation.

Final focused organization/OpenAPI siblings pass 89 scenarios / 5466 assertions
in `/tmp/org-member-role-hooks-family-final.log`. API native siblings pass 332
and SeaORM native siblings pass 51 (including the distinct optional-member store
owner). Strict production and fixture Clippy, SDK TypeScript, the locked fixture
build and the public rustls/axum/SeaORM/Redis consumer build all pass. Proof is
recorded in
`/tmp/org-member-role-hooks-family-final.log`,
`/tmp/org-member-role-hooks-api-native-final.log`,
`/tmp/org-member-role-hooks-seaorm-native.log`,
`/tmp/org-member-role-hooks-production-clippy.log`,
`/tmp/org-member-role-hooks-fixture-clippy.log`,
`/tmp/org-member-role-hooks-typecheck-final.log`,
`/tmp/org-member-role-hooks-final-build.log` and
`/tmp/org-member-role-hooks-consumer-final.log`. The canonical gate, inventory,
locks and publication remain coordinator-owned.

## Explicit scope

Hook parity here covers initially validated NONEMPTY roles. The preexisting
empty initial role guard remains unresolved: pinned source returns empty400,
while the current Rust handler can reach storage/callbacks. Its body/auth ordering
also remains a separate member-input capability, with a configured callback
negative control required before claiming those branches. No generic coded error
is substituted for source's empty response.

Snapshots cover canonical Member and configured UserView columns. Source joined
user data, custom physical membership/organization columns, direct JavaScript
argument mutation, undefined/prototype behavior and non-string trusted role
patches are not claimed. Default no-hook missing-row errors and broader member
input/owner-count/order branches are unchanged. Removal/addition lifecycle hooks
are separate capabilities. This slice supplies no global trusted server-API
dispatcher or API-key-only equivalence and does not independently prove HTTP
cancellation continuation or shutdown behavior.
