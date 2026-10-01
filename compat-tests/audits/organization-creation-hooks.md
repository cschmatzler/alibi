# Organization creation lifecycle callbacks (Better Auth 1.7.6)

This capability ports the supported creation callbacks, not organization deletion
or every organization hook. The implementation uses application-configured
`Arc<dyn OrganizationCreationHooks>` and immutable draft/persisted contexts.
The public HTTP body cannot select callback modes or supply the acting user.
The existing trusted `create_organization_for_user` helper resolves its user
from storage and invokes the same creation lifecycle without request selection.

## Pinned source and actual runtime

The installed `better-auth@1.7.6` sources are
`dist/plugins/organization/routes/crud-org.mjs` (`createOrganization`) and
`dist/plugins/organization/adapter.mjs` (`createOrganization`, `createMember`,
`createTeam`, `findOrCreateTeamMember`, `setActiveOrganization`, `setActiveTeam`).
Creation policy, membership-count limit, and the initial duplicate-slug check
precede callbacks. Creation callbacks receive one data argument; unlike the
separate deletion hooks they do not receive endpoint context as a second
argument. Before callbacks merge a returned `data` object without revalidation.

The awaited order and real writes are:

1. `beforeCreateOrganization` receives the validated organization draft and
   actual user. Its supported patch overrides ID/name/slug/logo/metadata.
2. Persist the organization. `beforeAddMember` receives this persisted
   organization, the actual creator-member draft, and the same user.
3. Persist the member. `afterAddMember` receives persisted organization/member
   snapshots. A callback can perform separate application-owned database work.
4. When enabled, run the existing `beforeCreateTeam`, default-team creation,
   original user's team membership write, and `afterCreateTeam` phases.
5. `afterCreateOrganization` receives the organization, user, and original
   member snapshot. Then the HTTP handler selects organization/team on only
   its authenticated token unless `keepCurrentActiveOrganization` requests
   preservation. Requestless trusted creation selects no session.

There is no new transaction around these phases. Callback errors leave earlier
rows intact and prevent later writes/selection. The existing adapter operations
retain their own local transaction boundaries. Duplicate creation now returns
source `400 ORGANIZATION_ALREADY_EXISTS` / `Organization already exists` before
any creation callback; the update duplicate-slug branch was not changed.

An independent pinned-runtime probe in
`/tmp/organization-lifecycle-source-runtime.log` demonstrated returned ID/name/
slug/role patches, the six callback phases, before/after error partial states,
requestless creation, and metadata patch branches. It also confirmed that a
before-member returned ID is ignored by the source adapter, while an empty
returned role persists. The typed member patch therefore supplies user/org/role
and does not add a member-ID override that the source does not support.

A missing metadata patch retains the draft; an empty record stores `{}`. A
returned `metadata:null` applies the pinned creation adapter's falsy-null policy:
SQL NULL and omitted creation response metadata. It is represented by
`OrganizationCreatePatch.metadata = Some(None)` and is deliberately distinct
from the public store's `Some(Value::Null)` literal JSON-null write. Returned
`logo:null` clears the logo. Returned empty name/role bypass request validation
and persist; these supported patches are not revalidated by the Rust owner.

## Proof and regression value

`tests/organization-extensions/creation-hooks.test.ts` owns seven real
HTTP/official-client scenarios with private application fixtures:

- Patches affect actual stored organization/member/default-team rows, callback
  snapshots contain the authenticated principal despite forged HTTP `userId`,
  and six receipts observe each phase's actual SQL state before selection.
- No-team profiles distinguish omitted/null/empty metadata and allow source
  empty-name/empty-member patches without accidental fallback or revalidation.
- Rejection at every before/after org/member/team phase checks exact preceding
  row deltas, all prior records, both current/sibling session selections, and
  unchanged users. A success response or receipt alone cannot pass this test.
- Denied creation and an existing slug reject before callbacks; trusted
  requestless creation bypasses only the allow-policy denial, invokes callbacks,
  and leaves sessions untouched.
- An actual after-member database update changes its role to admin, while the
  later callback and response retain the original owner snapshot. This catches
  accidental refetching or mutation of completed callback snapshots.
- A callback actually waits on an asynchronous application gate. One bounded
  private state waiter observes real after-member delivery and database rows;
  no team write or token selection occurs before release. Every HTTP request
  remains traced, and the comparator is unchanged.
- Trusted member patches redirect user/organization while callback authority,
  default-team membership, and current-token selection continue to use the
  original authenticated actor. The foreign session and previous rows remain
  unchanged. These privileged overrides are configured by the application,
  never derived from public request control fields.

The dedicated source fixture invokes pinned callbacks on actual `betterAuth`
profiles and reads Bun SQLite. The Rust fixture invokes the public callback
traits/helper and reads actual SeaORM SQLite. Private fixture modes cannot
replace production callback receipts, writes, or authorization decisions.

The exact previous production `org.rs` and error mapping from `d31e40b` were
replayed against unchanged callback definitions/fixtures. All seven scenarios
failed for missing callback/patch/rejection/ordering behavior in
`/tmp/org-creation-hooks-sdk-before.log`; the correct production was restored
byte-for-byte. Final whole organization/default/configured SDK proof is 53
scenarios / 3254 assertions in `/tmp/org-creation-hooks-sdk-final.log`.
Owner API native tests (321 passed), strict API-library/fixture Clippy, client TypeScript,
changed reference fixture TypeScript, and formatting are checked separately.
The coordinator owns the full gate, capability evidence inventory, and locks.

## Explicit boundaries

The typed callbacks cover bundled organization/member fields and public user
views. They do not reproduce JavaScript argument/user mutation, arbitrary
additional SQL columns, non-JSON JavaScript patch values, or every custom
organization schema. Draft `Option<String>` collapses the original HTTP
logo property's absent/null distinction; supported returned logo patches retain
three-state semantics. Capturing an application store supports independent
persistence without exposing mutable framework authority. Creation-only member
callbacks do not claim delivery for ordinary add-member/invitation routes.
Existing default-team factory configuration and all deletion/update hooks are
separate capabilities. Explicit callback `AuthResult` errors are covered;
generic JavaScript throws and Rust panics are not declared equivalent.

A real HTTP-disconnect probe, with correct `/__test/reset-state` isolation,
records `/tmp/org-creation-hooks-abort-runtime.log`. Both runtimes persist the
organization and member while `afterAddMember` waits. Aborting the client fetch
then allowing 200 ms for disconnect propagation and releasing the callback lets
pinned Bun finish team/team-member/after-org
and token selection. Axum cancels the request future and retains only the prior
organization/member writes. This is an unresolved framework continuation and
shutdown/task-ownership boundary, not silently repaired by detaching creation
callbacks. Normal awaited callback completion and controlled errors remain the
scope of the capability above.

Organization deletion ordering/orphan effects, default adapter page limits,
empty-update prepared-query behavior, and wider cookie/cache/schema settings
remain separately audited work. No synthetic SQL error or transaction was added
to manufacture parity for those branches.
