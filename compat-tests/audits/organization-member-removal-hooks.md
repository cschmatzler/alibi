# Organization member removal callbacks against Better Auth 1.7.6

This capability follows the separately frozen member-removal defaults/storage
prerequisite 4cedcae7. It does not change stores, schema, migrations or the old
delete/list APIs. The production changes add immutable configuration, typed
callbacks and a signed-header native operation over the same removal core.

Pinned `dist/plugins/organization/routes/crud-members.mjs:172-229` resolves the
requester, target, last-owner/permission/tenant guards, raw organization and target
user before invoking beforeRemoveMember. It passes only member, user and
organization: no actor, request, headers or patch argument is invented. An email
selector includes the joined user in member; ID selection strips that join.
The callback is awaited. Adapter deletion then uses the original member ID,
organization and user. Current-token selection clearing happens after that
transaction and before afterRemoveMember. Both callbacks receive the original
snapshots and the response returns the original member. Returned callback data
is ignored by the source, so the Rust removal callbacks return AuthResult<()>.

OrganizationMemberRemovalContext holds the full supported member snapshot,
target UserView and raw OrganizationResponse. OrganizationConfig stores the
optional shared immutable OrganizationMemberRemovalHooks. Before errors prevent
ordinary deletion; after errors retain deletion and current-session clearing.
The lifecycle is deliberately not wrapped in a new transaction. Independent
application writes made by a callback persist normally. The captured contextual
store operation remains the distinct transaction boundary from the prerequisite.

The public remove_member_with_headers(ctx, headers, typed_body) operation
requires an actual supplied header map and authenticates a signed-cookie session.
Header names normalize only for existing session resolution. The operation shares
the same business core, callbacks and store writes as HTTP. A body userId cannot
choose authority. Upstream requires headers for its server API; Rust expresses
that required argument statically, with an empty supplied map authenticating as
unauthorized. The nested session-error catch remains limited to session resolution;
subsequent store/application errors are preserved. No global server dispatcher
or virtual API-key session is manufactured by the helper.

The unchanged published runtime was first exercised with an independent probe
(`/tmp/organization-member-remove-source-probe.log`): target joins, before/after
errors, independent deletion/mutation, missing and foreign guards, exact owner
page order, enabled/disabled/paged teams, SQL ABORT rollback versus IGNORE, current
and sibling selections, and required-header/expired-session server calls. That
probe demonstrates partial writes and original callback snapshots independently
of the Rust implementation. The source adapter delete ordering and default Bun
transaction configuration are recorded in the prerequisite audit.

Ten official-client scenarios now own actual callback delivery and its effects:

- ID and uppercase-email selection preserve the whole known target-user,
  member-createdAt/join and raw organization values through both phases and
  the response. Callback receipts record actual SQLite state before and after.
- Genuine before and after callback errors preserve the respective source write
  phases. A before callback independently deletes the real member or changes
  its role and the target's stored name; the later callback still receives the
  originals, and team cleanup still uses the original authorized scope.
- Permission, last-owner, wrong requester, foreign target, missing target and
  malformed-body controls reach no configured callback or mutation; legitimate
  retries reach both phases. Public userId never grants server authority.
- Self-removal, including after-hook rejection, clears only the current active
  organization. Both current and sibling activeTeamId values remain, and the
  sibling organization remains selected. These are the measured source defaults.
- A disabled-team profile retains real team memberships seeded by the enabled
  profile. A default-page-one profile removes only the actual first team page.
  A membership-page-one profile rejects removal despite two persisted owners,
  then the ordinary profile succeeds. No sort, extra rows or expected result is
  injected by these profiles.
- An actual async before callback blocks member/team writes until released.
  The bounded waiter reads real receipts; it cannot invent delivery. Its
  independent release transport is retained via recordTransport after the pending
  operation, preventing incidental concurrent response completion order from
  changing trace order. No trace, field or cookie is suppressed.
- The trusted header helper rejects guest/foreign authority, then successfully
  removes by email using the real cookie. A separately expired actual session
  is deleted without a callback or sibling mutation; the surviving sibling then
  succeeds. Parsed source auth.api errors expose no queued cleanup cookie, which
  the private server fixture preserves; ordinary HTTP dispatch owns cookie cleanup.

All fixtures live under controlled __test interfaces. They configure real
application callbacks and read actual rows. Before-delete calls the native public
contextual store with team cleanup disabled, matching the source independent
adapter deletion; the ordinary core operation then performs the real cleanup.
Neither fixture supplies expected callback phases or fake successful persistence.
The source hooks and authentication runtime are unmodified.

The initial unchanged pinned-self owner passes 9 scenarios / 1174 assertions
(`/tmp/org-member-removal-hooks-oracle.log`). The final primary differential,
including expiry and stronger foreign/missing guards, passes 10 / 1300
(`/tmp/org-member-removal-hooks-sdk-final.log`). A separately built delivery
negative control removes only the two production callback invocations, retaining
the same actual fixtures, public types/helper, storage and guards. All ten owners
fail for missing callback receipts, missing callback errors or premature async
writes (`/tmp/org-member-removal-hooks-before.log`, 0/10, 1011 assertions). This is
an incorrect-implementation delivery control, not a claim that the preceding
public API already declared these new callback types. Production was restored
before tests and final checks; no source/test edits occurred during Bun runs.

The final complete organization, extension and actual OpenAPI focused owners pass
109 SDK scenarios / 7804 assertions (`/tmp/org-member-removal-hooks-family-final.log`).
All 332 API library siblings pass (`org-member-removal-hooks-api-final.log`);
the prerequisite's 53 SeaORM siblings remain unchanged by this callback commit.
Core/API/SeaORM strict library Clippy, actual fixture strict all-target Clippy,
client TypeScript, locked fixture build and both format checks pass in
`org-member-removal-hooks-{clippy-final,fixture-clippy-final,typecheck-final,
build-final,format-final,format-fixture-final}.log`. The one existing exhaustive
API test configuration gains only the mechanical new None callback field.

Boundaries retained explicitly: direct JavaScript callback-argument mutation,
undefined/prototype/arbitrary custom joined columns, global server-API/API-key
dispatch and continuation after HTTP cancellation require separate contracts.
The target UserView covers the declared native user projection; trusted custom
storage access remains available by capturing an application store. Source
last-owner guards are outside the deletion transaction; no new concurrency/CAS
guarantee is claimed. HTTP native database errors still differ from Bun's empty
500; actual native SQL rollback/error owners are in the defaults prerequisite.
No synthetic adapter error, global mapper change, comparator/clock/tolerance,
dependency/lock or inventory modification is introduced. The coordinator owns
independent review, full gates and publication; external autoreview is unavailable.
