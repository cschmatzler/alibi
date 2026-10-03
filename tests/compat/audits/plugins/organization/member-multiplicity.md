# Physical organization membership rows

Pinned reference: published `better-auth@1.7.6`, organization
`routes/crud-members.mjs` (`addMember`, `removeMember`, `updateMemberRole`),
`adapter.mjs` (`createMember`, `findMemberByOrgId`, `listMembers`,
`listOrganizations`, `deleteMember`), and the generated SQLite member table.
The member ID is unique; the organization/user pair is not. The initial admission
duplicate check happens before trusted hook patches and is not a pair lock.

Actual isolated runtime evidence is preserved in these scripts and logs:

- `/tmp/organization-duplicate-admission-probe.mjs` and `.log`: four fresh
  lifecycles establish trusted retargeting and overlapping unmodified admissions,
  distinct IDs for the same pair, physical totals/pages, repeated organizations,
  sequential duplicate rejection, first-member role authority, foreign actor
  rejection, exact-ID mutation, and team cleanup despite a remaining sibling.
  Duplicate owner email removal clears the current selection while a second
  owner row remains. The concurrency barrier is a genuine application before
  callback; it returns no patch and does not replace adapter results.
- `/tmp/organization-membership-page-probe.mjs` and `.log`: older/newer real
  organizations receive memberships in newer/older/newer order. Full returned
  rows retain that order and multiplicity. Configured pages 2, 1 and 0 apply to
  member rows. Foreign listing is empty. An organization limit of 3 rejects
  creation with three physical memberships despite only two distinct
  organizations; smaller configured pages permit genuine creation and deletion.

The bundled member table has no unique organization/user index. The single squashed auth migration installs this shape; there is no upgrade path from earlier bundled shapes.
Application constraints/indexes remain application-owned.

`OrganizationStore::list_user_organizations` keeps its existing public return
type. The bundled implementation selects the caller's physical member page with
`advanced.database.default_find_many_limit`, joins organizations, then projects
them in member-page order, including repetitions. Organization creation dates
do not reorder that page. Returned organization fields are unchanged.

Existing member operations are unchanged: pair lookup returns the adapter's
selected first row, roles are not unioned, counts/pages include physical rows,
and role update/deletion targets a member ID. Contextual deletion uses the
captured original organization/user for team cleanup even when another member
row for that pair remains. This is a low-level store contract; caller
authorization remains in the existing route/helper logic.

The native owners prove:

- A published-style unconstrained table protects the consumer: full
  newer/older/newer output, physical pages 100/2/1/0, first-member lookup and
  exact-ID deletion with scoped team-seat cleanup retain full peer
  organization/user/member and foreign team state.
- Two independently opened SQLite connections admit both actual inserts with
  distinct IDs and roles for one pair. Both connections read the persisted rows
  and the unrelated peer remains unchanged. This is a storage admission proof,
  not a claim of atomic API capacity enforcement.

Before-fix controls use the actual baseline production: all three fail in
`/tmp/organization-member-multiplicity-native-three-before.log`. The installed
and independent-connection cases fail on the real pair UNIQUE constraint; the
consumer fails on deduplicated organization-creation order. The initial test
compile setup failure is retained separately and is not counted as a behavioral
failure. Final focused SeaORM family: 60 native tests pass in
`/tmp/organization-member-multiplicity-seaorm-final.log`.
The final locked focused owner passes three tests in
`/tmp/organization-member-multiplicity-native-final.log`.
Strict production Clippy passes in
`/tmp/organization-member-multiplicity-production-clippy.log`; the locked
downstream root build without default features and with
`rustls,axum,seaorm,redis-cache` passes in
`/tmp/organization-member-multiplicity-consumer.log`. An exploratory
`--all-targets` Clippy invocation found existing test-only warnings outside this
slice; that nonpassing log is retained and is not represented as a passed check.
The new native assertions use the conventional scoped `panic_in_result_fn`
expectation while setup errors still propagate.

Custom-store boundary: stock native MemoryStore does not implement member state;
its unsupported/inert operations are unchanged. Published JavaScript memory
storage appends member rows, selects its first match, and counts physical rows.
Custom persistent adapters are responsible for matching these row semantics;
this change adds no new traits, models, macros or implicit pair deduplication.

Limits: SQLite runtime behavior is proved. PostgreSQL
execution, unusual dangling rows, arbitrary joined custom columns, non-integer
or nonfinite page configuration, and adapter-specific unordered query plans are
not claimed. A dangling native member still omits its missing organization,
preserving the prior nonnullable return contract. Source invitation conditional
accept/reset, rollback failures, pre-transaction capacity checks and lifecycle
hooks remain a separate capability. The server-only add-member duplicate-hook
SDK extension follows its independently frozen helper dependency; this storage
prerequisite does not claim that additional end-to-end evidence yet.

## Real SDK admission and consumer owners

The separately reviewable SDK extension is based on master `8c0c8dc1` with the
frozen storage prerequisite `0d0ba40c` and installed-FK guard `5324954f`.
It changes only the existing private member-addition application fixtures,
adds four literal configuration profiles, and adds three primary owners in
`tests/plugins/organization/member-multiplicity.test.ts`. Existing primary
owners, the comparator, default deadlines, production handlers, schemas, main
fixture registrations, dependencies and inventories remain unchanged.

The authoring contract is physical membership admission and its observable
consumers. Earlier owners cannot reach duplicate rows because the old unique
index rejects them. The independently connected storage race retains its
distinct boundary; these SDK owners exercise the actual official client and
unchanged published server-only helper.

- A genuine trusted before-add patch retargets a new candidate to an existing
  member, creates a second physical row with an `admin` role, and observes the
  original callback authority and actual persisted result. The target retains
  its first row's `member` authority; its role update is denied, as are foreign
  role update and removal. The owner changes only the second ID to `owner` and
  removes that ID while the original remains. Complete member/team/team-member
  rows and dates prove scoped team-link removal and counter adjustment, retained
  owner links, foreign team/user/session preservation, and an unchanged target
  session selection. A real sequential retry rejects before any callback.
- Real newer/older/newer admissions produce the complete repeated organization
  output in physical membership order. Default and configured pages 2, 1 and 0
  are checked against those full objects. An organization limit of three rejects
  creation at three visible membership rows but allows actual creation/deletion
  for each smaller page. Each profile uses the existing legitimate target
  session through the official client's fetch transport. This isolates the
  organization page contract: the measured Source zero-page profile cannot find
  its credential account during a new password sign-in. Foreign organizations
  and the full foreign user state remain unchanged.
- Two ordinary admissions reach the actual application before callback after
  both genuine prechecks. The application barrier returns no patch. Serial
  release retains each full request/response transport and real callback SQL
  snapshot while making neither insertion nor capacity decisions. Both distinct
  IDs persist, member count/page and duplicate organization output are observed,
  and a later sequential retry rejects without writes or callback receipts.
  This proves overlapping admission without claiming arbitrary response
  completion ordering or concurrent capacity enforcement.

The optional private `full` state selector retains all bundled member, team and
team-member columns, including dates and nullable fields. A nonnull physical
`membershipKey` is independently checked against the actual SHA-256 tuple
encoding, then retained losslessly as a token plus the original team/user
components. This lets the existing identity graph compare generated inputs and
outputs together; it adds no comparator exemption or opaque field suppression.
Full actor user/account/session observations additionally protect ownership.

Meaningful prior-production controls are preserved:
`/tmp/organization-member-multiplicity-sdk-before-final.log` uses actual
master `8c0c8dc1` production with only the equivalent fixture scaffold. All three
owners fail at the intended duplicate insertion (500 instead of 200, including
the second concurrent admission). A separate old-list consumer control retains
both approved migrations but restores the previous production organization
query. `/tmp/organization-member-multiplicity-old-list-before.log` fails all
three owners on missing repeated organization rows, including the wrong
older/newer ordering. No baseline result is represented as passing.

The initial Source-self setup failure is retained in
`/tmp/organization-member-multiplicity-source-self.log`: creating a new session
through the zero-page profile fails credential lookup. After using the existing
actual session, Source-to-Source passes all three owners with 370 assertions in
`/tmp/organization-member-multiplicity-source-self-v2.log`. This is a fixture
setup correction, not an authentication or page-policy exception.
The first old-storage concurrency control attempted JSON decoding of its empty
500 body; the final preserved before log records that actual response losslessly
and fails specifically on status instead.

Limits remain SQLite's physical row/page behavior with valid installed data and
these configuration values. Arbitrary adapter query ordering, custom joined
columns, dangling records, exotic page values, duplicate-pair application
constraints and invitation phased acceptance remain separate boundaries.
No role union, pair-level lock, deduplication, app-FK rewrite or generic
custom-store semantics are introduced.

Final focused SDK verification passes all three new owners with 370 assertions
in `/tmp/organization-member-multiplicity-sdk-final.log`. The complete
organization, organization-extension and OpenAPI family passes 125 scenarios
with 10,688 assertions in
`/tmp/organization-member-multiplicity-sdk-family-final.log`. Strict locked
fixture Clippy, client TypeScript, Rust formatting and diff checks pass in
`/tmp/organization-member-multiplicity-sdk-fixture-clippy-final.log`,
`/tmp/organization-member-multiplicity-sdk-typecheck-final.log`, and
`/tmp/organization-member-multiplicity-sdk-fmt-check.log`.
No full canonical gate was
run by this owner. All focused fixture processes were stopped by their runner;
source trees, scripts and nonpassing evidence are preserved.

Coordinator and independent SIWE-owner review of exact SDK freeze 687f2c16 are
bounded clear. Both original-production admission failures and the separate
old-query failures reach their intended boundaries. The complete callback/state
receipts, actual rows, first-row authorization, exact-row deletion and all four
concurrent transport observations prevent placeholder success. The hashed team
membership key is retained as an opaque token together with its complete inputs;
each runtime's actual key is independently recomputed locally. No raw value or
identity relationship is discarded. Twenty-three additive inventory requirements
enforce the three complete primary owners through their real official-client
consumers; the trusted add-member helper remains outside the public route map.
The complete next integration gate remains pending.
