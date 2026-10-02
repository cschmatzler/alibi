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

The appended `m20261001_000015_member_pair_multiplicity` migration drops only
the bundled `idx_member_org_user_unique` index when present. The recorded initial
schema remains unchanged. Fresh databases run the same appended upgrade as
populated installations. No rows are rebuilt or deduplicated, and application
constraints/indexes remain application-owned. SQLite upgrades first refuse an
incoming application foreign key over the organization/user pair, as detailed
below. There is no automatic downgrade
that invents a choice of which duplicate rows to delete.

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

The three distinct native owners in `member_multiplicity_tests.rs` prove:

- A genuinely populated prior migration history enforces the old pair index,
  then the appended upgrade permits a second public-store insert. Complete
  physical row/rowid/text/date snapshots, table/foreign-key SQL, application
  index/trigger/view and peer rows survive. Exact-ID role updates retain the
  sibling and fire the actual application trigger. Repeated migration runs and
  direct repeated execution with the index absent preserve rows/schema/ledger.
- A separately prepared published-style unconstrained table protects the
  consumer independently of the migration: full newer/older/newer output,
  physical pages 100/2/1/0, first-member lookup and exact-ID deletion with scoped
  team-seat cleanup retain full peer organization/user/member and foreign team
  state.
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
`rustls,axum,seaorm2,redis-cache` passes in
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

Limits: SQLite runtime and installed-upgrade behavior are proved. PostgreSQL
execution, unusual dangling rows, arbitrary joined custom columns, non-integer
or nonfinite page configuration, and adapter-specific unordered query plans are
not claimed. A dangling native member still omits its missing organization,
preserving the prior nonnullable return contract. Source invitation conditional
accept/reset, rollback failures, pre-transaction capacity checks and lifecycle
hooks remain a separate capability. The server-only add-member duplicate-hook
SDK extension follows its independently frozen helper dependency; this storage
prerequisite does not claim that additional end-to-end evidence yet.

## Dependent application foreign keys

Independent review found a real installed-schema preservation failure in frozen
0d0ba40c: SQLite permits dropping the old unique pair index even when an
application foreign key depends on it. The drop succeeds, but subsequent
`foreign_key_check` and real member deletion fail with foreign-key mismatch.
The native prior-code reproduction is retained in
`/tmp/organization-member-pair-fk-guard-before.log`; both operations reach the
actual database. This is not a hypothetical constraint or a mocked migration.

Before dropping a present index, the SQLite migration now reads actual catalog
tables, passes each name as a bound value to `pragma_foreign_key_list`, groups
references by their FK identity/sequence and detects the two referenced pair
columns in either order. Quoted names and case-insensitive parent names remain
data. It returns an explicit migration error before any index, row or ledger
write. The application must migrate its reference to the member ID first; this
migration does not drop its FK, rewrite its records or choose duplicate rows.
The existing absent-index no-op and fresh/default migrations remain unchanged.

The additional native owner creates two actual organization/user/member pairs
and a quoted-name application table with real pair references and byte payloads.
On refusal, complete schema, member rowids/text/dates, app records, migration
ledger and full owner/peer records match their prior snapshots. The real FK
check remains valid and the referenced member still rejects deletion. An actual
application-owned change preserves both payloads while moving to member-ID
references; upgrade retry then succeeds, permits a duplicate member insert and
retains the peer and app records. The reference guard deliberately refuses pair
references even if another application-owned unique index could also support
them; arbitrary app constraint redesign remains application-owned.

Focused storage family passes 61 native tests in
`/tmp/organization-member-pair-fk-guard-seaorm-final.log`. Production strict Clippy passes in
`/tmp/organization-member-pair-fk-guard-clippy-final.log`; formatting and diff
checks pass on the isolated guard tree.
PostgreSQL/MySQL dependency rejection relies on their existing DROP without
CASCADE behavior and is not runtime proved here. Concurrent application-schema
changes during migration are outside this bounded installed-upgrade contract.
No store API, handler, model, initial schema, dependency, lock or inventory
changed in this follow-up.

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
index rejects them. The native installed upgrade, application FK refusal/retry,
and independently connected storage race retain their distinct boundaries;
these SDK owners exercise the actual official client and unchanged published
server-only helper, rather than replaying migration assertions.

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
The frozen storage/FK prerequisites retain their separately proved native
61-test family and installed schema evidence above. No full canonical gate was
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
