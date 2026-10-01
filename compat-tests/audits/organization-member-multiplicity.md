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
constraints/indexes remain application-owned. There is no automatic downgrade
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
