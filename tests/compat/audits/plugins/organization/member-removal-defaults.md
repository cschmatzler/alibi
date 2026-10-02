# Organization member removal defaults against Better Auth 1.7.6

Pinned `dist/plugins/organization/routes/crud-members.mjs:140-229` validates the
two string selectors before authentication. Empty organizationId falls back to
the current selection; whitespace remains a literal ID. The authenticated
requester must be a member and must have member.delete permission even when
removing itself. A creator target uses exact stored comma-separated roles, while
the requester creator check applies JavaScript trim. The last-owner check reads
the configured membershipLimit-or-100 adapter page without ordering. It precedes
permission and foreign-target checks. Email selectors lowercase without trimming
and retain the adapter's joined user; ID selectors omit that join.

The defaults repair preserves that ordering and exact errors. No public userId
selects authority. The existing member response gains a source-compatible generic
parameter for the ID-versus-email snapshot. Authentication errors are caught only
at the existing nested session resolver, preserving later storage and application
errors. The route-local parser reuses the existing JSON/media validation and does
not change shared role normalization or organization resolvers.

Pinned `dist/plugins/organization/adapter.mjs:305-350` deletes the member first,
then conditionally cleans team memberships using the captured original user and
organization, within the adapter transaction. Its default Bun SQLite adapter
enables transactions (`@better-auth/kysely-adapter/dist/index.mjs:64-71`). Teams
use the configured defaultFindManyLimit and no sort. Missing or SQL IGNORE member
deletion still permits cleanup; a real SQL failure aborts it. Selection clearing
occurs after commit and only for the current self-removing session whose active
organization matches. activeTeamId and sibling selections remain unchanged.

Two additive MemberStore operations express those contracts without changing
old delete/list/query APIs: delete_member_with_context and
list_organization_members_page. Defaults and MemoryStore fail closed;
PluginStore forwards. SeaORM performs member-first deletion and scoped paged
team cleanup in one real transaction. Its existing guarded seat-release loop is
shared internally while old callers retain their old ordering/query behavior.
The page operation deliberately has LIMIT without ORDER BY; it is not a promise
of universal insertion order across adapters.

Three official-client scenarios extend the existing member owner. They assert
the ID/email wire shapes, full owned/foreign rows and sessions, exact guard
failures, ordered malformed-body/media errors before guest authentication,
literal and blank selectors, then legitimate retries. Their independent oracle
run passes 3/286 (`/tmp/org-member-removal-default-oracle.log`). Against the
preceding frozen native implementation all three fail for the intended reasons:
extra ID join, unauthorized self-removal success and authentication preceding
body validation (`/tmp/org-member-removal-default-before.log`, 0/3, 188 assertions).
The repaired owner passes all seven cases / 316 assertions
(`/tmp/org-member-removal-default-sdk-final.log`). Callback non-invocation is not
claimed here: these are defaults; configured removal callbacks are a separate
following capability.

Two real SQLite public-store owners cover the separate persistence contract.
They use actual SQL ABORT and IGNORE triggers, assert the exact veto message to
exclude unrelated SQL failures, and compare complete member/team/team-member
models plus unrelated users/organizations. A second-stage veto rolls the member
deletion back. Captured scope still controls cleanup after independent mutation
or absence. Enabled/disabled cleanup and default page one preserve unrelated
memberships and exact seat counts. Reverse creation timestamps distinguish the
new raw page from the retained sorted list. The unchanged pinned runtime probe
independently confirms first-inserted page behavior despite reverse timestamps
(`/tmp/organization-member-remove-source-probe.log`, page-one-reversed-dates).
Native owners pass (`/tmp/org-member-removal-native-final.log`).

The complete organization, extension and OpenAPI sibling owner passes 99 SDK
scenarios / 6504 assertions (`/tmp/org-member-removal-family-final.log`). All 332
API and 53 SeaORM library tests pass (`org-member-removal-{api,seaorm}-final.log`).
Strict core/API/SeaORM library Clippy, fixture all-target Clippy, TypeScript and
the locked fixture build pass in `org-member-removal-{default-clippy-final,
fixture-clippy-final,typecheck-final,default-build}.log`. The optional stricter
SeaORM --tests lint invocation reports existing test assertion/unwrap warnings
across the suite, including Result-returning native assertion owners; it is not
the repository's production Clippy gate and is not claimed as passed.

The source probe also establishes lifecycle error phases, original callback
snapshots, requestless cookie authentication and team-disabled/page branches for
the following callback slice. Those observations are not SDK coverage claims for
this prerequisite. HTTP SQL failures currently retain the generic native database
error mapping rather than Bun's empty 500; no synthetic failure response or global
mapper change is introduced. Source argument mutation, custom joined-user
columns, virtual API-key global server dispatch, cancellation and other adapter
configuration remain explicitly outside this bounded defaults proof.

No schema, migration, dependency, lockfile, inventory, comparator, clock policy
or pinned runtime change is made. The coordinator owns independent review, full
gates and publication. External test-audit autoreview tooling is unavailable.
