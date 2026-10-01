# Organization deletion defaults (Better Auth 1.7.6)

The installed `better-auth/dist/plugins/organization/routes/crud-org.mjs:237–292`
validates its required string body and media type before the handler. The
handler checks `disableOrganizationDeletion` before session authentication,
then rejects an empty identifier, missing membership or missing delete
permission. Configuration rejection is coded 404; missing authentication is
empty 401; empty identifiers and missing membership have distinct coded 400
responses. Permission denial is coded 403. Public request fields never choose
the authenticated user or authorize a deletion.

For an authorized member, the handler clears only the current session token's
active organization when it equals the requested organization. It does this
before looking up the organization. A real legacy orphan with an existing
membership therefore clears that token and returns empty 400. Other tokens,
the active team and unrelated selections remain intact. A successful response
contains the stored organization, including its raw metadata string, despite
the source OpenAPI declaration describing a string response. The Rust private
core returns `AuthResult<Option<OrganizationResponse>>`: absence represents
only this genuinely missing organization after membership lookup; HTTP maps
it to the observed empty 400. This does not add a global error variant.

`adapter.mjs:370–396` wraps deletion of members, invitations and the organization
in a transaction, in that order. It does not explicitly delete teams, team
members, dynamic roles, organization API keys or sessions. Actual pinned Bun
SQLite uses foreign keys off by default. The runtime proof retains those
extension rows and an organization key remains valid through the configured
key verifier after deletion, although member-scoped key reads are denied.
The source schema does declare cascading organization references. A separate
actual source probe with foreign keys enabled cascades teams, their members
and organization roles. This repair targets the pinned default adapter
behavior; it does not claim identical effects across every source adapter or
foreign-key configuration.

The public SeaORM organization store now transactionally deletes only the
three source-owned tables. It retains organization keys instead of deleting
them before the final organization write. Fresh bundled schemas omit only the
team and organization-role references to the organization. Team-member
references to teams and application-owned references remain enforced. An
appended named migration, `m20261001_000014_detach_organization_references`,
detaches those same two declared references from installed schemas.

The existing bounded reference-removal helper now accepts a private closed
`AuthReference` descriptor with fixed table, column, parent and constraint
names. Device-code and two-factor callers retain their singleton behavior.
SQLite rebuilds both organization tables on one pinned connection in one
transaction and runs a final relationship check. It preserves stored bytes,
rowids, custom fields, default/check rules, generated columns, indexes,
triggers, dependent views and unrelated foreign keys, including another
parent referenced from the same organization-id column. On failure both
rebuilds roll back and foreign-key/rename settings are restored. A connection
is closed on cancellation or a failed restoration rather than returned with
altered settings. Migration-ledger insertion remains owned by the migrator
after this helper returns: failure during rebuilding leaves the new migration
unapplied, but ledger-insert failure or cancellation after the helper commits
is an explicit separate driver boundary. PostgreSQL's scoped constraint
removal is transactional and compile-checked; PostgreSQL runtime behavior is
not claimed. Arbitrary unrecognized constraint definitions fail closed.

Five official-client scenarios own the HTTP/state contracts: actual pending
invitations, teams, dynamic roles and an organization key; foreign/member
rejections with unchanged state; media/schema/configuration/session ordering;
a privately seeded actual legacy orphan; and deletion of an unselected owned
organization while another remains selected. They observe persisted current
and sibling tokens, public session active-team fields, unrelated principals
and organization rows, exact raw numeric metadata, and key verification before
and after deletion. The controlled orphan setup uses parameterized SQL after
checking an actual organization and stays under the existing private fixture
interface. It manufactures no handler response or callback receipt.

One independent native public-store test owns its transaction contract: an
application trigger aborts the final organization delete and all physical
user/organization/member/invitation/team/team-member/role/key rows retain
their exact fields. After removing that trigger only the scoped organization,
members and invitations disappear; unrelated rows and all extension records
remain. Two native installed-migration tests own byte/constraint preservation
and second-table rollback. The latter seeds a real check-violating legacy role
row so the first table rewrite succeeds and the second copy fails. It compares
both original schemas, rows and ledger, restored settings, absence of temporary
tables and retained foreign-key enforcement, then repairs the row and upgrades.
The prior mixed team test retains its member/user capacity contract; its
obsolete organization cascade tail is superseded by the deletion primary
owner rather than duplicated.

Exact pre-fix production replay fails four new SDK scenarios at raw metadata,
coded permission, validation-before-authentication and current-token clearing;
the unselected-organization invariant already passes. The public-store test
fails because an aborted organization delete has already removed its key.
Both upgrade tests fail before the migration is registered. A separate
incorrect implementation that commits each table independently fails the
second-table rollback snapshot, proving that the negative control detects a
partial migration commit rather than an unrelated early failure.

Focused proof passes 51 organization/configuration SDK scenarios with 3,050
assertions, 325 API library tests and 49 SeaORM library tests, including prior
device/two-factor upgrade and rollback cases. Strict API/SeaORM library and
fixture Clippy, client TypeScript, formatting and diff checks pass. One
unchanged two-factor fixture nested condition was mechanically collapsed to
unblock strict Clippy; its SQL and short-circuit behavior remain the same.
No comparison, inventory requirement, lockfile or oracle runtime was changed.
The coordinator owns the complete gate and integration.

Creation/deletion lifecycle callbacks are separate capabilities. This slice
establishes deletion defaults and storage ordering, not callback rejection,
requestless trusted deletion, request-future continuation after client
disconnection, generalized adapter errors, cross-adapter transactions or
custom organization-model support. Existing raw invalid/noncanonical JSON
readback boundaries are unchanged.
