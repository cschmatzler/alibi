# Organization user invitation listing

The pinned 1.7.6 HTTP API derives email from a verified current session and
rejects client email selectors. A trusted Rust server-only method accepts an
application-authorized email without session headers. Empty selectors produce
the pinned missing-email error. Both forms use the same adapter query and
pending-state projection; unknown organizations omit organizationName.

The adapter lowercases email, preserves natural row order, includes expired and
processed invitations and applies defaultFindManyLimit before endpoint status
filtering. This differs from filtering expired/processed rows in SQL. A limited
page occupied by a canceled invitation therefore yields no pending invitations,
even when a later pending invitation exists. Reading does not change stored rows.

Real official-client scenarios prove verification, ownership, acceptance and
expiry transitions. Controlled server-only fixture calls invoke the actual
TypeScript API and public Rust method without adding authentication endpoints.
The configuration scenario uses existing default and limit-one profiles, checks
both HTTP and server-only results, and observes persisted invitation state.
The Rust team fixture now installs the real configured verification sender,
matching the TypeScript profile that already inherited core verification.

Before /tmp/invitation-list-confirmed-baseline.log proves guest error and expired
row differences; /tmp/invitation-pagination-before.log proves the wrong limited
page returned a later pending row. After /tmp/invitation-pagination-final.log
passes 26 organization scenarios / 1,342 assertions. No normalization,
comparison exceptions, ignored fields or TypeScript oracle changes are used.
Coordinator-owned independent review and the integrated gate remain before
publication. Missing-organization omission is meaningful for custom stores;
bundled foreign keys normally prevent that state. Other organization callbacks,
custom schema mappings and configured invitation lifecycle policies are separate
selected work rather than claims made by this listing repair.
