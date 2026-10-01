# Organization membership policy and adapter pages

Pinned source is `better-auth@1.7.6`: installed
`dist/plugins/organization/routes/crud-members.mjs` (addMember, listMembers,
removeMember), `routes/crud-invites.mjs:163–172,275–279`,
`routes/crud-org.mjs:334,357–380`, and `adapter.mjs:186–247,427–473`.
The source-only probe `/tmp/organization-membership-policy-oracle.mjs` exercised
14 actual SQLite configurations, including fixed/falsy/nonfinite limits,
async results and errors, and independent adapter member/user pages.

The public Rust configuration has one `Option<MembershipLimit>` field.
`MembershipLimit::Fixed(f64)` replaces the former integer primitive;
`MembershipLimit::Resolver(Arc<dyn OrganizationMembershipLimitResolver>)`
provides an immutable async application policy over the actual target `UserView`
and the raw stored `OrganizationResponse`. Existing callers select, for example,
`Some(MembershipLimit::Fixed(100.0))`. None, fixed zero and fixed NaN use 100.
Negative, fractional and infinite fixed numbers remain numbers. Resolver results
have no second fallback: zero rejects admission and NaN allows it. The SDK also
admits at count one with fixed/resolved 1.5 and rejects at count two, distinguishing
this behavior from rounding a fractional policy to an integer.

Trusted addMember and invitation acceptance evaluate the real all-row COUNT,
then look up the organization, then await this policy before team limits or
membership writes. Existing addMember target/duplicate/scoped-team checks and
invitation recipient/verified-email checks remain earlier guards. The callback
receives the actual target rather than the authenticated inviter. It receives no
invented actor/request or authority from client-supplied callback options.
Policy errors preserve their declared native/public application errors and do
not mutate member, invitation, team, owner/session or foreign records. The source
create-invitation operation has no membership admission check; that false native
gate is removed. A configured pending-invitation limit still rejects with source
403 `INVITATION_LIMIT_REACHED` / `Invitation limit reached`. The primary owner
proves a first invitation succeeds with two actual members and membership limit
one, then a second invitation hits pending limit one without writes or callbacks.

Read pages never invoke an admission resolver. They use a truthy fixed numeric
configuration or 100, even when a configured resolver would throw. The additive
`MemberPageQuery` and `UserStore::list_users_by_ids_page` retain raw f64 values
until actual SQL binding; existing usize store APIs keep their contracts. Default
unsupported store implementations fail closed with NotImplemented instead of
rounding or silently delegating to an unpaged query. SeaORM uses the actual chosen
user entity/table and custom native ID parser. LIMIT/OFFSET are bound values;
there is no numeric text interpolation or artificial query error. A missing sort
adds no ORDER BY. Filtered counts are independent of the member page.

List-members query strings use JavaScript Number semantics; full-organization's
string membersLimit uses parseInt. Zero/NaN queries use the operation's fallback,
negative SQLite limits are uncapped, and fractional/infinite limits produce genuine
SQLite query failures. Full-organization's member page uses its own supplied limit
or the configured adapter default-find-many limit, while its separate user page
uses the fixed membership limit or 100. A shorter user page can therefore fail
while joining an otherwise valid member page. Full projection precedes membership
authorization, so that actual join failure preserves the requesting foreign session
instead of prematurely clearing its selection. These two HTTP page wrappers map
actual Database/MissingUser failures to the source's empty 500; application errors
and other native errors retain their original typed/public contracts. Removal's
last-owner guard uses the configured member read page without invoking a resolver.

Primary SDK owner is
`tests/organization-extensions/membership-policy.test.ts`. Four connected scenarios
retain whole callbacks, raw organization metadata, all actual organization/member/
invitation/team rows, user/account/session state, and complete official-client
transport. The private application fixture calls published `auth.api.addMember`
and the public native helper; it adds no authentication endpoint. Immutable profile
policies produce genuine receipts only when production invokes their callbacks.
The distinct public SQLite storage owner reverses insertion versus timestamp order,
checks offsets and filtered counts, and checks genuine fractional/nonfinite SQL
failures plus complete physical owner/foreign records. Existing custom-schema
consumers additionally exercise native numeric IDs and application-owned columns.

## Proof and boundaries

Production checkpoint is `b7e29c28`; source-exact pending-limit wire supplemental
is `69b23fb4`. Source-self passed 4 scenarios / 602 assertions. The complete focused
organization/extensions/OpenAPI family passed 126 scenarios / 10,920 assertions,
including those same four policy owners. All 62 SeaORM native tests and nine
custom-schema consumer tests passed; production-library and fixture strict Clippy,
fixture build, TypeScript checking, formatting and diff checks passed. Logs are
`/tmp/organization-membership-policy-source-self-final-complete.log`,
`/tmp/organization-membership-policy-sdk-family-final.log`,
`/tmp/organization-membership-policy-native-seaorm-final.log`, and
`/tmp/organization-membership-policy-custom-consumers.log`. Meaningful removed incorrect-implementation controls are retained
in `/tmp/organization-membership-policy-resolver-fallback-before.log` (callback
zero incorrectly admitted), `/tmp/organization-membership-policy-implicit-sort-before.log`
(wrong member selected), and `/tmp/organization-membership-policy-truncated-bind-before.log`
(fractional SQL limit silently accepted). The actual old pending-limit rejection
fails at 400 versus 403 in `/tmp/organization-membership-policy-pending-cap-before.log`.
All temporary controls were restored before final validation; no comparator,
clock/tolerance, source runtime or coverage requirement was changed.

This capability covers membership admission and member/user numeric pages. It
does not implement invitation staged accepted-status/reset/after-hook lifecycle,
nonteam duplicate acceptance, fractional/dynamic invitation limits, or the source
pending-invitation/advanced team join pages. The existing public native
accept_invitation_with_teams usize API remains unchanged; the source-compatible
plugin path supplies None for its legacy in-transaction membership recheck.

The callback's user is the existing typed UserView, as with addition hooks.
Native metadata remains available through that view, but its serde-skipped metadata
and arbitrary application-owned user columns are not a raw custom-field callback
projection. The organization snapshot preserves its existing raw metadata contract.
Custom joined-member fields/orphan rows and unrelated invalid query, selector,
filter and sort behavior remain separate capabilities; in particular invalid sort
column names still follow the existing native whitelist rather than claiming every
source adapter error. Missing or revoked nested sessions, global server dispatcher/
API-key virtual sessions and HTTP disconnect continuation retain the existing
operation boundaries. Runtime raw numeric SQL behavior is proved on SQLite;
PostgreSQL/MySQL placeholders compile but their runtime numeric behavior is not
claimed. Legacy/custom stores must explicitly implement the new raw-page APIs to
support these plugin read paths. No schema, migration, dependency lock or inventory
change is part of this policy capability.

Independent JWT-owner review of final frozen `c7084d18` is clear within the documented scope. Coordinator publication retains the same production/public custom-schema consumers and all four actual SDK owners; physical duplicate-member profiles remain present from master. Twenty-five additive requirements anchor actual create/read/invite/accept/removal consumers, including setup for trusted private addition; no fictitious public add-member endpoint is registered. The next complete integrated gate is pending.
