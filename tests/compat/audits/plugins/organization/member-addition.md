# Organization server-only member addition

Pinned source: `better-auth@1.7.6`, installed
`dist/plugins/organization/routes/crud-members.mjs:13–133`,
`organization.mjs:18–20`, and `adapter.mjs` (`findMemberByEmail`,
`countMembers`, `createMember`, `deleteMember`, `findOrCreateTeamMember`, and
`addTeamMemberWithLimit`). The published `addMember` endpoint has no path.
The native `OrganizationPlugin::add_member_with_headers` is an idiomatic trusted
server operation; it does not register `/organization/add-member` or another
public authentication endpoint.

The application supplies the target user ID and an optional organization/team.
A nonempty explicit organization does not require an authenticated actor. Optional
real signed-cookie headers supply active-organization fallback and the session
required by a functional team-limit callback. Session-lookup exceptions are caught
only around that nested optional lookup; errors from target lookup, admission,
hooks and writes remain actual native errors. Blank organization IDs use fallback;
whitespace IDs stay literal. The published description says null user IDs select
from a session, but its coercing schema turns null into the string `"null"` and
its actual handler looks up that target: the source probe returns `USER_NOT_FOUND`.
The native helper requires a target string; its serde transport input preserves
the existing JavaScript-string ID coercion.

Initial checks precede callbacks: organization selection, teams enabled, persisted
target, duplicate membership by lowercased target email, scoped team existence,
all-row membership count and raw organization existence, then capacity. The
current integer configuration supports source default 100 and finite integer
settings; None and zero both fall back to 100 for this operation. The source
COUNT is independent of its configured findMany page. Roles use source
`parseRoles`: arrays join verbatim, with no trimming, deduplication, registration
check or empty-role rejection. Member-role update has its own stricter validated
input contract and is unchanged.

Dedicated immutable `OrganizationMemberAdditionHooks` contexts preserve the target
and raw stored organization, without an invented caller or request. Before receives
an unpersisted member draft with no generated ID/creation date and the supplied
optional team ID; after receives the persisted member and original user and
organization snapshots. This intentionally keeps creator-member creation contexts
unchanged: the source creator callback receives a parsed organization, while this
server-only operation reads its stored JSON text. Supported org/user/role patches
are trusted shallow replacements without revalidation. Empty and unregistered
patched roles remain valid. Independent persistence in a callback does not refresh
its original snapshots.

There is no lifecycle-wide transaction. Before errors prevent member insertion.
The member is inserted before team admission. A functional team limit without a
real session fails at that later phase, with an empty upstream 401; a configured
application error remains its declared status/body. Team failures run the existing
contextual deletion transaction with the newly created member ID and ORIGINAL
organization/user, even after a trusted patch retargets the inserted member. That
cleanup can also remove original-user memberships from preexisting teams in the
configured adapter page and release their seats. Page limits zero and one are
observable. Cleanup failures replace the original failure and retain the inserted
member. After callback failures retain admitted member/team rows. Native callers
receive genuine `AuthError::Database` and explicit application `Api` errors; the
controlled private fixture maps unexpected storage failures to an empty 500 and
an absent functional-team session to empty 401, matching its actual published
server-call observations. This private application wrapper is not a new public
HTTP error contract.

Primary SDK owner: `tests/plugins/organization/member-addition.test.ts`.
It invokes real `auth.api.addMember` through an application-owned `/__test` control
and the public native helper. Real official-client signup, organization/team/session
operations set up both runtimes. Actual SQLite state, delivered callback receipts,
complete signed-session/target/foreign user state and unabridged transport are
retained. Capacity setup creates 98 distinct real users and member rows, then
admits member 100 and rejects member 101 across default, zero, None and smaller
query-page configurations. The private snapshot's explicit SQL ordering preserves
all rows and arrays; it does not modify the source adapter's pagination order.
Actual SQL ABORT triggers separately exercise before callback, member insertion,
team insertion, after callback and cleanup failure, with successful retries.
Returned snapshots prove selected current/sibling organization and active-team
fields survive, original-user team cleanup stays scoped, and foreign rows are
preserved. No fixture supplies synthetic callback receipts or a fake success.

The distinct native owner `tests/organization_member_addition_tests.rs` exercises
the public helper from a legitimate manual AuthContext with real SQLite. It checks
that an insertion veto remains a typed database error, an actual after callback's
explicit 500 remains an `Api` error with its committed row, duplicate retry fails,
and unrelated user/organization snapshots are unchanged.

## Evidence and limits

Source-only probes `/tmp/organization-add-member-source-probe.mjs` and
`/tmp/organization-add-member-source-limit-probe.mjs` exercised 42 fresh real
SQLite lifecycles. Logs retain raw rows and actual callbacks. They also establish
numeric/callback branches reserved for the next coherent admission/configuration
slice: fixed NaN/zero/null fallback to 100, negative/fractional/infinite limits,
and async limit callbacks over the TARGET user and raw organization. Callback
zero is a real zero limit and callback NaN allows admission; callback values do
not use the fixed configuration's falsy fallback. The public configuration still
uses its existing integer primitive. Fractional/dynamic membership limits are
unimplemented; the existing invitation precheck/acceptance and list/page consumers
are not silently changed. A single idiomatic configuration migration and its
required paging/admission evidence remain pending.

Unresolved storage difference: the published default SQLite member schema permits
multiple rows for the same organization/user; bundled Rust enforces a unique pair.
The normal source addMember duplicate guard rejects duplicates before hooks, but a
trusted beforeAddMember patch can bypass that initial guard and insert a duplicate.
Actual source patch-retarget probes accepted the duplicated pair; initial native
capacity setup and retarget controls hit the real UNIQUE constraint. This slice
preserves the current schema/migrations and does not claim that branch. The
supported retarget proof uses a distinct actual user. The genuine functional
team-limit callback captures SQL while the inserted row exists, proving its patched
organization/user before rejecting and proving original cleanup authority afterward. A source-backed schema prerequisite is needed before claiming
arbitrary duplicate hook patches or existing duplicate rows. The published adapter
also returns repeated organizations per duplicate membership; bundled Rust
currently collapses those through its organization-ID lookup. That separate
physical-row/list prerequisite remains unresolved.

Additional boundaries: arbitrary custom member columns, hook argument mutation,
custom/hidden user-column callback projection, supplied generated member IDs or
timestamps, global server-API dispatch hooks/API-key virtual sessions, HTTP
cancellation and continuation, malformed private-wrapper transport input beyond
the typed contract, concurrent membership-capacity admission, and stale team
counter repair are not established here. The existing team-store numeric/callback
API is reused without broadening its scalar range or unproved return semantics.
Existing native `delete_member` behavior remains unchanged; controlled setup uses
the explicit member-only contextual operation to match the source adapter's direct
member-row deletion. No schemas, migrations, locks, inventories or comparisons
were altered in this capability.

Incorrect-implementation controls were run against isolated binaries with the real
callbacks/configuration/state unchanged: omitting both production callback calls
fails eight of nine primary scenarios (missing receipts, genuine before/after
errors wrongly succeed, and patches/waiting are skipped). Restoring callbacks but
misinterpreting absent/zero limits as unlimited and cleaning the patched member
scope instead of the original target fails both capacity and retarget owners:
member 101 wrongly succeeds and the original target team membership remains.
Logs: `/tmp/org-member-addition-callback-omission-before.log` and
`/tmp/org-member-addition-cap-scope-negative-before.log`. These are explicit
negative implementations of the new capability, not a claim that a previously
published native addMember endpoint existed. All production controls were removed
before final validation.

Focused whole organization, organization-extension and OpenAPI families pass
122 owners/10318 assertions in `/tmp/org-member-addition-family-final.log`. The
final staged-retarget owner is included. API native family passes 334, the distinct
public-helper SQLite owner passes, and API/fixture/native-owner strict Clippy,
TypeScript, formatting and diff checks pass. The initial final primary run hit
Bun's five-second default deadline in its six real error/patch lifecycles; its
complete failure log is retained. That one expensive scenario now declares a
15-second runner deadline; no timestamp/comparison tolerance or assertion changed.
Coordinator owns canonical gates and publication.

The strengthened retarget owner additionally fails when the production path
discards only the hook's organization/user patches while still applying its role:
the genuine team-policy snapshot has no row at the required patched pair
(`/tmp/org-member-addition-ignored-patch-before.log`). This closes the previous
possibility that final cleanup alone could pass with ignored retargeting. The
supported handler was restored byte-for-byte and its fixture rebuilt. Final
Source self-control and restored differential each pass nine owners/1568
assertions in `/tmp/org-member-addition-source-self-final.log` and
`/tmp/org-member-addition-differential-restored-final.log`. The final direct
public-helper SQLite regression also passes. Temporary negative servers were
stopped and no mutant remains in the frozen source.

## Coordinator integration and independent review

Frozen a0c0996d was independently read against the pinned runtime by the
coordinator and phone/storage owner; both reviews are clear within the stated
boundaries. The retarget case records the actual inserted row before cleanup,
and a real ignored-patch variant fails that check. Whole family passes
122 / 10,318, with final Source and restored Rust primary runs each 9 / 1,568.
All eleven nonbinding feature files remain byte-identical during integration;
the three shared bindings retain both member addition and OTP delivery.

Because addMember has no public HTTP route, its controlled server calls are
accounted for here separately. Eighteen additive inventory requirements use the
nine owners' genuine organization-creation setup success/state as execution
anchors; the whole differential owner must pass to record them. They do not
claim that addMember is an organization-creation handler or expose a fabricated
public route. Each owner's actual helper result, private transport, callbacks
and persistence assertions remain the direct evidence. The complete following
530-scenario canonical gate remains pending.
