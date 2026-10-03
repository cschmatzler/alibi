# Anonymous application projections and recovery combinations (#212)

The reference is the published Better Auth 1.7.6
`plugins/anonymous/index.mjs`, its internal adapter, and the passkey verification
endpoint. The historical authentication, lifecycle and seven-method audit files
and their original observations remain intact. This audit supersedes their
custom-column, ordinary-exception and multiple-session evidence limitations.

## Measured regressions and repair

A concrete application user model declares actual `cargo_label` and
`cargo_hidden` columns, with asynchronous application generation/link callbacks,
a callback default and real database session-after hooks. The hook changes the
stored signup user's name and both columns after the original user was created.
The link receipt must retain the original completed user, including hidden
application columns. It must not manufacture a model from the public response
or reread the mutated row. Cookie-derived anonymous users use the public session
projection; cookie-less recovery uses the trusted stored user, including hidden
columns. The existing completed-adapter callback accessors implement this
projection without changing shared issuer/cache hooks.

SQLx and SeaORM baseline runs both lost `cargoHidden` from completed and recovered
receipts, and returned a JSON 500 for an ordinary link exception where Source
returns an empty 500. Native baseline identity callbacks likewise exposed a JSON
body for ordinary failures. The repair normalizes `AuthError::Internal` from the
application identity/link callbacks to the existing `CallbackFailure` wire.
Explicit coded and uncoded API errors keep their own response. No transaction
was added: a failing link callback retains the already committed login, the old
anonymous user, all historical sessions and accounts, and its real callback
receipt. Cancellation remains covered by the unchanged original owner.

The custom-column seven-method table retains every original default row and
adds the same independently authenticated methods with physical application
columns. Wrong proofs, genuine deliveries/signatures, original anonymous pairs,
completed-user snapshots, replay rules and complete original transports remain
asserted. Signed-email verification uses the actual pre-verification lookup
snapshot, which may already differ from the signup response after a real hook.
Passkey verification has a pinned peculiarity: its successful response returns
the trusted adapter user, including declared hidden fields. Its callback must
also retain those fields, while the subsequent `get-session` remains filtered.
This behavior is explicit rather than suppressed by the comparator.

## State, transfer and configurations

The custom default and compact-cache profiles perform a real link callback
write: they transfer the anonymous application label to the new owner's physical
column. Receipts retain the original completed snapshot, while later storage
and authoritative session reads expose the callback's transfer and the earlier
session hook's changes. Foreign owners and their accounts/sessions remain intact.

Controlled server-only fixture operations call the actual adapter to create
three additional sessions and an application account for the anonymous owner.
Cookie-less OAuth recovery exercises an original active session, an expired
original with two other active sessions, disabled cleanup, and an entirely
expired set. It selects the first active session; absent any active session it
completes the authenticated login without linking or deleting the anonymous
owner. A wrong state cookie cannot transfer data. Consumed-state replay cannot
repeat transfer. Every historical token is replayed with its actual signed
session cookie: deleted/expired rows reject it; disabled-cleanup active sessions
still authenticate their original owner and their ordinary refresh writes are
observed in the final persisted state. Existing provider transport is reused;
no provider/decoder code or cookie-state strategy was changed.

The compact `version-api` and `version-ordinary` publication-error owners remain
unchanged and are rerun against both adapters. Failed cache publication still
prevents anonymous transfer. Existing cookie-state differences remain tracked
by #189, not hidden or redefined by this issue.

## Evidence and limits

Retained artifacts: `/tmp/better-auth-issue-212-evidence/` includes original issue
text, the pinned source copy, every baseline/fix/final log, full Source/native
observations and traces, source-only observations, and published-package
integrity results. SQLx and SeaORM baselines expose the missing column and wire
regressions. Passing proof excludes intentional mutations; no installed
published dependency was mutated. Every installed file of Better Auth, core,
passkey and API-key 1.7.6 was compared with its registry tarball.

Five negative controls corrupt actual passing cross-runtime observations:
the original hidden completed value, the recovered hidden value, the selected
active session, deleted historical account state, and the ordinary exception
body. Each first requires a clean Source/native comparison, then records the
specific detected drift. These are external evidence checks, not synthetic
production seams or dependency mutants.

Native targeted tests cover public identity callback errors before any write,
plus the existing request isolation, identity lifecycle and trusted recovery
owners. SDK proof covers both real storage adapters. Final grouped commands and
exact tested/merged revisions are recorded in the retained handoff manifest.
GitHub Actions are disabled for this repository; no green CI claim is made.
The user explicitly replaced the historical full `devenv test` requirement with
these targeted both-adapter checks. The later user override removes full sweeps
entirely; no canonical full gate or periodic coordinator sweep is required.

The native callback boundary projects declared application columns into
`UserView`/`SessionView` and retains adapter output. Arbitrary JavaScript-only
runtime objects (functions, symbols, prototypes/accessors, BigInt or undefined
object members) are not native callback representations. This is a representation
limit, not an exclusion of the measured physical application columns. The
configuration matrix is the named supported combinations above, not an exhaustive
claim over every possible application schema or schedule. Generic OAuth/provider
work and invitation lifecycle remain their separate owners' scope.
