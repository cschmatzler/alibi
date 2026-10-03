# Invitation creation, reissue, delivery and non-accept lifecycle — 1.7.6

This closes #217's invitation family, preserving staged ACCEPT's conditional
claim, subsequent membership transaction, reset precedence and after hook.
Custom additional schemas (#184), generic task/error composition (#181) and
secondary verification (#174) are outside this change.

## Pinned evidence and order

The actual published `better-auth@1.7.6` runtime owns Source responses and
receipts. Installed `dist/plugins/organization/routes/crud-invites.mjs` and
`adapter.mjs` were compared byte-for-byte with the authentic npm tarball.
SHA-256: crud-invites `b9f2e3a893891daa2fc49868604f97a28bb5121ec7bd231902290711f1f80895`;
adapter `28b913fb01f464dbe08644a60798040afae483cdbfe0e4a4a89676c203dd02e3`.
The dependency files were never mutated; Bun's hardlinked cache was not changed.
`context/create-context.mjs:215–227` supplies the real
`runInBackgroundOrAwait` delivery error/completion behavior.

Creation validates schema, authenticates, validates email, verifies organization
membership/permission and requested roles, then denies an existing member. It
finds a pending email adapter page and filters expiry after that page. Duplicate
invites deny unless resend or cancel-on-reinvite is configured. Organization
lookup precedes either reissue path. Resend renews only expiry on the first live
pending row before delivery, preserves identity/role/team/inviter/created time,
and bypasses quota and CREATE callbacks. Reinvite cancels only the first live
pending row before resolver/quota/team admission; later errors retain that row.
No CANCEL hook runs for this internal cancellation.

Admission resolves the actual immutable user, raw organization and adapter-joined
member/user, then fetches the pending organization page before expiry filtering.
Every configured number is compared raw. None uses 100; zero and negative numbers
reject, 1.5 admits at one and rejects at two, NaN and positive infinity admit.
Resolvers have the same raw result semantics and no fallback. This differs from
the membership policy's fixed-number falsy fallback. A page filled by an expired
pending row hides later live rows from admission and duplicate lookup, exactly
as Source does. Public invitation listing uses the same configured adapter page
and no added sort. Trusted all-row pending COUNT and single pending lookup keep
their existing contracts.

All scoped team IDs are validated before team limit callbacks. CREATE before
hook receives the admitted draft and original inviter/organization; typed
returned patches merge without revalidation. The row is inserted, real configured
email delivery starts, and CREATE after runs. Awaited delivery rejection is
logged/consumed and still reaches CREATE after. With a configured background
observer, owned delivery starts before observer handoff, CREATE after can precede
completion, and a rejected observer does not cancel the pending task. Original
request/header context and the initialized instance/store remain owned by the
callback. No new transaction encloses any of these writes or callbacks.

REJECT checks pending identity, authenticated recipient and verified-email
policy before callbacks; expired pending invitations remain rejectable. CANCEL
checks actual organization membership and cancellation permission, and can cancel
an already canceled/rejected/accepted row. Both look up the stored organization,
run before, write status, then run after. Before errors prevent their write;
after errors retain it. Genuine ordinary application/storage failures use these
invitation endpoints' empty HTTP 500; declared application API errors retain their
actual code/status/message. No global error mapping changed.

## Primary proof and authoring gate

`tests/plugins/organization/invitation-lifecycle.test.ts` is the primary owner.
Immutable fixture profiles configure real async callbacks and policies on the
published plugin and the native plugin using the actual selected SQLx/SeaORM
store. Application controls record receipts, SQL snapshots and genuine errors;
they do not produce invitation mutations, authority decisions, quota admission,
resend logic or synthetic delivery acknowledgements.

Each scenario retains all invitation/member/team/team-member/organization rows
and every current, sibling and foreign session column. Official clients observe
lists, member/team state and current/sibling/foreign selections. Complete original
transport remains in the strict comparator, including declared/ordinary errors.
Callback snapshots identify the exact recipient, inviter and tenant. Retry and
foreign-recipient controls distinguish before vetoes, retained after writes,
consumed delivery failures, cancellation preceding denial, and first-match
cancellation among multiple actual pending rows.

The tests protect publicly observable callback order, delivery completion,
identity/expiry/state retention, permission/body denial and numeric/page
admission. Credible regressions include returning an old pending row, checking
quota before resend, counting all pending rows, rolling back reinvite cancellation,
swallowing hook errors, propagating delivery errors, or dropping a background
completion. Prior ACCEPT/member/team coverage does not own these phases. Public
callback/store APIs are useful to applications; fixtures add no production-only
test flags, exports or endpoint seams.

SDK Date objects retain milliseconds directly. `teamIds` elements are proved
against actual scoped team rows before their existing identity-bijection wrapper;
no element is removed. JSON media is decoded for full wire-body comparison;
empty/non-JSON body bytes remain literal. Concurrent release transports are
retained and recorded after the owned pending request, as in the staged ACCEPT
owner, without changing the comparator or broadening accepted errors.

## Public migration and bounds

Use `invitation_limit: Some(InvitationLimit::Fixed(100.0))` instead of
`Some(100)`, or `InvitationLimit::Resolver(Arc::new(policy))` for one async policy.
None means the pinned default 100 rather than unlimited; positive infinity
expresses an uncapped numeric admission policy. Use
`invitation_expires_in: Some(172_800.0)` instead of the former u64. None, signed
zero and NaN use 48 hours; finite fractions and negatives retain their raw span.
Native expiry uses the absolute ECMAScript millisecond timestamp and truncation.

JavaScript Invalid Date/nonfinite or dates beyond Chrono's representable range
cannot be persisted as native DateTime values and return an explicit configuration
error. Non-number JavaScript callback results, argument mutation/aliasing and
arbitrary object-spread keys are not native typed contracts. Typed creation
patches cover all bundled persisted invitation fields, including the documented
expiry override and trusted ID/status/creation time. Arbitrary custom columns
belong to #184; invalid enum statuses and JavaScript-only null/non-date values
are not silently coerced into native models. The request is a native owned AuthRequest,
not a JavaScript Request stream object. PostgreSQL/MySQL runtime parity is not
claimed by the SQLite official-client evidence. Custom stores must implement
new pending-page and expiry-write primitives; defaults fail closed.

## Validation

Evidence logs use the owned `/tmp/invitation217-` prefix. Published Source
self proof passed 58 scenarios with 4,592 assertions. SQLx differential primary
proof passed the same 58 scenarios and 4,592 assertions. Genuine SeaORM
(`cargo build --features seaorm`, not an environment selector) passed 113 grouped
scenarios with 9,804 assertions: this owner, staged ACCEPT, existing invitations,
membership policy, teams and raw numeric limits.

Old-lifecycle controls preserve the schema/authority prefix and bridge the numeric
configuration API so they measure lifecycle behavior rather than unrelated
validation migration. The SQLx control failed 51 of the original 54 scenarios
(3 passed, 3,322 assertions); the genuine SeaORM control failed 55 of the final
58 (3 passed, 3,524 assertions). The added four scenarios cover trusted persisted
field overrides and non-pending cancellation/expired rejection. Earlier logs
labeled SeaORM using an environment variable actually ran SQLx, because backend
selection is compile-time; they are retained as SQLx replays and excluded from
SeaORM evidence. A startup port collision is retained as a setup failure, not
behavioral evidence; final runs allocate independent available ports and check
child liveness.

Strict production all-target Clippy, final SeaORM fixture Clippy, workspace
formatting, TypeScript checking and changed-file lint passed. Latest-main grouped
results are recorded below. No full suite or sweep is required
or run for this workpiece.

Rebased interaction proof on `df57345f` passed 113 scenarios and 9,804 assertions
on SQLx (`rebase-sqlx.log`). The subsequent main change `b3920a06` contains only
docs/deployment/configuration additions; Rust code, Cargo locks, fixture and
client-test trees are unchanged. Its shell adds only the SOPS package.

The same latest-main group passed on genuine SeaORM: 113 scenarios, 9,804
assertions, zero failures/skips (`rebase-seaorm.log`). Final SQLx fixture artifact
SHA-256 `31337e2181419ac9a7f1034a00c133b69f52bb4f0666a95e7fa4618160dbc08f`;
SeaORM `ebc78655809d291838faf8e2a7399898e3a0f4b8c24db26c1fd113917b6841cd`.
Permission review confirms scoped membership and action checks precede callbacks,
recipient rejection checks precede hooks, body data cannot inject trusted patches,
and pending pages bind organization and recipient. The staged ACCEPT production
handler has no diff. GitHub reports no checks for this PR; no CI failure exists
to repair, and no full-suite gate is introduced.
