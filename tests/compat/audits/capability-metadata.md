# Inherited capability evidence repair (issue #290)

Main `16205b5b0e99f69899cf84ac71b11be64c362dba` requires 4,817
route/category/scenario cells. A fresh run of the 67 owners implicated by the
earlier independent full-suite diagnostics reproduces all 115 missing inherited
cells: 66 owners pass, one membership owner reports timestamp/lifetime drift,
and 3,332 assertions run. The baseline log is
`/tmp/capability-metadata-baseline-owners.log`; a read-only fetch observer retains
the actual Source/native method, path, status, error code, redirect location and
null-response flag in `/tmp/capability-metadata-baseline-transport.jsonl`.
Those receipts are investigation records and are never copied into positive
capability evidence.

`capability-metadata-classification.json` records every original missing tuple
and its retained or corrected requirement. Of the 115, 61 have a bounded
collection/annotation/owner repair, 52 were miscategorized, and two retain the
original membership requirements while repairing their actual receipt collection. The inventory
keeps its route flags, oracle version, strict unknown-field checking and every
unaffected requirement, including all 113 measured #221 additions.

## Contracts and primary owners

Apple's existing signed-token, code exchange, refresh, mapping and rejection
owners already compare complete physical user/account/session rows and actual
provider receipts. Their missing state annotations now name the actual canonical
routes. Authorization-URL owners additionally compare complete rows before/after
and assert that starting authorization has not created identities or sessions.
State evidence includes both mutations and measured preservation. It does not
claim that those three row sets contain the separate OAuth verification table.

Published `api/routes/account.mjs` filters durable accounts by the authenticated
owner and returns `BAD_REQUEST / ACCOUNT_NOT_FOUND` for foreign row selection.
Published `api/routes/update-user.mjs` rejects a missing password-bearing
credential as `BAD_REQUEST / CREDENTIAL_ACCOUNT_NOT_FOUND`. The collector admits
authorization evidence only for those literal codes, HTTP400, and their precise
POST refresh/unlink/delete routes. Other 400s and empty or unknown 500s do not
supply authorization. The credential duplicate owner now attempts the real
foreign credential row while its own two accounts ensure the last-account guard
cannot mask ownership; full rows and the foreign principal remain unchanged.

The pending OTP table owners now send OTP with the same genuine absent/corrupt
pending-cookie controls as their existing verifier guard. They assert the actual
401 `INVALID_TWO_FACTOR_COOKIE`, no adapter receipts and the complete unchanged
verification/factor snapshot. Their successful delivery, retry, cleanup,
lockout, original principal and foreign principal observations remain intact.

The media-order owner now sends valid JSON with an actual foreign Origin after
its malformed/unsupported-body cases. Source returns 403 `INVALID_ORIGIN`,
records the real application hook and preserves both principals. The initial
extension's incorrect expectation of no hook failed on Source; the corrected
expectation follows the installed dispatcher rather than changing production.

Published `api/routes/password.mjs` redirects invalid reset tokens by setting
`error=INVALID_TOKEN` on the origin-validated request callback URL. The existing
HTTP owner now explicitly asserts the complete actual target, preserving its
application query. The collector requires one callback URL, the same origin,
no credentials/fragment/preexisting error or token, and exact equality to that
request-bound URL after Source's query update. Unowned, duplicated, malformed or
spoofed error-query locations cannot supply denial evidence.

The harness protects a distinct metadata risk: real Source400 ownership denials
and request-bound reset302 denials disappearing from collection. Its before run
fails because the genuine error-code categories are absent, while unrelated
400s, arbitrary routes, fixture controls and server failures remain negative
controls. It introduces no production seam.

## Corrected declarations

Anonymous/invalid/revoked/expired get-session responses are Source HTTP200/null,
not transport rejection or authorization errors. Google/Apple positive token
admission, sign-out and dispatch signup setup calls likewise retain their real
success/state requirements. The intentionally disabled origin guard has no
rejection at that route; enabled sibling owners retain the promised denials.

OAuth start POSTs succeed before the actual callback admission/replay. Their
misplaced denial requirements move to the genuine callback route. Unavailable
Apple provider/verifier lookup is a 404 rejection, while the actual callback
state check owns authorization denial. Ordinary application callback exceptions
and ambiguous adapter failures retain complete HTTP500/redirect, trusted receipt,
signed identity and unchanged-row comparisons and state requirements; the
collector does not infer an authorization decision from unknown server failures.

This explicit migration yields 4,775 cells on the original parent: 52 incorrect
cells are corrected into retained existing contracts, four actual callback
category requirements are added and six actual OTP rejection requirements are
added. No valuable scenario or denial assertion is deleted. Regeneration still
fails closed when any committed requirement disappears.

## Validation ledger

Baseline owners: terminal1, 66/67, 3,332 assertions, all115 absent. The first
repaired owner run is terminal1, 65/67, 3,414 assertions: unchanged membership
clock drift plus the explicitly corrected Source hook expectation above.
`/tmp/capability-metadata-repaired-owners.log` retains both failures.

Collector harness before: terminal1, 3/4, 55 assertions, missing all three actual
400 ownership authorization categories. After: terminal0, 4/4, 78 assertions.
Logs: `/tmp/capability-metadata-collector-before.log` and
`/tmp/capability-metadata-collector-after.log`. Complete unchanged/extended
harness and TypeScript: terminal0, 72/72, 778 assertions in
`/tmp/capability-metadata-harness.log`.

The first frozen composed head `ce38c9d4e144ef617dd670c6bab6bcff9ef632f7`
on main `2bf51a600d053ea7d1f48d56af25f5d967ee5dce` preserves the full 5,141
parent cells except the explicit 52 corrections plus ten measured additions
(5,099 final cells). `/tmp/capability-metadata-final-canonical.log` is terminal100:
strict default/optional/rustls/fmt, 793 default native, 845 optional native,
fixture2, harness73/849, and alignment36+3+2 all pass. The genuine SDK collection
is 1,383/1,386 with 89,900 assertions. It retains six fixed-membership timestamp
aliases, two member-addition timestamp aliases, and the independently owned #174
expired-proof length discrepancy. The independent strict capability check
`/tmp/capability-metadata-final-inventory.log` reports only the four success/state
requirements belonging to the two failed organization owners. All other repaired
original requirements were genuinely measured. Both failed owner captures and
the complete original collection are preserved as before proof; none are imported
into final positive evidence.

## Complete application and session clock receipts

The organization failures above arise from missing observations: the existing
tracer recorded only response shapes for the two application-owned organization
server bridges, while the membership owner read session expiry only from SQL.
The unchanged comparer already requires an actual creation/issuance receipt in
its own request window before reconciling these dates.

`createTracingFetch` now retains complete bodies only for POST
`/__test/organization-membership-policy/server` and
`/__test/organization-member-addition/server`, alongside its existing public-auth
and API-key creation observations. It preserves every literal field, foreign row,
status and rejection body. GET requests, neighboring paths and unknown fixture
controls retain their earlier privacy bounds. No response body is filtered or
changed. The existing membership signup helper additionally calls the actual SDK
getSession, verifies its user ID and token against the real signup, and verifies
its session ID/user ID/token against the complete durable session rows. These
complete SDK receipts remain compared in traces; the fixed-policy owner also
retains them directly in its returned observation. Both original membership
success/state requirements remain unchanged.

The new primary transport observer owner serves real HTTP rows and checks exact
full-body retention, foreign rows, literal application values, status and complete
rejection bodies. Its before run fails specifically on missing responseBody:
`/tmp/capability-metadata-trace-before.log`, terminal1, 3/4, ten assertions.
After the narrowed capture, full harness/typecheck pass75/961 in
`/tmp/capability-metadata-trace-after-harness.log`. Existing clock/cookie negative
controls and the new HTTP owner reject out-of-window creation and altered session
lifetimes, while unknown controls and wrong methods/paths remain private. This
protects an observation transport risk independent of the real organization
admission owners and needs no production seam.

The actual two-owner intermediate run
`/tmp/capability-metadata-trace-org.log` is terminal1, 1/2, 600 assertions: all
member-createdAt aliases disappear, but four fixed-membership session expiresAt
aliases remain. After the genuine SDK issuance receipt, the unchanged two owners
pass2/2, 732 assertions in `/tmp/capability-metadata-session-receipt-org.log`.
A separate read-only adversarial command captures two fresh actual Source HTTP
organization/session runs and complete physical/foreign rows. Its unmodified
comparison passes; changing all matching member creation aliases outside the real
request window or extending the real session lifetime by 60 seconds produces
specific creation/lifetime differences. Terminal0:
`/tmp/capability-metadata-receipt-counter-actual.log`. The earlier module-resolution
failure is retained in `/tmp/capability-metadata-receipt-counter.log`; it supplied
no parity evidence. No comparator, tolerance, Source package or positive evidence
artifact is modified by this probe.

The current candidate composes onto actual main
`4bcd25c3084ac16b39c96b8dc42804f80dc21900`: all 5,339 parent cells, including
Kakao/Kick/password and selector prerequisites, survive the same explicit
52 corrections plus ten measured additions, yielding 5,297 cells and unchanged
143 route records/flags. Before the receipt extension, its strict/fixture build,
TypeScript, full harness74/927 and warning-free docs pass at
`8f63f9acd98140b913b9bb76b506e184183887d8` in
`/tmp/capability-metadata-composed-checks.log`. The new frozen complete canonical
and strict inventory collection are pending; their artifacts will be freshly
captured, with no copied baseline evidence.
