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
collection/annotation/owner repair, 52 were miscategorized, and two are retained
requirements of the unchanged timing-sensitive membership owner. The inventory
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

Final composed genuine owners and the complete strict inventory gate are pending.
No old artifacts are used to claim their result.
