# Configured verification, mailbox changes and account deletion

Issue #186 uses the installed, unmodified Better Auth 1.7.6 application as its
oracle. The production owners are `api/routes/email-verification.mjs`,
`api/routes/update-user.mjs`, `api/routes/session.mjs`, cookie writers and the
actual internal SQLite adapter. The lifecycle fixture registers real public
configuration, callbacks and cryptography on both servers. Its private controls
read complete persisted rows, choose application callback errors, alter the
actual stored session clock, and hold an actual deletion callback for concurrency.
They do not supply authentication, callback receipt/order or deletion admission.

## Stage contracts

* Signup delivery uses `sendOnSignUp ?? requireEmailVerification`; sign-in
  delivery additionally requires verification and explicit send-on-sign-in.
  Delivery observes the real original HTTP method, full URL and application
  marker. Native exposes the original URL on `RequestHookContext` while keeping
  the logical routing path, original body, trust policy and request metadata.
* Ordinary verification calls before/after hooks around the stored update, then
  resolves an automatic sign-in session. Already verified mailboxes skip hooks
  and session resolution. Existing sessions retain their original snapshot with
  only the verification flag changed; absent/foreign sessions create a genuine
  owner session. A rejected after-hook leaves the stored update without issuing
  a session cookie or cache snapshot.
* Mailbox change conceals occupied addresses with the same success shape. The
  missing-delivery guard runs before lookup. Verified old-mail confirmation
  issues a configured new-mail proof without changing rows. New-mail completion
  creates any missing session before updating the mailbox and invoking the
  after-hook, then publishes the selected original session projection. A failed
  after-hook leaves that new physical session and updated mailbox but publishes
  no cookie. An old session for another mailbox cannot complete either stage.
* Unverified promotion updates the mailbox and publishes its old session
  projection before optional delivery. Its ordinary new-mail proof uses the
  configured expiry; with automatic sign-in disabled, verification updates SQL
  while the already issued cache snapshot remains unverified. A configured
  promotion without delivery still succeeds. Same-mail errors retain Source's
  message-only wire shape.
* Deletion checks a truthy password using the initialized maximum and actual
  configured hasher before a body proof. Callback sender configuration selects
  proof issuance before freshness. Tokens use a real CSPRNG and the 32-character
  lowercase-alphanumeric alphabet. Zero configured expiry falls back to 24 hours;
  negative expiry produces a genuinely expired delivered proof. Pending delivery
  retains sessions and cookies even when the notification callback rejects.
* Deletion consumes the actual stored proof atomically before expiry/owner
  admission and before the application hook. Wrong owners and failed before-hooks
  consume the proof without deleting rows. A held before-hook leaves no reusable
  proof; concurrent replay rejects while the first request completes once.
  Success removes only the owner's user, accounts and every session. After-hook
  errors propagate after those writes. Direct deletion and GET callback responses
  clear browser cookies, including after-hook failures.
* Source's body-token deletion invokes the callback as a nested endpoint and
  discards its response headers. Native preserves this observed distinction on
  both success and after-hook errors; the completed database deletion still
  makes the old session unusable. Missing or stale lifecycle HTTP authority uses
  `UNAUTHORIZED`/`Unauthorized`, while trusted storage/application errors retain
  their own error types. Stale update-user authority clears the actual browser
  cookies; missing cookies do not cause an issuance or callback.

## Independent observations

The official SDK owners retain every user/account/session/verification field and
actual application receipt. Foreign rows are compared byte-for-byte within each
runtime before differential comparison. Secret hashes and prefixed proof
identifiers are presented as lossless typed entropy witnesses: the entire actual
hash, salt and key remain observable, and proof prefix/token/owner reconstruct the
original SQL tuple. Actual password verification delegates to each public crypto
implementation; no fixture substitutes a successful comparison.

Every issued email JWT retains its original bytes and its signature is checked
independently with Node HMAC before decoding the actual claims and configured
lifetime. Every cache cookie is retained separately, including two writes during
promotion. Its atom preserves the original signed token, exact parsed envelope,
raw Set-Cookie header, observed clock and actual public Source decoder result.
The unchanged shared comparator validates canonical bytes, HMAC, configured
expiry and the complete authenticated decoded copy. No Source implementation,
comparator, transport allowance or coverage floor changes are included.

Error response bodies are parsed as JSON independently, preserving all fields;
this avoids treating object property serialization order as a behavioral change.
Raw HTTP traces retain complete body types, fields, headers and cookie effects.
Source date controls use the actual adapter's Date binding instead of incorrectly
writing numeric milliseconds directly into its SQL representation. Supplied
absolute timestamps and every resulting stored date remain in the observations.
Signup/sign-in notification proofs are deliberately separated by an observed
NumericDate second so deterministic JWT equality cannot depend on a wall-clock
boundary crossed by only one server.

## Regression and validation record

The genuine pre-repair server at parent `7eeeee5f` failed the initial three owners
for the intended differences: occupied mailbox 422 versus 200, incomplete full
before-delete user receipt, and swallowed after-delete error (200 versus 400).
The preserved log is `/tmp/issue186-three-owners-before-valid.log`.
Additional actual owner runs then exposed eager verification session/cache
callbacks, promotion cache/delivery order, missing HTTP `UNAUTHORIZED` shape,
stale-cookie cleanup, and the body-token nested response-header distinction.
Each failed result is retained before its corresponding repair.

The final focused matrix passes all 40 owners and 1,960 assertions with real
Source/native HTTP servers (`/tmp/issue186-40-owner.log`, terminal exit 0).
Client TypeScript and optional-feature workspace Clippy pass before the final
bounded body-token cookie repair; final exact-head checks remain required.

The concurrency owner was also run with only the original get/check/delete
consumption algorithm restored, while retaining the real configured application
and actual callback gate. Source completed its full concurrent flow, then Native
failed at the held callback because the actual stored proof remained reusable
(31 assertions, `/tmp/issue186-original-consumption-before-valid.log`). This is
an isolated regression check of the original algorithm, not a claim that the
complete old tree implemented the newly configured sender API. Final production
source was restored before commit. The earlier archived-binary launch with a
missing execute permission was a setup failure and provides no regression proof.
The completed owner count, final parent rebase, canonical/native/coverage result,
and independent review will be appended after those commands finish. This audit
does not claim that an earlier focused result is a complete canonical pass.

The existing native success setup now configures the genuine public development
email provider required by its claimed delivery capability. The existing cookie
unit test imports its real public helper directly instead of depending on a
removed production-only import. The exact rebased canonical candidate then stopped at its native default gate:
151 of 154 executed tests passed, out of 794 selected tests (640 not run), with
three stale native change-email setups/expectations. Both integration success
setups and the spec smoke now configure the real public development provider;
the occupied-address expectation follows the independently proven Source
privacy shape. Shared support accepts real AuthConfig overrides without
changing default configurations or validators.

The callback scope here is the complete currently supported initialized core
and plugin user snapshot. AuthUser presently has no custom-user additional-field
accessor; arbitrary custom hidden user columns belong to #184. Source ordinary
verification hooks use adapter users while sensitive session callbacks use
parsed session users, and those boundaries must remain distinct when custom
schema support is implemented. No claim of arbitrary raw/custom user projection
is made by this issue. No duplicate private-core tests or production exports
used only by tests were added.

The repaired native setups passed all four focused selections (the three
canonical failures and the existing unit success) in
`/tmp/issue186-native-expectations2.log`. An initial compilation of those setup
edits used a nonexistent AuthConfig builder method; it was corrected to the
actual public `email_provider` field before that successful run. The final
restored and rebased native fixture also built successfully.

A separate real HTTP probe retained the original issued token/cache bytes and
revoked the actual physical session through the existing adapter control.
Full stored rows confirmed an empty session table while the user and credential
account remained. Independent stdlib HMAC checks verified both runtimes' signed
tokens, compact-cache signatures and user/token relationships. Source ordinary
update-user accepted the genuine cached authority, wrote the requested name and
republished token/cache cookies; the current native ordinary handler rejected
it with UNAUTHORIZED. Both denied a wrong signed-token signature without
issuing cookies. A corrupt cache with the genuine revoked token was denied by
both, with Source retaining its two observable cache-clearing headers. These
artifacts are in `/tmp/issue186-source-cache-authority.json` and
`/tmp/issue186-native-cache-authority.json`. This broader ordinary update-user
cache authority/snapshot contract is recorded for the cache/update-user issues
instead of claiming that #186 implements it. Sensitive change-email and
deletion remain physically authoritative.

## Final frozen integration ledger

Independent production/security review of immutable
`6742a20476af9675210a78e5e6c48c657571a20c` found no blocker. Its parent is actual
main `d8889f8819652bba7ac1d08125fae65552ed660a`; all 3,433 parent requirements
remain intact and 62 genuine #186 cells are additive. The earlier 9128 native
failure and original atomic-consumption failure remain in the logs above.

The exact canonical command `devenv shell -- bash scripts/check.sh` ended with
exit 100 at the complete SDK gate (`/tmp/issue186-6742-canonical.log`). Before
that failure, formatting, both default/optional all-target workspace Clippy
variants, the no-default optional check, default native 794/794, fixture 2/2,
optional native 845/845, TypeScript, all 71 harness tests (754 assertions), Axum 36/36, endpoint
validation 3/3 and capability inventory 2/2 passed. The full actual SDK run
passed 966/971 owners with 68,004 assertions, including all 40 #186 owners.
It is not a complete canonical green result. The five remaining failures are:

* API-key server validators: ten Content-Type header observations differ.
* Organization fixed membership policy: two member-createdAt observations and
  two candidate-session expiry observations exceed the existing clock tolerance.
* Three generated seed-12648430 profiles: only step 22's public change-password
  unauthenticated code/message differ. Steps 21/29's lifecycle authority shape
  now matches. The public password guard/error boundary remains #181/#193; this
  is not a trusted server-only #205 dispatch claim.

The organization failure was reproduced using the unchanged owner, real servers
and the exact d888 parent in `/tmp/better-auth-issue-186-parent-proof`. That
parent failed only the two member-createdAt paths, each comparing
`2026-10-02T00:22:32.795Z` with `2026-10-02T00:22:35.127Z` (204 assertions,
`/tmp/issue186-parent-membership-owner.log`, exit 1). The frozen final focused
owner also failed those two paths (`00:23:41.670Z` versus `00:23:44.232Z`) and
two candidate-session expiry aliases (`2026-10-09T00:23:41.659Z` versus
`2026-10-09T00:23:44.134Z`), with no other observed value/ownership/row/category
differences (204 assertions, `/tmp/issue186-final-membership-owner.log`, exit 1).
This establishes the precise parent subset; it does not claim identical counts
or infer an identical cause merely from the scenario name or duration. The
original full-run diagnostics are retained unchanged.

The separately invoked evidence checker ended with exit 1, reporting 115
missing cells from the parent inventory and zero missing additive #186 cells
(`/tmp/issue186-6742-capability-evidence.log`). All 62 new cells have real recorded
evidence; no missing parent requirement was discarded. The recorded aggregate
is retained in `/tmp/issue186-6742-capability-evidence.json`.

Independent documentation with warnings denied passed
(`/tmp/issue186-6742-docs.log`, exit 0). Chromium passed 2/2 with 22 assertions
(`/tmp/issue186-6742-browser.log`, exit 0). Clean coverage used documented
`MBX_DISABLE=1` to prevent cached source aliases and ran the unchanged coverage
script: native 845/845 plus all five actual SDK owner suites passed, with
1,078 genuine runtime profraw files and the real fixture object. The unchanged
75% gate passed 30,175/39,025 lines (77.322229%,
`/tmp/issue186-6742-clean-coverage.log`, exit 0). Its 203 workspace source paths
are unique. The report also retains the same conservative standard-library
thread-local inline record (3/6) present in the #179 and #256 reports; excluding
only that non-workspace record for informational arithmetic gives
30,172/39,019 production lines (77.326431%). Neither floor nor exclusions were
changed. Relative to the #179 report, this revision adds 353 production lines.
Actual module hits include email verification 295/383, user management 367/413,
cache runtime 385/414 and request hook context 29/29.

These final observations leave the broader signed-cache update-user migration
in #221 and arbitrary custom-user projection in #184. The final publication
commit retains exactly the frozen 6742 production tree. A separately invoked
strict all-target fixture Clippy found an unnecessary `drop` of SeaORM
UpdateResult in the real session-clock control
(`/tmp/issue186-6742-fixture-strict.log`, exit 101). It was replaced by the
idiomatic explicit discard `_ = ...await...?;` without altering the actual SQL
operation or clocks. Strict fixture Clippy then passed
(`/tmp/issue186-fixture-strict-final.log`, exit 0), as did fixture formatting
and rebuilding (`/tmp/issue186-fixture-build-final.log`, exit 0). The complete
actual final family then passed 40/40 owners and 1,960 assertions
(`/tmp/issue186-final-40-owner-retry.log`, exit 0). Its first attempt was a
setup-only native bind failure (`/tmp/issue186-final-40-owner.log`, exit 1);
it provides no Native parity result. The unchanged retry used fresh ports,
started Native first and verified both owned PIDs during health checks. No
lint suppression or production/test-only interface was added.
