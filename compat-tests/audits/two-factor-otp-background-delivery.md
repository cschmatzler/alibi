# OTP delivery with an application background handler

This bounded capability starts from selected integration 87b84649 and changes
only factor-local delivery scheduling. Existing OTP storage, enrollment, budgets,
secret/backup codecs, trust policies and authoritative-session behavior remain
owned by their merged capability audits. No public configuration, core/store
contract, schema, dependency, lockfile, comparator or inventory is changed.

## Published runtime and implementation

Better Auth 1.7.6 `plugins/two-factor/otp/index.mjs` creates the verification row
before calling sendOTP. An asynchronous delivery rejection is caught and logged.
`context/create-context.mjs::runInBackgroundOrAwait` awaits that promise when no
application background handler exists; otherwise it gives the handler the hot
completion and returns. It also catches/logs a synchronous handler exception.
These errors leave the already issued OTP available for real verification.

Actual pinned real-TCP probes are preserved in
`/tmp/two-factor-otp-background-oracle.mjs/.log`. Default, observe, ignore and
throwing-handler configurations use real signups, migrations, signed cookies,
an application-held async sender and actual SQLite rows. Default send remains
pending at the sender receipt; configured responses return 200 while delivery
remains held. After rejected delivery, real OTP verification enables the owner
and rotates its persisted session. A second actual probe
`/tmp/two-factor-otp-background-api-errors-oracle.mjs/.log` confirms explicit
application APIError 400 from delivery and 403 from the handler are swallowed at
this stage too. The original invalid-origin probe setup failure is retained in
`/tmp/two-factor-otp-background-oracle-origin-setup.log` and is not proof.

The private factor `otp.rs` owns the sender Arc, original UserView and OTP.
Default delivery remains awaited. Configured delivery is eagerly polled once,
then pending work is owned by the current Tokio executor before the existing
BackgroundTaskHandler receives its completion. Dropping the completion or
rejecting registration cannot cancel that work. The operation logs delivery
AuthError and resolves Ok, matching the caught source promise. Only this
registration stage catches/logs the handler's error; unrelated callback errors
and other plugins' error mappings are not modified. The initiating framework
request-hook context, current tracing span and subscriber are captured.

## Evidence ownership and meaningful failures

Four official-client owners cover default, observed, ignored and throwing
handlers. Each uses actual owner/foreign signups, real signed cookies and a
genuine async application sender gate. Actual delivery entry is acknowledged;
configured entry also waits for actual registration. The response succeeds
before delivery release only with a configured handler. The observer receives
successful completion even when the sender rejects. Ignored/thrown observers
still allow the original sender to finish with its original owner snapshot.
Observed release acknowledges both sender completion and the real completion
observer before returning its application-control response.

The genuinely persisted plaintext code is checked against the actual callback
input before any random-code redaction. Wrong-owner and wrong-code requests,
real first enrollment, old-cookie retirement, consumed replay, a pending login,
actual SQL expiry and renewal of the same login challenge prove that scheduling
cannot manufacture a session or borrow another owner's authority. Configured
delivery remains held during enrollment/renewed pending completion. Callback
user ID/email/flag stay at their initiating values even after the persisted user
and session change. Complete owner/foreign state and every physical OTP and
challenge row field/date are retained. Actual pending challenge rows anchor the
OTP identifier and user; successful completion removes them.

Composite OTP identifiers are retained losslessly as the original token plus
decoded observed user/session or challenge components. Local roundtrips, exact
initial stored-user/session equality, actual pending challenge equality and
unchanged resend identity guard their meaning. No alias rule or comparator is
added. Plain random codes are checked against stored values and all callback
receipts before the existing style of random OTP result redaction; counters,
digit counts, row identities, dates and all complete canonical transports remain.
Independently captured send transports are recorded after genuine completion in
explicit order, including every response header/cookie/status/body.

One native public-route/store owner protects the distinct Rust task-local and
owned-future contract. A dropped completion and genuine rejecting observer must
permit the response while the real async sender is held. Its issued code enables
and rotates the actual owner before release. A second verification request uses
different context values; the resumed sender must still see its original request
path/header/query and original disabled-user snapshot. No production test seam
is used: gates are real application implementations of existing public traits.

Restoring the original direct await makes that actual native route fail at the
bounded response guard in `/tmp/two-factor-otp-background-native-await-before.log`.
Removing only captured request-hook context makes resumed delivery fail on the
missing initiating context in
`/tmp/two-factor-otp-background-native-context-before-bounded.log`.
An initial version of the latter test left its completion channel owned after a
panic; it was stopped only in this worktree and a bounded completion guard was
added. Stalled setup logs are preserved and not counted as completed proof.

The first new Source self-control exposed raw random composite identifier drift
(`/tmp/two-factor-otp-background-source.log`); its reversible identity projection
was repaired. The next differential run exposed an application-control response
race between real completion notification and reply (3/4 in
`/tmp/two-factor-otp-background-sdk-identity.log`). The actual acknowledgment
protocol above fixes that fixture race without changing production or dropping
receipts. No retries, tolerance changes or array exceptions hide either failure.

## Focused checks and bounds

Source self-control and differential primary owners each pass 4/976 in
`/tmp/two-factor-otp-background-{source,sdk}-controlled.log`. Complete focused
two-factor family passes 71 owners/5884 assertions in
`/tmp/two-factor-otp-background-family.log`. Native factor family passes 19 tests
in `/tmp/two-factor-otp-background-native-final.log`. Production Clippy and
client/reference typechecking pass. Final strict fixture Clippy and locked build
pass in `/tmp/two-factor-otp-background-fixture-{clippy,build}-final-corrected.log`;
the default-feature-free `rustls,axum,seaorm2,redis-cache` consumer passes in
`/tmp/two-factor-otp-background-consumer-rustls-final.log`. Final rebuilt-fixture
primary differential passes 4/976 in
`/tmp/two-factor-otp-background-sdk-final.log`. Edition-specific formatting and
diff checks pass. Initial relative-path commands,
missing explicit reference TypeScript configuration and fixture edition/lint
setup failures are retained and not counted as successful validation.

The configured pending task requires a current Tokio executor. Runtime/process
shutdown, arbitrary task-local inheritance, Rust panics, synchronous JavaScript
sendOTP callbacks, async-returning background-handler callbacks, additional
custom user-column snapshots, extreme dates and installed malformed storage
remain outside this bounded contract. Normal AuthError delivery and handler
rejections are covered. The authoring gate from test-audit and authorization
review were applied. Coordinator owns independent review, full gates and
publication; no full canonical gate was run here.

## Coordinator integration

The unchanged frozen slice was read against the pinned sender and
runInBackgroundOrAwait runtime. Owned eager polling, default await, retained
issued-code state, ignored/throwing observer completion and original task-local
context match the demonstrated asynchronous contract. No broad callback/error
mapping changed. Coordinator and independent organization-owner reviews are clear on frozen
9c7067d8. The following canonical gate remains pending. Twenty-eight additive names
are required in actual inventory evidence: all four owners require successful,
rejected and stateful send/verify behavior, and genuine guest send rejection
supplies authorization evidence. Verification authorization is not inferred
from its wrong-owner expired-code response.
