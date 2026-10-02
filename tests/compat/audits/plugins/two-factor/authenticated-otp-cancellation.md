# Authenticated OTP session-creation cancellation

This route-local capability follows trust-lifetime freeze `cddfaa0` and the
separate backup-fixture reset prerequisite `50c3807` (local equivalent
`b18dc9ab`). It does not change shared error types, helpers, schema, dependency,
fixture profiles, inventory, coverage, selectors or comparison rules.

Published Better Auth 1.7.6 `plugins/two-factor/otp/index.mjs` consumes the
session-bound OTP before updating a disabled user to enabled. It then creates a
replacement session, sets its cookie and finally deletes the original session.
An actual session-hook cancellation returns null; the subsequent cookie writer
throws and produces an empty 500. The consumed OTP and enabled user remain,
while the original session remains valid. A genuine application Forbidden with
the same cancellation-like message remains structured 403. The independent
public-handler probe is `/tmp/two-factor-otp-auth-session-cancel-oracle.ts` and
its `.log`, including the successful rotation and exact persisted-state controls.

The private ExistingSessionFactorError distinguishes only the typed cancellation
returned by the replacement-session issuance helper. User enablement and
operations outside that helper, including a typed cancellation returned by user
update, remain ordinary AuthError values. The issuer retains its existing
user-read/admin-ban policy; correctly implemented stores emit this semantic
variant from session creation. Artificial use of that creation-specific variant
from the issuer's preceding reads/ban update is not separately stage-coded by
the existing helper and is not claimed here. The authenticated OTP handler alone maps this creation result to empty
500. Existing TOTP and backup callers convert the private result back to their
prior AuthError contract; pending OTP completion retains its separately reviewed
FAILED_TO_CREATE_SESSION response. No message matching or generic Forbidden
remapping is used. Write order and original-session deletion order are unchanged.

The official-client owner has three equivalent existing runtime profiles:
cancelled creation, genuine same-message Forbidden, and successful rotation.
Actual signup supplies the authenticated session with two-factor disabled and no
factor row. Real delivery is checked against the exact persisted session-bound
OTP and counter. Guest and foreign-session attempts cannot consume it or change
owner state; a wrong code increments only its OTP counter. Completion consumes
the code, enables only that user and preserves the factor-free state. Rejection
retains the original complete session; success rotates its token and ID. The
cookie-backed getSession observes the resulting authoritative user/session.
Neither branch creates trust, and replay is rejected with unchanged persisted
owners. Complete SDK and canonical transport observations are retained.

The distinct native owner uses actual installed SeaORM hooks rather than a
synthetic test error. It checks cancelled creation against same-message 400 and
403 application errors, and typed cancellation from user update. Hooks receive
the original IP/agent fields. Actual user/session/factor/OTP persistence and
retry distinguish the creation stage from earlier failures. Its session baseline
is the persisted state after sending, preserving normal authoritative-session
refresh rather than comparing an unrelated stale setup expiry. No new test-only
production seam or duplicated private-predicate test is introduced.

Before `/tmp/two-factor-auth-otp-cancel-sdk-before.log`, all source owners complete
and Rust fails exactly on cancelled creation status 403 versus required 500.
The genuine Forbidden and success controls pass, along with 58 existing sibling
cases (60 pass, one intended failure). Invalid setup or compile failures are not
used as behavioral before evidence.

Final focused results are recorded below after completion. Only focused family
checks are run here; coordinator review and full canonical integration remain
separate. The external autoreview tool referenced by test-audit is unavailable.

Final focused results: 61 two-factor SDK scenarios / 3,174 assertions
(`/tmp/two-factor-auth-otp-cancel-sdk-final.log`), 18 native two-factor cases
(`/tmp/two-factor-auth-otp-cancel-native-final.log`), client TypeScript and
workspace library Clippy with warnings denied
(`/tmp/two-factor-auth-otp-cancel-typecheck-final.log` and
`/tmp/two-factor-auth-otp-cancel-clippy-final.log`) pass. Formatting and
`git diff --check` pass. The native session baseline correction is a test setup
repair, not production evidence; the valid SDK pre-fix failure remains the sole
primary regression proof.
