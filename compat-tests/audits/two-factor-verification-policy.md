# Two-factor verification and account policy

This capability follows the published Better Auth 1.7.6 two-factor schema,
`verify-two-factor.mjs`, `totp/index.mjs`, `backup-codes/index.mjs`,
`otp/index.mjs`, and enrollment/sign-in hooks in `two-factor/index.mjs`.
It depends on the separate atomic factor storage prerequisite a1f2d431 and
nullable SQLite arithmetic correction 9ffc56c. The isolated helper dependency
dbb6479 copies only the already integrated replacement-session helper from
master eaa478e; the coordinator should omit that dependency when integrating.

Enrollment explicitly creates an unverified factor, or a verified factor when
skip-verification is configured. A repeated enrollment updates only the exact
unverified generation's secret, backup codes and verified flag. Established
factors reject re-enrollment after password validation. Re-verification marks
the exact factor verified after the user/session transition. The sign-in
method list omits disabled or explicitly unverified TOTP. Pending TOTP rejects
an explicitly unverified factor before consuming its attempt record.

Each pending challenge has an independently stored, equally expiring attempt
record. TOTP and backup failures share the five-attempt budget. Consumption is
atomic; exhausted or malformed counts invalidate the challenge and clear its
cookie. Unexpected TOTP/backup crypto errors restore the consumed attempt
count. Successful pending completion consumes and validates the challenge
owner before issuing a session. Backup consumption uses the exact row ID and
stored encrypted backup generation in an atomic compare-and-swap, removing
every duplicate occurrence of the successfully consumed code.

The account budget spans pending TOTP, OTP and backup failures and renewed
challenges. Defaults are enabled, ten failures and 900 seconds; the public
configuration retains f64 thresholds/durations and supports explicit zero.
Future locks reject before challenge/OTP consumption. Expired clearing uses
the exact conditional storage predicate. Failures first re-arm their challenge
or OTP attempt state, then increment the account count and conditionally set a
lock. Success unconditionally resets the budget before subsequent verification
or session work. Authenticated verification does not check, increment or reset
this account budget. Disabled budgets preserve the stored count.

The actual pinned Kysely SQLite adapter uses NULL + delta, despite a contrary
plugin comment. This implementation and owner tests deliberately preserve that
observed NULL arithmetic. A NULL counter does not lock under threshold zero;
successful verification explicitly writes zero. Ordinary counters default to
zero, and fractional stored values remain fractional. Date creation follows
JS millisecond truncation and invalid-date rejection within Chrono's supported
date range; JS dates outside that representation are not claimed here.

Six official-client scenarios own public policy and actual SQLite state:

- The sixth attempt after mixed TOTP/backup failures invalidates the challenge
  before a real correct code, denies replay and leaves no session. A renewed
  challenge consumes the previously unused real backup and persists its owner.
- Ten mixed failures across renewed challenges lock every pending factor while
  authenticated and foreign owners retain their sessions. Correct codes cannot
  clear the account lock through an authenticated verification.
- Equivalent fractional, zero and disabled profiles exercise 0.5 → 2.5,
  duration 600.25 seconds, NULL preservation/reset, a zero-duration expired lock,
  conditional expired clearing, successful resets and exact factor preservation.
  Each actual fractional deadline is checked against that runtime's request
  clock; cross-runtime observations compare lock presence after those checks.
- Unverified enrollment retains the exact generation and existing count while
  replacing its secret/backups. Wrong passwords and foreign codes cannot mutate
  it; real TOTP establishes it; established re-enrollment fails without mutation.
  A historical explicit-false factor is omitted from TOTP methods and denied
  before consumption, while its real backup still completes with false retained.
- A real delivered OTP shares the pending account lock with TOTP, survives a
  denied locked request, succeeds after expiry, resets the budget and leaves
  the stored secret/backups unchanged. Authenticated wrong OTP does not count.
- Skip-verification enrollment persists true, rejects wrong passwords and
  established re-enrollment, rotates only the owner session, deletes the old
  token, then completes a later sign-in with a real generated backup code.

Trusted fixture controls only read actual persisted rows/delivered callbacks,
seed historical nullable/fractional counters or verified state, and expire a
real stored lock. They do not return a fabricated success or replace the
production policy. Both runtimes use equivalent isolated profile options and
parameter-bound mutations. Dynamic encrypted secrets/backups remain asserted
for equality or changes locally and are excluded from returned observations;
the real codes are exercised through official clients.

The existing private rotation helper test is replaced, rather than duplicated,
by an actual enable → real TOTP plugin dispatch. It independently owns native
callback mutation and configured session fields: the update hook receives the
owner and true flag, mutates a name that persists, and the new signed cookie
reads the owner with org/team/impersonation/IP/agent fields intact. The old token
is deleted and the exact factor becomes verified with secret/backups unchanged.
It fails against the frozen pre-policy API owner (verified true instead of
false at enrollment) in `/tmp/two-factor-policy-hook-before.log`. The original
two SDK budget regressions fail on the actual pre-policy owner by accepting a
sixth/eleventh real code (`/tmp/two-factor-lockout-before.log`).

The separate storage tests own installed schema preservation, idempotence,
eight independent connections with unique increment snapshots, conditional
expired clearing, stale threshold protection and a single backup CAS winner.
The API tests do not duplicate those lower storage concurrency contracts.

Focused validation: all 18 two-factor SDK scenarios / 630 assertions pass
(`/tmp/two-factor-policy-sdk-family-final.log`), including the six new scenarios
/ 426 assertions (`/tmp/two-factor-lockout-sdk-final.log`). Nine native API tests
pass (`/tmp/two-factor-policy-native-final.log`). TypeScript
(`/tmp/two-factor-policy-typecheck-final.log`), workspace library Clippy with
seaorm2 (`/tmp/two-factor-policy-clippy-final.log`), formatting and diff checks pass.
No shared inventory, comparator, coverage, dependency, lock or migration changes
occur in this API commit. The coordinator owns independent review/full gates.

Further capabilities remain explicit: passwordless enable/disable/URI policy;
custom OTP/backup storage and configurable generation; OTP first-enrollment
response/token behavior and malformed OTP counters; pending backup
disableSession semantics; trust-cookie configuration; extreme Date values;
custom session fields from the separately coordinated session contract. This
slice does not claim those remaining 1.7.6 branches complete.
