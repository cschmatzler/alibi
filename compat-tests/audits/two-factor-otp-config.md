# Two-factor OTP storage and lifecycle

The oracle is the published Better Auth 1.7.6 package, specifically
`plugins/two-factor/otp/index.mjs`, `plugins/two-factor/index.mjs`,
`plugins/two-factor/verify-two-factor.mjs`, `utils.mjs`, and its published
random-string and symmetric-crypto dependencies. Standalone actual-handler
probes, with real migrations and SQLite, are recorded in
`/tmp/two-factor-otp-config-oracle.log` and
`/tmp/two-factor-otp-errors-oracle.log`; no implementation copy supplies the
asserted OTP or session transition.

## Production contract

`TwoFactorConfig` exposes f64 OTP digits, lifetime in minutes and allowed
attempts, plus `TwoFactorOtpStorage`. Plain is the upstream default; hashed
uses the existing SHA-256/base64url token helper, encrypted uses the existing
published-compatible XChaCha representation, and custom async hash/cipher
traits receive only the OTP or stored value. Callback rejection propagates at
its actual stage. An awaited delivery rejection is logged while the already
persisted code remains available. Debug output identifies a configured codec
without exposing its captured state or code.

Generation preserves leading zeros, uses the ceiling of fractional digit
counts, and retains configured fractional lifetimes and budgets. Zero/NaN
period and allowed-attempt settings select the upstream three-minute/five
attempt defaults. Expiry uses millisecond Date arithmetic and TimeClip within
Chrono's representable date range. Verification consumes the newest identifier
generation atomically and invalidates all earlier generations; resend does not
prematurely delete them. It splits the stored payload at its first colon and
applies decimal-prefix `parseInt` semantics to the counter, including signed
prefixes, JS whitespace, suffixes and negative overflow. Rejected codes create
a new generation with the original deadline before account failure handling;
an exhausted code is consumed. The OTP-specific budget retains the pending
login cookie, unlike the separate TOTP/backup challenge budget.

Successful first authenticated OTP verification returns the updated user and
newly issued token, retires the original session, and preserves the configured
server-owned session fields through the existing issuance helper. TOTP keeps
its distinct original response snapshot. Pending OTP completion retains the
separately reviewed challenge-consumption, owner, account-budget and typed
session-cancellation behavior.

Enable accepts the source's default `totp` or explicit `otp` method. Body
validation precedes authoritative-session authentication in the actual HTTP
runtime. Password verification precedes provider availability. OTP enable
requires a delivery callback, immediately updates the user and rotates its
session without creating a TOTP factor, including when TOTP is disabled.
Its missing-provider message is `OTP is not available`, distinct from the
send endpoint's message. Send validates its optional trustDevice boolean
before delivery or persistence. The existing enable cancellation mapper and
other factor routes are retained.

## Regression ownership

Nine official-client cases own the observable lifecycle and actual SQLite
state. Five equivalent profiles exercise default/plain, hash, encryption and
both async custom codec kinds, digits 3/3.5/6/8, periods 0/0.5/1/default and
budgets 0/2/2.5/default. Each delivered OTP is independently checked against
its persisted representation, configured length and request-clock deadline.
The encrypted representation is decrypted with the published crypto helper,
and hashing uses WebCrypto SHA-256 rather than the production helper under
test. Wrong owners and codes, consumed replay and real expired rows are denied;
real first enrollment and later pending login persist the correct owner token,
leave no unexpected factor and preserve the foreign owner's full stored state.
Actual async callback inputs and ordering are asserted locally.

The method case exercises malformed and valid guests, invalid method before
wrong-password handling, disabled TOTP, successful OTP-only enrollment,
malformed send input without callback/row effects, and retirement of the old
actual signed browser cookie. Counter cases mutate only the actual stored
counter via parameter-bound fixture controls, then exercise the real verifier
and consumed state. Both budget cases use a real pending login: exhausted OTP
replay is denied, and resending a code completes the same surviving challenge
with exactly the correct owner session. The before-cookie repair fails this
flow with INVALID_TWO_FACTOR_COOKIE
(`/tmp/two-factor-otp-pending-budget-before.log`). A resend/concurrency case retains two real generations,
uses an already OTP-enabled owner to keep its authentication stable during the
race, and proves exactly one official-client completion, rejection of the
loser, removal of every generation and the authoritative stored session.
Both requests have separately captured complete canonical tracing-fetch
entries, recorded through `recordTransport` in semantic success/rejection
order; no transport observations or comparator checks are discarded.

Two native owners add contracts those SDK profiles cannot reach: actual
configured codec/delivery rejection and registered user-update hooks with
server-controlled session extensions; and the missing-delivery password-first
rejection without owner/factor/token mutation. They exercise real plugin
dispatch and the bundled store, not copied predicates. Existing TOTP, hook
cancellation, signed-cookie and backup owners remain intact.

Meaningful before proofs: the original six SDK cases fail on Rust's old scrypt
representation, fixed digit count and malformed-guest ordering
(`/tmp/two-factor-otp-sdk-before-final.log`). Restoring only the old codec,
integer-counter and pre-delete owner behavior makes the new counter and resend
checks fail for those reasons
(`/tmp/two-factor-otp-sdk-counter-resend-before.log`); the callback test fails
before its configured rejection is reached
(`/tmp/two-factor-otp-native-callback-before.log`). Missing-provider message
regression fails after the wrong-password control passes
(`/tmp/two-factor-otp-native-no-sender-before-corrected.log`). Malformed-send
regression observes Rust 200 instead of the source's 400 and leaked delivery
(`/tmp/two-factor-otp-send-schema-before.log`). Tests and production remain
unchanged during each Bun run.

## Dependencies, focused checks and remaining scope

This commit depends on the frozen factor policy and its typed cancellation
repairs. Local parent 8955863 is the exact pending-cancellation capability
2b18a6c; local 081663b is the coordinator's separate strict concurrent-transport
prerequisite ed5bf906. The coordinator omits duplicate dependencies when
integrating and forwards the separately reviewed passwordless parser and
latest authoritative disable/custom session-field behavior. No schema,
migration, lockfile, comparator, coverage or shared inventory changes occur in
this capability commit. Branch-local fixture registration and a focused test
selector are the only shared integration wiring.

Focused validation passes 36 SDK scenarios / 1,542 assertions and 12 native
two-factor tests. Focused verification logs: `/tmp/two-factor-otp-sdk-family-validated-final.log`
for the complete two-factor SDK family;
`/tmp/two-factor-otp-native-validated-final.log` for native dispatch;
`/tmp/two-factor-otp-typecheck-validated-final.log` for TypeScript;
`/tmp/two-factor-otp-clippy-validated-final.log` for workspace library Clippy.
Rust formatting and diff checks also pass. Canonical full gates, independent
review and publication belong to the coordinator.

Remaining capabilities are explicit: authenticated OTP enrollment session-hook
cancellation still propagates the default 403 while the pinned runtime emits
an empty 500 (actual probe recorded above); pending completion already emits
its distinct JSON 500. Genuine identical-message Forbidden remains 403.
The existing factor-secret/backup AES format remains a separate confirmed
XChaCha interoperability gap; this slice changes only OTP storage. Backup
configuration/server-only disableSession and trust-cookie policy remain
separate work. Arbitrary invalid/extreme generation settings, including the
source's nonterminating sub-half-character random buffer, and dates outside
Chrono's range are not claimed. OTP method plus passwordless configuration
requires the coordinator's forward parser merge and focused review.

## Integrated validation

Forward integration preserves inherited password schemas, method-before-issuer validation, configured session fields, and all existing inventory requirements. Independent forward review is clear. The canonical gate passed on this tree: 316 SDK scenarios / 10,748 assertions, 39 harness tests / 243 assertions, two Chromium tests / 22 assertions, and 79.38% source line coverage (25,562 / 32,203). Full log: `/tmp/two-factor-otp-reviewed-canonical.log`. Combined passwordless enrollment evidence is recorded in [the interaction audit](two-factor-otp-passwordless.md). PR #46.
