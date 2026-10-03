# Terminating raw two-factor numbers

Issue #201 uses published Better Auth 1.7.6 and its installed
`plugins/two-factor/{totp,otp,backup-codes}` and `@better-auth/utils/{otp,random}`.
Bounded actual-handler probes ran under `timeout 30s` before implementation;
`/tmp/issue201-evidence/source-probe.ts` and `.log` retain their raw results.
No installed dependency was modified. Tests retain the ordinary comparator,
complete public transport and physical user/session observations.

`TwoFactorConfig::totp_digits` and `totp_period` now accept `f64`. Zero and NaN
select provider defaults. Enrollment preserves the raw period in its URI,
while retrieval uses the provider default. TOTP generation uses millisecond
counter arithmetic, modulo-2^64 counter encoding, SHA-1 HMAC, floating-point
remainder and JavaScript number formatting. Fractional digits can produce
*decimal strings*, exactly as Source does; they are not rounded to integer
digit counts. Negative periods and both infinite periods remain supported.
Verification evaluates the entire three-counter window and compares UTF-16
units, including lengths. Invalid generation restores the pending attempt and
returns Source's empty HTTP 500 without changing the factor/account.

OTP and backup generation remove the old 32768.5-character/count restriction.
Finite lengths round up; backup amounts truncate with JS array-length bounds.
Fallible native allocation replaces the artificial cutoff. NaN generates an
empty OTP or the backup separator alone, while nonpositive backup amounts
skip generation entirely. Infinite OTP lengths and invalid OTP dates now return
the measured empty 500 before persistence/delivery. Existing zero/nonpositive
TTL, backup and OTP handling, fractional trust TTL, generators/codecs and sender
failure policies are preserved.

Authenticated TOTP session-hook cancellation now has its own private typed
error and returns an empty 500. A real application Forbidden with the identical
message remains 403. The real owner updates the user before attempting session
creation: cancellation retains the old session and unverified factor, creates
no trust proof, and allows retry to mark that factor without rotating the old
session. The focused scenario checks this ordering and reset through actual
SQLx and SeaORM owners, with no synthetic owner state.

Native bounds are explicit: Rust strings cannot contain lone UTF-16 surrogates;
application secrets accept valid UTF-8. Positive random lengths below 0.5 give
Source an empty random buffer and a nonterminating loop; native rejects those.
Native allocation failure or lengths beyond native address space return an
error. JS valid dates beyond Chrono's representable range remain unsupported;
nonfinite/TimeClip-invalid dates fail. Probes never request nonterminating
lengths, massive arrays, or unbounded output. OAuth providers, organization
configuration, raw quotas #378, schema, dependencies and comparisons are outside
this change.
