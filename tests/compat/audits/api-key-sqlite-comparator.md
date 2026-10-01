# Complete API-key SQLite comparison

Issue #271 is a prerequisite for #204. Read-only installed Better Auth 1.7.6
captures exposed phantom second issuances for complete SQL rows and an invalid
prefix assertion for actual surrogate-cut readback. The original #204 Source-only
logs remain `/tmp/issue204-source-options.log` and
`/tmp/issue204-source-options-2.log`; no Native process participated.

The authoring gate protects the comparator's independent storage and identity
contract. A complete real SQL row must be derived from a genuine issuance, and
SQLite WTF-8 bytes must encode an actual UTF-16 prefix of that credential with the
exact database text readback. Credible regressions include using a foreign hash,
changing the cut bytes, changing readback, or falsely treating an unobserved row
as an issuance. Existing API-key comparator owners cover ordinary public prefixes
and partial rows, and therefore do not reach these complete SQL receipt shapes.

The new owner invokes installed Source authentication and generation against a
real migrated Bun SQLite database. It captures both issuing users, both real keys,
all persisted columns, actual `hex(CAST(start AS BLOB))` and `typeof(start)`, and
real public readback. Negative controls mutate those actual observations. There
is no new production export, fixture-generated callback receipt, fake hash or
allowlist. Existing owners and raw observations remain.

The exact new real-Source harness owner failed before the fix with 35 assertions:
the two full SQL rows were reported as changed plaintext credentials, and actual
issued/read/persisted surrogate cuts failed the prefix relationship. The final
owner passes, including single-side tampering and matching invalid bytes/hash
corruption on both sides. Plain and hashed storage modes are both valid; a mode
change on just one side fails, while equal modes still require real derivation.

All 71 harness owners pass with 754 assertions, and the client TypeScript check
passes. The first full harness attempt had one environment failure because this
isolated worktree lacked its reference dependency symlink; adding the existing
pinned dependency installation resolved it without a code or test change.

Actual Source-only integration proof uses `/tmp/better-auth-issue-271-proof`,
based on the same main as this PR and the unchanged #204 application fixture and
owners. Before the comparator repair all six fail at comparison, after their
behavior assertions passed. After copying only this comparator repair all six
pass. Both runs execute 2,624 assertions. Logs are
`/tmp/issue271-source-before.log` and `/tmp/issue271-source-after.log`. No Native
process runs in that proof. It retains the full observations and all raw traces;
the #204 production changes are not prerequisites for these actual Source calls.

The canonical gate will be executed on the committed immutable head, and its
actual terminal result will be reported separately from these focused passes.
The skill's OpenClaw/Crabbox/autoreview tools and scripts are unavailable; actual
repository checks and independent root review are reported without claiming
those unavailable checks ran.
