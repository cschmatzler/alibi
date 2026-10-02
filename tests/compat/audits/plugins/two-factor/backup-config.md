# Configured backup generation, persistence and session policy

This capability follows the separately frozen factor-cipher prerequisite
`1023ffe` and nonpositive OTP response repair `5e2a23f`. It adds API-local backup
options without schema, dependency, comparator, coverage or inventory changes.
Published Better Auth, its official client and the reference fixture remain
pinned to 1.7.6.

## Source contract and production boundary

Published `plugins/two-factor/backup-codes/index.mjs` uses
`Array.from({length: amount ?? 10})`, random strings of `length ?? 10`, and a
separator after the first five characters. The actual runtime supports zero or
negative amounts as an empty array without evaluating the random-string length;
fractional amounts truncate and fractional string lengths round up. The new
f64 options retain these distinctions, including explicit zero. A synchronous,
input-free Rust generator returns its strings unchanged; asynchronous custom
cipher callbacks receive the whole JSON array string or stored string.
Encrypted storage remains the default and uses the separately reviewed shared
XChaCha writer/installed legacy reader. Plain storage and custom cipher storage
apply consistently to enrollment, regeneration, verification and the existing
server-only `view_backup_codes` method. No HTTP route exposes that method.

Generation or initial encoding occurs before skip-enrollment user updates,
session rotation or factor insertion. Regeneration checks the user flag,
password and existing factor before generation, then updates only that exact
factor row's backup field. Its ID, secret and account policy fields survive.
Missing factors now produce the pinned TWO_FACTOR_NOT_ENABLED error, including
users enabled through OTP-only enrollment.

The private InvalidGeneration discriminator maps the bounded generation failure
to the pinned empty 500 only in enrollment and regeneration. Callback AuthError
values retain their identity, status and message. Typed session cancellation
keeps its existing separate route mapping; an application error with the same
message is not cancellation.

Verification removes every matching duplicate, encodes the remaining array,
then applies the existing exact-ID/expected-ciphertext compare-and-swap. Decode
errors restore pending attempt state; encoding errors after successful decode
leave that attempt consumed, without changing the factor or challenge. Pinned
runtime probes independently establish both stages in
`/tmp/two-factor-backup-pending-callback-oracle.ts/.log`.

Pending disableSession verification consumes matching codes and the shared
attempt while retaining the real challenge. It omits the token and emits no
session or trust cookie, creates no session and does not consume the challenge.
Another factor's separate budget can still complete it. Authenticated existing
session verification instead returns its current token without rotation, as
published source does. Account failure resets remain after successful backup
CAS and before the response branch.

## Meaningful evidence

The official-client owner `tests/plugins/two-factor/backup-config.test.ts` has five
bounded profiles: fractional plain generation, zero amount/length, negative
amount/length, encrypted generation and custom generation/cipher callbacks.
Each exercises actual enrollment, independently decoded persisted storage,
actual server-only retrieval, foreign-owner and invalid-code rejection,
consumption/replay where codes exist, password rejection and regeneration with
stable factor ID/secret and original session ownership. The custom generator
intentionally produces duplicates; verification must remove them all. Its
receipts contain actual callback inputs, not synthesized owner outcomes.
Parsed factor state retains every field through passthrough rather than
comparing a projection to a complete row. Random code values are asserted
against actual storage before result redaction; complete transport observations
remain untouched.

A separate owner checks invalid configured length, guest/password ordering,
empty generation failure, OTP-only enrollment bypassing unused backup generation
and missing-factor regeneration. The pending owner proves omitted token,
unchanged user/session state, retained exact challenge identity, consumed budget,
no trust, backup replay rejection, and real OTP completion of that challenge.

Two native public-route/store tests protect distinct Rust callback contracts:
generator/encoding rejection preserves actual factor/user/session state and
application 400/403 identity; pending decoding/encoding rejection preserves the
source stage-specific attempt state and actual retry behavior. Published runtime
400/403 controls with a cancellation-like message are independently recorded in
`/tmp/two-factor-backup-callback-oracle.ts/.log`. No test-only production seam or
private predicate assertion is introduced.

Before-fix proofs:

- `/tmp/two-factor-backup-config-sdk-before-corrected.log`: equivalent configuration
  interfaces and fixtures were scaffolded while the old production generator
  still produced ten codes. All five published-runtime cases completed; Rust
  failed on the actual configured counts; 45 sibling cases passed.
- `/tmp/two-factor-backup-config-sdk-pending-before.log`: the old pending finalizer
  issued a token/session for disableSession. The new owner failed on token field
  presence while 51 siblings passed.
- `/tmp/two-factor-backup-config-sdk-mapper-before.log`: generic Rust internal JSON
  differed from the pinned empty configured-generation failure. The intended
  owner failed in strict comparison while 51 siblings passed.

The earlier uncorrected generation log is not a valid production regression:
its test compared projected factor fields with a complete row. That assertion
was repaired before recording the meaningful count failure above.

## Bounds and checks

Positive amount/length above 32768.5 and infinite values fail closed in this
bounded implementation. Source nonterminating positive lengths below 0.5 are
not executed in the harness; Rust rejects them. Extreme allocations, arbitrary
non-string custom-generator results, malformed installed code JSON error-wire
parity, secret rotation, extreme dates and the remaining trust-device settings
are not claimed closed by this capability.

Focused verification logs are `/tmp/two-factor-backup-config-sdk-final.log`,
`/tmp/two-factor-backup-config-native-final.log`,
`/tmp/two-factor-backup-config-typecheck-final.log` and
`/tmp/two-factor-backup-config-clippy-final.log`. Final counts and checks are
recorded after completion below. Coordinator review and canonical integration
remain separate; no full canonical gate is run in this worktree. The external
autoreview tool named by test-audit is unavailable here.

Final focused results: 52 two-factor SDK scenarios / 2,500 assertions, 17 native
two-factor cases, client TypeScript, workspace library Clippy with warnings denied,
workspace/excluded-server formatting and `git diff --check` all pass.
