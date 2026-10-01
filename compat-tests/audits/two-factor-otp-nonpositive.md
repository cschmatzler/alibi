# Nonpositive configured OTP generation failures

Published Better Auth 1.7.6 passes explicit zero and negative digits through its
OTP options to the installed random-string utility. That utility explicitly
throws for length <= 0. Actual runtime probes of 0, -1, and -0.25 terminate with
an empty 500 response, no delivery, no OTP row, unchanged disabled user, and
retained original session. Evidence is `/tmp/two-factor-otp-zero-oracle.ts/.log`.
Zero is not converted to an empty OTP or a default digit count.

The Rust guard already rejected nonpositive lengths at the correct stage, but
its generic internal-error JSON differed from the pinned empty response. The
private `SendOtpError::NonpositiveLength` now identifies only that generation
failure; `handle_send_otp` emits the empty 500. All other AuthError values retain
their original handling, including application errors from codec callbacks.
Sender availability and state resolution remain before generation; body schema
validation remains before core dispatch. No shared error or public API changes.
Large/infinite positive lengths and extreme dates remain separately bounded and
are not covered by this response repair. Nonterminating positive sub-half-digit
source configurations were not executed in the main harness.

One new parameterized official-client case in the existing OTP test owner uses
equivalent zero and negative fixture profiles. It proves guest rejection,
malformed body rejection, actual SDK failure, zero real delivery/codec receipts
and generations, and complete persisted original-user/session preservation.
Its canonical transport and SDK output preserve the empty-response observation;
there is no comparator exemption or error-message normalization. Existing
positive/configured OTP cases remain the success controls. No duplicate native
predicate or test-only production seam was introduced.

Before `/tmp/two-factor-otp-nonpositive-sdk-before.log`, nine OTP sibling cases
pass and this owner case fails exactly on SDK error.message field presence for
both lengths: generic Rust JSON versus the pinned empty body. Both runtimes'
persisted state assertions already pass before the response change.

Final focused verification:

- 45 two-factor SDK cases / 2,028 assertions:
  `/tmp/two-factor-otp-nonpositive-sdk-final.log`.
- 15 native two-factor cases:
  `/tmp/two-factor-otp-nonpositive-native-final.log`.
- Client TypeScript and workspace library Clippy with warnings denied:
  `/tmp/two-factor-otp-nonpositive-typecheck-final.log` and
  `/tmp/two-factor-otp-nonpositive-clippy-final.log`.
- Workspace and excluded Rust-server formatting, and `git diff --check`, pass.

Parent is factor-codec freeze `1023ffe`. Only this bounded route error, existing
OTP fixture module/profile additions, one test owner extension, and this audit
change. No inventory, coverage, comparator, skip, selector, lock, schema,
migration, or full canonical gate changes. Coordinator independent review is
requested; the external autoreview command referenced by test-audit is not
available in this environment.
