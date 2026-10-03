# Installed backup JSON verification

PR #417 repairs a production mismatch in public backup verification against
published Better Auth 1.7.6. Native decoded the entire stored JSON as
`Vec<String>`: a mixed array containing a valid string proof failed wholesale,
and a truthy non-array value incorrectly became an invalid proof. Source instead
uses strict `includes`/`filter` on the parsed value inside its decode-stage
try/catch. Shape exceptions restore a pending attempt; invalid JSON spends it.

Verification now reads the JSON value, accepts only exact string matches within
arrays, removes every duplicate matching string, and re-encodes the other
values. Truthy non-arrays restore the attempt and return an empty 500. Invalid
JSON, falsy values and wrong proofs retain the invalid-proof branch. Default
cipher authentication, legacy readers, exact factor-ID/ciphertext CAS and
callback error identity remain unchanged. No global decoder, cookie helper,
schema, fixture behavior or dependency changed.

The existing encrypted-factor SDK owner now has one corruption lifecycle. It
starts with an actual published enrollment, imports Source-encrypted malformed
storage through the existing controlled fixture, and exercises the official
client against real SQLx and SeaORM SQLite stores. It checks four truthy shapes,
invalid JSON, exact numeric-versus-string proof identity, a mixed array with
Unicode object content and duplicate valid codes, reset, challenge retirement,
full factor-row preservation, foreign factor/user/session state and replay.
All original transport/cookie observations remain in the strict comparator.
The opaque challenge observation uses the existing `{ token: identifier }`
representation; raw identifiers and observations remain intact in the receipts.

The corrected baseline Source lifecycle completes; native fails with 401 where
Source returned an empty 500. The earlier baseline failed on a test expectation
that overlooked the actual account-failure increment for invalid JSON; that log
is retained but is not the production before proof. The initial repaired run
passed local assertions on both servers and failed only on the untyped random
challenge observation, which was corrected without changing comparisons.

Permanent evidence: `/home/cschmatzler/.local/share/better-auth-evidence/factor202`.
The published npm tarball matches registry SHA-512 integrity, and both installed
two-factor modules inspected match that tarball. Private frozen Bun installs
were used without dependency mutation. Source/SQLx and Source/SeaORM pairs retain
complete transports, actual input proofs, observer rows and retirement cookies.
Three existing native callback-stage/server-only-view tests and API library
Clippy pass. The final selected lifecycle strengthens foreign-factor and
numeric-proof assertions. TypeScript, scoped lint, formatting and diff checks
are recorded alongside each affected backend run. Incoming #415 changes were
read and rebased; its numeric renderer refactor preserves the factor cookie
writer's existing default behavior. Passing unrelated scenarios were not replayed.
Actions are disabled; no CI, full suite, devenv-test or coverage claim is made.

## Issue #202 reconciliation

This work does not close #202. Prior fresh/legacy codec proof, trusted-cookie
truthiness and Base64-bit aliases, pending lookup/error ordering, disable
ownership, raw numerical configuration (#201), and secret rotation (#176) remain
covered by their landed owners. Those are not duplicated here.

A live published server-only probe records two concrete remaining contracts:
truthy object backup JSON is returned as an object by `viewBackupCodes`, whereas
the native public view and endpoint output require `Vec<String>`; and an ISO
string installed as a backup code is revived into a Date by Source's parser,
so it is not equal to a submitted string proof. Source's view normalizes that
date to milliseconds. Native's JSON-value comparison retains the string.
These outputs are recorded in `source-unsupported-boundaries.log`. Arbitrary
malformed server-only output would require a public native return-type contract
change. Date revival, extended Date/Chrono limits and nonfinite parsed numeric
JSON are not claimed supported by this repair.

Pending/preference/disable URI and Unicode alias admission, together with their
exact malformed-value retirement stages, remains unproved by the landed HTTP
receipts. The existing native pending preference test owns signed-empty,
wrong-key and first-cookie behavior, not those wire aliases. The native callback
stage regression and prior Source 400/403 receipts protect explicit application
errors; ordinary versus explicit same-message errors combined with installed
corruption are not newly claimed covered. No closing keyword or newly fabricated
production change substitutes for these remaining acceptance requirements.

The external autoreview tool/skills referenced by test-audit are unavailable.
This sole-worker task performed a separate production/security review without
nested contributors; independent external review is not claimed.
