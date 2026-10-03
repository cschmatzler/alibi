# Installed backup JSON verification

PR #417 repairs a production mismatch in public backup verification against
published Better Auth 1.7.6. Native decoded the entire stored JSON as
`Vec<String>`: a mixed array containing a valid string proof failed wholesale,
and a truthy non-array value incorrectly became an invalid proof. Source instead
uses strict `includes`/`filter` on the parsed value inside its decode-stage
try/catch. Shape exceptions restore a pending attempt; invalid JSON spends it.

Verification now reads the JSON value, accepts only exact string matches within
arrays, removes every duplicate matching string, and re-encodes the other
values. Canonical, Chrono-representable ISO dates are normalized as Source JSON Dates and cannot authenticate as string proofs. Truthy non-arrays restore the attempt and return an empty 500. Invalid
JSON, falsy values and wrong proofs retain the invalid-proof branch. Default
cipher authentication, legacy readers, exact factor-ID/ciphertext CAS and
callback error identity remain unchanged. No global decoder, cookie helper,
schema, fixture behavior or dependency changed.

The existing encrypted-factor SDK owner now has one corruption lifecycle. It
starts with an actual published enrollment, imports Source-encrypted malformed
storage through the existing controlled fixture, and exercises the official
client against real SQLx and SeaORM SQLite stores. It checks four truthy shapes,
invalid JSON, exact numeric-versus-string proof identity, a mixed array with
Unicode object content, duplicate valid codes and ISO-date revival, reset, challenge retirement,
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

## Historical #417 reconciliation

This work does not close #202. Prior fresh/legacy codec proof, trusted-cookie
truthiness and Base64-bit aliases, pending lookup/error ordering, disable
ownership, raw numerical configuration (#201), and secret rotation (#176) remain
covered by their landed owners. Those are not duplicated here.

A live published server-only probe records two concrete remaining contracts:
truthy object backup JSON is returned as an object by `viewBackupCodes`, whereas
the native public view and endpoint output require `Vec<String>`; and an ISO
string installed as a backup code is revived into a Date by Source's parser,
so it is not equal to a submitted string proof. Source's view normalizes that
date to milliseconds. The initial native JSON-value comparison retained the string; the final repair normalizes ordinary ISO dates and excludes them from string proofs.
These Source outputs are recorded in `source-unsupported-boundaries.log`. The ordinary ISO-date proof mismatch was then fixed inline: `before-date-sqlx.log` demonstrates Source rejection and native success before the date repair. Both affected backend pairs include native rejection, account-failure spending and retained `.000Z` serialization after repair. Arbitrary
malformed server-only output would require a public native return-type contract
change. Canonical date revival is supported by the same workpiece. Noncanonical calendar rollover forms, extended Date/Chrono limits and nonfinite parsed numeric JSON are not claimed supported.

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

Final validation on rebased main `b41f0e63`: the selected installed corruption/date
lifecycle passes with 164 assertions on SQLx and 164 on SeaORM. The three native
callback/view tests, API Clippy with warnings denied, client TypeScript and
scoped lint pass. Original native shape-stage and date-proof failures remain
in `before-sqlx-corrected.log` and `before-date-sqlx.log`. Additional bounded
published probes record calendar rollover (`2025-02-30` becomes `2025-03-02`)
and parsed `1e400` serialization in `source-serializer-bounds.log`; these are
remaining bounds, not native support claims. No new tests were added for
unimplemented contracts, and no test-only follow-up PR was created.


## Remaining acceptance completed in #419

The remaining production contracts now follow the actual published 1.7.6
runtime. `view_backup_codes` and `BackupCodesOutput.backup_codes` return
`serde_json::Value`, allowing the truthy heterogeneous values Source returns.
The SDK owner calls the installed typed server endpoint through the controlled
view wrapper. Generated arrays keep their ordinary string-array representation;
callers that require a string array can explicitly deserialize that JSON value.
No public HTTP backup-view route is added.

Backup parsing now uses the existing IEEE754 JSON utility without changing it.
It retains the raw parsed value until truthiness/shape checks. The installed
view distinguishes a missing factor from decoded null and malformed JSON, while
truthy Infinity remains a successful view with a serialized null. Verification distinguishes
truthy Infinity (a view serializes it as null; verification throws and restores
an attempt) from literal null, invalid JSON, false, zero and an empty string.
Actual code consumption serializes nonfinite array numbers as null, rounds
integers at JavaScript double precision, and uses the existing exact ISO-Z date
reviver grammar. Calendar rollover, 24:00, fractional truncation and revival
past year 9999 are supported. Expanded-year input is an ordinary string under
Source's four-digit grammar, including dates outside Chrono; the live proof
retains it and accepts it as a string code. This matches that Source mode rather
than excluding it. Recognized Date values cannot authenticate as string codes.
Existing authenticated legacy readers and exact factor-ID/ciphertext CAS remain
unchanged.

All factor signed-cookie readers now share the local Better Call reader.
It separately trims the first matching key, retains first duplicate precedence
even for an invalid or empty value, trims/unwraps the value, and either decodes
the whole URI component or retains the whole original value. Nonempty payload,
44-character padded Base64 and constant-time authenticated bytes are required;
unused Base64 bits retain their actual accepted meaning. URI, Unicode, unused
bits, malformed URI UTF-8, quoted values and whitespace before '=' run through
actual pending, preference and disable handlers. Later invalid duplicates prove
first-cookie precedence. Malformed signatures fail before pending consumption,
malformed preference proofs create normal persistent sessions, and malformed
disable proofs preserve the trust row without emitting its deletion cookie.
Valid aliases issue temporary sessions, retire pending/preference cookies and
delete the actual trust row at disable. Foreign state stays unchanged. Global
cookie/crypto helpers are not modified.

Combined storage/error cases cover a truthy corrupted installed value followed
by session cancellation, an explicit Forbidden and an ordinary same-message
throw. After successful duplicate consumption, the actual session callback
error retains its transport, emits no cookies, and leaves no newly created
session or trust proof. Cipher callbacks independently cover decode and encode
errors, including ordinary Internal, explicit public Forbidden and an explicit
public API 500 with the same message. Only Internal is wrapped in the existing
CallbackFailure variant (empty 500); explicit public errors retain their body.
Decode failures restore the physical attempt row. Encoding exceptions consume
that row entirely, retain the challenge, and deny a retry; a fresh sign-in then
completes the unchanged proof and retires its new challenge. Original factor
identity, secret, user and session ownership survive the failed stages.

Fifteen remaining SDK cases have passing Source/SQLx and Source/SeaORM receipts.
SQLx runs contain 12 cases/716 assertions, the new whitespace case/46 assertions,
and two explicit public-500 cases/114 assertions. SeaORM first passed eight
cases/466 assertions; the seven changed cases passed with 448 assertions, and
the two explicit-500 cases passed with 114 assertions. The final affected
absent-factor/heterogeneous view case passes with 110 assertions on each
adapter. Passing unrelated
factor/cookie inventory was reused from #417 rather than replayed. Six focused
native view/preference/cipher tests pass, API Clippy with warnings denied passes,
fixture-binary Clippy with warnings denied passes, and client types, the
affected reference fixture types, scoped lint and format/diff checks pass. Actions are disabled; no CI, full-suite, devenv-test or
coverage claim is made.

Meaningful native before failures are preserved for heterogeneous view,
malformed-URI pending admission, both ordinary cipher phases and whitespace
before '='. The first cipher diagnostic had an incorrect encode-attempt
expectation and is retained separately; the corrected before log demonstrates
both intended ordinary-error body failures against successful Source cases.
Complete raw paired observations, current/foreign state and exact transports
remain at `/home/cschmatzler/.local/share/better-auth-evidence/close202`;
#417 receipts remain at its original permanent path. Private frozen Bun
installs were used, and installed factor modules match the authentic registry-
verified published tarball bytes. No dependency mutation was performed.

Independent coordinator review of checkpoint
`5738780919ce3cf72a02c794f2ea2fe60147e1de` found the key-trimming discrepancy.
The requested local repair and table extension are included. Independent
coordinator review of final production head
`8dcd98850d0c89b7f907736ff1d684b3254f8269` found no blocking findings.
This is independent coordinator review, not outside-party certification.
Rebasing onto `55243238` preserves both production commits exactly in
`git range-diff`; unrelated incoming work was inspected without adapter replay.
Subsequent explicit public-500 additions and the absent-factor view assertion
change only the affected regression and application fixtures. The worker's
separate final production/security
review confirms the Source grammar, error stages, exact-row CAS, authenticated
proof ownership and credential/session isolation. No residual acceptance item
from #202 is excluded or claimed closed without its corresponding proof.
