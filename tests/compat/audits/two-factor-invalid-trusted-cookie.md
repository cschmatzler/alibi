# Invalid trusted-device cookie branches

This capability starts at `5a14ea0e` on the selected reviewed timestamp stack.
Better Auth and the official client remain pinned to 1.7.6. Production changes
belong only to `plugins/two_factor/mod.rs::inspect_trusted_device` and its private
outer-proof decoder. Shared cookie parsing, other cookie owners, storage/schema,
error types, dependency versions, inventory and comparator rules are unchanged.

Published `plugins/two-factor/index.mjs` obtains an outer signed cookie and tests
its truthiness before entering the trust-proof branch. Invalid, absent and empty
outer values do not emit a trust deletion cookie. A nonempty authenticated value
is destructured into only its first two `!` components; extra components are
ignored. Empty token/identifier values skip HMAC and verification lookup. Invalid
inner signatures and wrong login owners skip lookup. These nonempty invalid
proofs expire the cookie with its actual attributes and Max-Age0, no Expires.

Only an authentic inner user-bound signature reaches `findVerificationValue`.
The existing helper reads the original verification snapshot before configured
global expired cleanup. Missing rows, changed stored owner and expired rows deny
trust and start a new factor challenge. Cleanup-disabled retains expired rows;
it does not accept expired trust. A valid row is retired and a new authentic
cookie/identifier is issued for the actual credential user. The repair preserves
these lookup/write/error stages rather than bypassing them.

`better-call/dist/context.mjs` requires a nonempty outer payload, a44-character
signature and final `=`. Its actual atob accepts unused trailing Base64 bits.
The prior shared Rust decoder rejects those representations even when they yield
exactly the same32 HMAC bytes. A private factor decoder uses the existing URI and
HMAC implementations plus GeneralPurpose's allow-trailing-bits setting, requiring
the actual source shape before constant-time MAC verification. No weaker HMAC or
new public cookie/crypto choice is introduced.

## Primary owner and authorization/state evidence

The existing `tests/two-factor/trust-ttl.test.ts` owner uses three bounded
lifecycles for each of the real default-TTL skip-enrollment and explicitly
configured TTL/cleanup-disabled profiles. The prior six lifetime cases remain.
Each lifecycle uses real public signup, enable, sign-out, credential sign-in,
actual delivery and OTP verification to obtain its original signed trust cookie
and persisted proof. Independent Node HMAC validates the actual issued inner
signature and changes controlled input syntax; no fixture emits a successful
production outcome or provides the verifier's expected result.

The matrix observes missing outer cookie, bad outer HMAC, absent signature,
signed empty payload, bad inner signature, missing delimiter, empty token and a
correctly signed empty identifier. A real unrelated expired verification makes
an accidental lookup observable: these syntax/HMAC branches must leave it
untouched. The correct-inner empty-identifier control failed before its guard
because Rust performed cleanup where the source skips lookup.

Foreign credential login with the original proof cannot gain the owner's session
or retire that row. Private application fixture mutation changes only an actual
verification value, by bound identifier and fixed columns, to the real foreign
user; the original owner-bound signature then cannot trust that changed row.
Actual store reads prove the changed value and its rejection before restoration.
A correctly signed missing identifier reaches cleanup; a second genuinely issued
proof is forced expired and rejected. Default cleanup removes expired rows;
configured disableCleanup preserves them. These controls retain original and
foreign user/account/session snapshots and owner-bound factor challenges.

OTP completion consumes the real challenge and code, creates a real owner session
and re-arms its source zero-attempt row; the tests intentionally preserve that
observed policy instead of assuming the attempt record disappears. A valid
original proof with extra components must succeed, retire its actual row and
issue a different identifier. An unused-Base64-bit alias of that actual new outer
signature must also succeed and rotate; independent decoded-byte equality
establishes what the input varies. Replaying the retired alias must require a new
factor and preserve the two genuine sibling sessions and current trust row.
Foreign session state and earlier foreign challenges remain unchanged.

Each denied login requires actual owned challenge and attempts rows, matching
expiry, no OTP delivery row and unchanged persisted sessions. Deletion assertions
check actual empty value, Max-Age0, root path, HttpOnly, Lax, no Secure/domain and
no Expires. Original issuance and rotation retain actual configured lifetimes.
Complete official-client transports, cookie observations and all returned fields
remain in the existing strict comparison. Row projections wrap only real IDs and
owner values for the existing identity bijection after local ownership checks.
No production seam, duplicated helper unit test or comparator exception is added.

## Meaningful before evidence

* `/tmp/two-factor-invalid-trust-oracle.log`: actual pinned HTTP matrix, including
  default versus configured cleanup behavior and ignored extra components.
* `/tmp/two-factor-invalid-trust-self-control-final.log`: both new source-to-source
  owners pass before Rust production edits. An earlier control incorrectly
  assumed success removes the attempts row; that assertion was corrected to
  the actual source re-arming policy and is excluded as a setup error.
* `/tmp/two-factor-invalid-trust-sdk-outer-before.log`: six prior owners pass and
  both new owners fail on Rust's extra trust deletion header for invalid outer MAC.
* `/tmp/two-factor-invalid-trust-sdk-components-explicit-before.log`: after only
  the outer truthiness correction, the default case fails actual expired-row
  cleanup for an empty identifier, and the configured control reaches the real
  extra-component proof and fails with unexpected twoFactorRedirect.
* `/tmp/two-factor-invalid-trust-outer-syntax-oracle.log`: actual source accepts
  the padded same-byte signature alias and retires the real original proof.
* `/tmp/two-factor-invalid-trust-sdk-base64-before.log`: after component repair,
  six existing owners pass and both new owners fail on unexpected redirect for
  that actual issued-proof alias, before the local decoder correction.

## Bounds and focused checks

This closes the measured HTTP trusted-proof branches for default TTL and the
explicit configured TTL/cleanup policy. Duplicate installed identifiers,
adapter-hook exceptions/order, invalid stored dates, extreme configurations,
malformed URI/Unicode/alphabet exception wires and all other Base64 aliases are
not claimed. Other cookie owners retain their existing shared verifier; pending,
disable, session and unrelated plugin cookie alias parity remain separate.
No global parser change or broad error suppression is hidden in this repair.

The external autoreview tool named by test-audit is unavailable. Coordinator owns
independent review, full canonical gates, inventory and publication. Only focused
owner/family checks are run here; final results are appended after completion.

The original combined-owner freeze passed 63 two-factor SDK scenarios / 4,452 assertions
(`/tmp/two-factor-invalid-trust-family-with-alias-final.log`), including both new
owners in about3.2 seconds each with the unchanged default scenario timeout.
All18 existing native factor tests pass (`/tmp/two-factor-invalid-trust-native-final.log`).
Client and changed reference fixture TypeScript pass
(`/tmp/two-factor-invalid-trust-typecheck-final.log`,
`/tmp/two-factor-invalid-trust-reference-typecheck-final.log`). Workspace library
strict Clippy passes (`/tmp/two-factor-invalid-trust-clippy-final.log`); actual
fixture strict Clippy also passes (`/tmp/two-factor-invalid-trust-fixture-clippy-final.log`).
Workspace/excluded fixture formatting and `git diff --check` pass. Production
changes total38 diff lines; fixture/test support stays private to the applications.


## Bounded evidence follow-up

The integrated canonical run `/tmp/next-selected-hooks-schema-trust-canonical.log`
retains the genuine original failure: 435/436 scenarios pass, while the default
combined owner's final replay challenge `createdAt`, `updatedAt`, and `expiresAt`
exceed the existing clock comparison. Its source and Rust timestamps are
02:10:39.171 and 02:10:41.824. The configured combined owner passes. This is
an evidence-lifetime problem, not a production cookie change.

`support/scenario.ts` records one clock immediately after health/reset for the
whole scenario. `support/compare.ts` subtracts that clock from every stored date
and requires the resulting offsets to remain within 1,500 milliseconds. A late
replay after signup, both enrollments, seven syntax logins, authenticated lookup
mutations, a second OTP completion, expiry, and two successful rotations compares
accumulated credential-work duration. No clock, date projection, tolerance,
comparison rule, timeout, transport or production owner changes in this follow-up.

The single setup implementation now serves three fresh lifecycles per profile:

* Syntax retains all seven original outer/inner cases, exact deletion attributes,
  original issued row and both users' state, and unrelated expired-row preservation.
* Authenticated lookup retains the foreign credential, changed stored owner,
  authenticated missing record and genuinely issued expired proof. It preserves
  both cleanup policies, second OTP completion/attempt timestamps and the earlier
  real foreign challenge.
* Rotation retains actual extra-component acceptance, retired-row/new-cookie
  state, actual HMAC alias acceptance, retired alias replay, two genuine sibling
  sessions, current proof and foreign isolation. Its preceding owner challenge is
  created directly with a genuine invalid-inner request rather than inherited
  from the lookup lifecycle's expired-proof request; both earlier real owner and
  foreign challenges must remain unchanged. The expiry rejection remains fully
  checked by the lookup owner.

Every lifecycle performs real signup, enrollment, pending login, OTP delivery,
verification, trust issuance and sign-out. The same local assertions, complete
traced official-client responses/cookies and lossless stored-row projections
remain. The small duplicated foreign denial in lookup and rotation establishes
independent real challenge state for their distinct cleanup and retention risks;
there is no alternate fixture auth result or production seam. Inventory naming is
left to the coordinator, who will deliberately replace both combined names with
all six new owners.

Focused proof after this split:

* `/tmp/trust-evidence-bounds-source-control.log`: source-to-source 12/2,178 pass;
  new lifecycles take 1.0–1.4 seconds each.
* `/tmp/trust-evidence-bounds-family-final.log`: all 67 two-factor scenarios /
  4,908 assertions pass on the first current source-to-Rust run. New default
  syntax/lookup/rotation take 2.17/1.74/1.72 seconds; configured counterparts
  take 2.29/1.79/1.81 seconds, versus the canonical combined 3.86/3.70 seconds.
* `/tmp/trust-evidence-bounds-build.log`: current-parent locked fixture build
  passes in the isolated owner target; no production changes are included.
* `/tmp/trust-evidence-bounds-typecheck-final.log`: client TypeScript passes;
  `git diff --check` passes. Only indentation changed after the focused run.

The source baseline failure logs and all previously recorded security/crypto
bounds above remain valid and retained. Full canonical gates and required-owner
inventory edits remain coordinator-owned.
