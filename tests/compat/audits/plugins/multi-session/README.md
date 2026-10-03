# Multiple browser sessions

The source of truth is installed better-auth@1.7.6's
dist/plugins/multi-session/index.mjs and client.mjs. This extraction implements
list-device-sessions, set-active and revoke, and the completed-response hooks
that retain browser proofs, retire previous sessions for the same account and
revoke held proofs on sign-out. The public Rust configuration defaults to five
distinct browser accounts and supports a configured maximum.

## Identity and storage contract

Each selection/revocation needs the corresponding signed browser cookie. A
session token in a body alone confers no authority. Selection can switch to
another account represented in that browser without requiring the current
account to match it; revoke additionally requires a current session. Malformed
body validation precedes the revoke authentication check, matching the actual
pinned HTTP endpoint. List filters expired sessions, resolves persisted owners
and returns one session per owner. Current-session revocation selects the first
remaining valid stored session or clears the session cookies.

The new-session hook resolves cookie tokens from actual storage rather than
trusting response body fields. A repeated login retires the previous held
session for that owner. The maximum counts every named multiple-session cookie,
including invalid signatures. A login beyond that maximum still obtains an
active session, but does not obtain a selectable browser proof. If a later login
replaces that active cookie, sign-out cannot discover the untracked earlier
session; the actual TS runtime leaves it in storage. Tests assert this behavior.

Cookie maps preserve last-value duplicate semantics. The extracted prototype's
selection used a first-value helper; a raw duplicate-cookie native regression
demonstrated its incorrect successful selection and now passes with local
last-value lookup. Selection and revoke fallback inherit signed dont_remember
preferences, so a browser session does not become persistent during switching.
Sign-out normalizes cookie names as upstream does. These changes remain within
the plugin and do not alter the shared cookie helper.

## Evidence and test ownership

Three official-client dual-runtime scenarios use two explicit profiles (default
and maximum two). They assert persisted user/session ownership, authenticated
foreign-browser rejection, fallback, same-account rotation, over-limit behavior,
sign-out, expiration, invalid fields and schema/authentication ordering. Actual
Set-Cookie traces and the standards-aware jar compare lifetimes and attributes,
including switching after rememberMe:false. Existing private user-state and
expire-session controls inspect production storage and change only the clock.

The fixtures use matching application database hooks to generate tokens whose
SQL order differs from creation order. These configured tokens make ordering
deterministic without sorting outputs or rewriting ownership. All admission,
authentication, revocation and browser proof decisions remain in production.
No anonymous implementation or other old prototype ancestry is extracted.

Three native SQLite plugin tests additionally cover duplicate raw Cookie names,
signature tampering, signed proof values, empty browser lists and invalid-cookie
budget accounting, which the ordinary official-client cookie jar cannot emit.
Their assertions inspect actual rows and response cookies rather than source
shape or a mock transition.

Before extraction the TS flows succeeded and Rust returned 404 for the absent
configuration: /tmp/multiple-sessions-before.log. Prototype regressions are
/tmp/multiple-sessions-duplicate-before.log (last invalid duplicate must reject),
/tmp/multiple-sessions-prototype-before.log (real malformed-body wire rejection),
and /tmp/multiple-sessions-validation-order-before.log (400 must precede 401).

Final focused logs: /tmp/multiple-sessions-native-final.log,
/tmp/multiple-sessions-sdk-final.log, /tmp/multiple-sessions-typecheck-final.log,
/tmp/multiple-sessions-clippy-final.log, /tmp/multiple-sessions-fmt-final.log and
/tmp/multiple-sessions-fixture-fmt-final.log. The coordinator runs the canonical
full gate, integrates current master and updates capability inventories. This
slice changes no comparators, coverage settings, lockfiles, database schemas or
migrations. Secondary-storage and cookie-cache integrations are not established
by these SQLite/no-cache profiles.

## Signed-empty proof review repair

Independent coordinator review found that a valid signature over an empty
payload reached selection/revocation. Upstream rejects this falsy payload
before looking up or deleting a session and before clearing a browser proof.
The existing raw-cookie SQLite owner test now submits that exact proof to
both operations with a valid current session, checks `INVALID_SESSION_TOKEN`,
no cookie retirement, and both owners' persisted tokens. On the original
`9eb973b`, revoke returns 200 rather than 401
(`/tmp/multiple-sessions-signed-empty-before.log`). Selection additionally
cleared a cookie where upstream throws before doing so.

Only selection filters the signed empty value. The post-issuance same-user
cleanup loop also skips the empty token before lookup, matching its upstream
truthiness guard; list/fallback keep their separate string-valued
semantics. Logout truthiness was missed in this historical review and is repaired
by the issue-232 closure below. Three native owner tests and three SDK scenarios / 194 assertions
pass after repair (`/tmp/multiple-sessions-signed-empty-native-final.log`,
`/tmp/multiple-sessions-signed-empty-sdk-final.log`). Production Clippy and
formatting pass; no inventory or shared schema changes were made.

Independent coordinator review found the signed-empty selection-proof difference;
its real SQLite rejection regression failed before repair and now passes.
The reviewed integrated canonical gate passes: 262 SDK scenarios / 7,568
assertions, 37 harness tests / 210 assertions, two Chromium tests / 22 assertions
and 79.30% source lines (23,849 / 30,076).
Log: /tmp/multiple-sessions-selected-canonical.log. Each new route requires
successful configured/expiry flows and persisted-state evidence; selection and
revocation also require rejection and browser-proof authorization evidence.
The inventory enables this plugin independently of the matching baseline wire
configuration.

## Issue #232: raw numeric limits and configured token cookies

The installed pinned `better-auth@1.7.6` `dist/plugins/multi-session/index.mjs`
spreads options over `maximumSessions: 5`, then directly compares the number of
named device cookies (including invalid signatures), less same-user retirements,
plus the newly issued primary cookie against that value. It neither defaults
falsy numbers nor evicts the database session when proof admission fails.
All numeric probes here terminate after three real signups; no loops depend on
an upstream numeric limit. Zero, -1 and negative infinity admit no proof; 1.5
admits one; NaN and positive infinity admit all three. Native configuration uses
`f64` to represent this contract, replacing `usize` (callers must use float
literals). Existing integer/default capacity and invalid-signature evidence is
retained.

Pinned `dist/cookies/index.mjs` resolves token attributes in order: defaults,
configured default attributes, session lifetime, then token-specific overrides.
The multi-session hooks copy those resolved attributes for issuance and replace
only Max-Age with zero for retirement. The implementation now derives the name
and attributes from the configured logical session token. A configured default
Max-Age must not replace the session lifetime; a token-specific Max-Age must.
The prefixed and aliased profiles exercise actual signup, selection, foreign
proof rejection, revoke/fallback and logout with configured path, HttpOnly,
SameSite and Max-Age precedence.

The existing lifecycle scenario is the primary owner for these profiles; the
numeric table separately guards admission and non-eviction, retaining all three
accounts' full before/after state and exact list order. Its credible regression
is coercing NaN/negative/fractional limits to an integer/default or retiring an
unadmitted session. No production test seam was added.

Signed-cookie evidence recognizes the two explicit fixture token names in
addition to the original name. It still authenticates the original signed
bytes and binds proof suffixes, ownership and tombstones to observed issuance.
The existing real-Source factor-rotation harness runs its negative controls for
all three names, including corrupt credentials, foreign authority, missing
receipts, duplicate retirement and altered path/HttpOnly/expiry. Cookie names,
raw attribute order, complete cookie scopes and ordered session lists remain
compared. No pin, exclusions, coverage floor or exception policy changes.

Residual scope: #232 remains open for the wider combined plugin/storage matrix
and unsupported JWT/stateless modes owned by the session dependency workpieces
(#221 and #171–177). Existing compact/JWT/JWE cache composition scenarios cover
some interactions, but this PR does not claim the entire matrix. The #154 and
#213 workpieces are separate.

Review traced selection and revoke through the ordinary-session guard, signed
nonempty device-cookie verification and adapter mutations. Device authority
matches Source: a token string alone does not authorize a foreign browser;
a valid issued browser proof does. Configured aliases preserve this boundary.

The repeated-proof regression obtains an actual signup Set-Cookie, presents the
same signed bytes under two distinct device-cookie names, then signs in again
with a fractional capacity. Source retires both named proofs before admission;
Rust previously deleted during its lookup loop and retired only one. The new
owner fails with two expected retirements versus one on the pre-repair loop
(`/tmp/232-before-repeated-fix.log`). Cleanup now resolves all proofs before
performing deletes. The scenario retains raw responses through the unchanged
trace path, full physical before/after rows and actual replacement selection.
The alias/prefix lifecycle regressions also fail with the prior cookie producer
(`/tmp/232-before-cookie-fix.log`); the baseline keeps `f64` only so those
previously unrepresentable fixture options compile.

A read-only registry check found 605 pre-existing duplicate entries in the
fixture profile registry on the inherited main baseline. Each of this slice's
eight new profiles is registered once. The broad registry cleanup and canonical
suite are coordinator-owned; no whole-repository green-gate claim is made.

Targeted verification uses the orchestrator's selected-file runner for
`tests/plugins/multi-session/sessions.test.ts`,
`tests/core/session/cookie-cache.test.ts` and
`tests/core/session/jwt-jwe-cache.test.ts`, with `CARGO_BUILD_JOBS=2`, isolated
`CARGO_TARGET_DIR=/tmp/better-auth-232-target` and explicit SQLx/SeaORM backend
selection. SQLx after the repeated-proof repair passes 52 scenarios / 3,216
assertions (`/tmp/232-sqlx-final.log`). The prior SeaORM run passes 51 / 3,198
(`/tmp/232-seaorm.log`); both backends are rerun after rebasing for landing.
Actual-Source signed-header harness: 5 tests / 554 assertions
(`/tmp/232-final-harness.log`). TypeScript type checking and changed-path lint
pass. Strict production and SeaORM fixture Clippy passed before the final
cleanup-order repair and are rerun for the final tree. No full compatibility
runner, `scripts/compat.sh`, or `scripts/check.sh` was invoked by this workpiece.

Final landing proof after rebasing on `origin/main` (`aa0d1388`): **SQLx and
SeaORM each pass 52 scenarios / 3,216 assertions**, including the repeated-proof
repair (`/tmp/232-post-rebase.log`). Two native multi-session owner tests and
strict final production/SeaORM fixture Clippy pass (`/tmp/232-native-final.log`).
Formatting, TypeScript and changed-path lint pass; focused comparator, trace
and evidence-gate harnesses pass 38 tests / 379 assertions
(`/tmp/232-verification-final.log`). No remote CI checks or reviews were reported
on this PR at landing. Remaining cookie-attribute/profile combinations and the
wider dependency-backed composition/storage matrix remain under #232; this
bounded slice establishes only the configurations named above.


## Issue #232 closure

The historical residual-scope statements above are superseded by the [closure
reconciliation and retained raw proof](232-closure/README.md). PR #418 repairs
signed-empty logout retirement and the actual noDB OAuth-state default cleanup
mismatch, proves noDB selector/order/fallback/logout/cache replay, and reconciles
all three #232 acceptance items with #359 and existing supported composition
receipts. Broad dependency lifecycle matrices remain with #171-177. No new full
suite, coverage or remote CI result is claimed.
