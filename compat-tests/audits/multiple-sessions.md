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
truthiness guard; list/fallback/logout keep their separate string-valued
semantics. Three native owner tests and three SDK scenarios / 194 assertions
pass after repair (`/tmp/multiple-sessions-signed-empty-native-final.log`,
`/tmp/multiple-sessions-signed-empty-sdk-final.log`). Production Clippy and
formatting pass; no inventory or shared schema changes were made.
