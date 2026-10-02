# Last-login-method tracking (#136)

The public `LastLoginMethodPlugin` implements the pinned Better Auth 1.7.6
middleware-only plugin. Its default cookie is unsigned, lasts 30 days and is
readable by the browser. `LastLoginMethodConfig` provides a cookie name/lifetime,
optional database persistence, a synchronous application resolver and async cookie
consent. Resolver `None` uses the built-in selection; an empty string suppresses
tracking. Consent errors are caught and suppress only the tracking cookie.

The published `plugins/last-login-method/index.mjs` resolves email signup/signin,
OAuth callback parameters, SIWE, passkey authentication, magic-link verification
and email OTP. Username and anonymous signins have no default tracking method.
Actual public flows prove each selection, callback context and persisted row,
including the real software-authenticator passkey, delivered OTP/link, actual
OAuth state/provider response and EIP-191 signature. Anonymous signup upgrades
remove the old owned user/account/session rows; foreign identity state stays
unchanged. MultiSession composition retains signed device sessions with genuine
application-generated deterministic session tokens, not rewritten cookies.

Database mode contributes a user-create transform and a session-created callback.
The pinned adapter queues after-create callbacks until the actual transaction
commits (`db/with-hooks.mjs`, `@better-auth/core/dist/context/transaction.mjs`).
The public `SessionCreatedHook` therefore receives the finalized store after
commit, preserving registered user-update transforms. Rollbacks discard callbacks;
post-commit callback errors preserve committed sessions. Application user-update
errors are caught by tracking, while resolver exceptions propagate. Failed password
admission creates no session; a resolver exception after nontransactional session
insertion leaves that real row without issuing cookies. These distinctions are
observed, never replaced with universal unchanged-state assertions.

`LastLoginMethodContext` separates original HTTP request bytes from endpoint-phase
`body`, and exposes the admitted logical route, actual URI, params, query, probe
header and original trusted new-session snapshot. OAuth declares `/callback/:id`
while native routing uses `/callback/{provider}`. Shared `ResolvedEndpoint` and
additive `AuthRoute::with_context_path` retain that distinction. Endpoint schema
input and username-hook input use separate `ValidatedRequestBody` and
`TransformedRequestBody` typed extensions. Both carry `JsValue` directly: an actual
raw signup containing 1e400, negative zero and nested custom fields selects its
method from the real callback values while consent observes the original bytes.
Nonfinite callback observations use explicit number markers on both fixtures;
finite values and complete field sets remain literal. No comparator changed.

Passkey authentication now reads the user after real session creation, matching
the pinned package's order. MultiSession selection records its genuinely selected
user/session as the completed snapshot. These shared repairs were required by the
actual callback receipt failures. Ordinary application exceptions use the existing
`CallbackFailure` boundary: completed hooks stop and discard accumulated headers,
including issued cookies, while committed database writes remain. Explicit coded
API errors retain their existing transport behavior.

Configured owners cover fractional, zero, NaN and negative-infinity lifetimes,
strict SameSite, custom names and escaped method values. Positive infinity exceeds
BetterCall's 400-day bound: cookie serialization fails with an empty 500, no
Content-Type or authentication cookie, after real account/session persistence.
Advanced global/session attribute overrides are honored by tracking; wider shared
session-cookie configuration remains independently owned by #177. Database column
aliasing belongs to the application's schema mapping; the native existing nullable
last-login field remains the canonical storage API.

The primary SDK owner also proves non-input signup/update rejection, full foreign
and sibling ownership state, original signup snapshots, configured user-update
transforms and actual SQL update rejection. Complete random OTP/WebAuthn input is
checked byte-for-byte against its posted callback body before existing identity
envelopes relate those values across runtimes. Private fixtures only deliver real
secrets, collect actual callback receipts/read SQL, or install real SQL triggers.
They never invent authentication, successful writes or callback decisions.

The distinct native public owner proves ordinary and transactional callbacks,
finalized transforms, an actual SQLite trigger failure after session insertion,
and retained rows after a post-commit callback exception. A second native boundary
proves trusted server-only calls have no request-derived tracking side effects.

Source oracle and restored differential owner pass 15 scenarios / 1,056 assertions
(`/tmp/issue136-raw-source.log`, `/tmp/issue136-exact-after.log`). The negative proof
runs the exact final owner against the real fixture with only tracking registration
removed, representing the original missing feature. It fails all 15 scenarios / 562 assertions (/tmp/issue136-exact-before.log).
Restored proof is /tmp/issue136-restored-after.log. Existing capability requirements remain, with additive tracking
owners. Production/fixture strict Clippy, client TypeScript, formatting and public
native checks are recorded there. Root coordinates the canonical gate; focused
proof does not claim all independent repository SDK baselines are green. The
external `$autoreview` executable required by test-audit is unavailable here.

Latest main had five duplicated capability records after Apple integration. This
change consolidates them into 143 unique routes while retaining the full union of
every requirement, and adds 166 actual tracking requirements. No route or prior
evidence requirement is removed.
