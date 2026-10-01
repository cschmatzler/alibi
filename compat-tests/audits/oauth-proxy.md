# OAuth proxy: database-state completion across two origins

Reference: published Better Auth 1.7.6 `dist/plugins/oauth-proxy/index.mjs`,
`dist/plugins/oauth-proxy/utils.mjs`, `dist/state.mjs`, `dist/api/state/oauth.mjs`,
`dist/oauth2/link-account.mjs`, `dist/crypto/index.mjs`, and
`@better-auth/core/dist/social-providers/gitlab.mjs`.

The public immutable `OAuthProxyConfig` configures current/production origins,
an optional dedicated secret, and a floating-point maximum payload age (default
60 seconds). `OAuthProxyPlugin` supports the provider completion route and the
legacy completion route with database OAuth state. Cookie-state configuration
fails explicitly at initialization. This is a bounded implementation, not a
claim that every Source proxy configuration is supported.

The preview dispatch retains an application-only request extension. The ordinary
OAuth handler still checks authorization, requested redirect targets and the
provider before storing genuine state. Its effective production redirect URI
and preview completion URL apply only to that dispatch. No global configuration
changes. The actual issued state is encrypted inside a second authenticated
proxy package, using the existing XChaCha20-Poly1305 codec. A production callback
uses the real provider token and user-info requests and returns the complete
encrypted profile to preview without creating production users/accounts/sessions.
Provider PKCE policy applies at code exchange as it does on ordinary OAuth.

Preview completion validates the target origin, authenticated payload shape,
provider relationship and age before accessing state. It consumes the original
preview row, then checks its expiry and restores only authenticated server
context from that original state. It reuses the existing provider user/account
processing and linking helpers. The saved link owner determines account ownership;
a caller's additionalData.serverContext cannot nominate another owner. Default
profile-override/email-verification policies follow the Source proxy helper,
which differs from configured ordinary provider processing.

## Independent evidence

The fixture uses two real authentication instances with independent migrated
SQLite databases, exposed as localhost and 127.0.0.1 at the same server port.
The provider's real HTTP authorize/token/user-info endpoints issue one-use codes
and verify SHA-256 of the actual 128-character PKCE verifier against the original
challenge. No provider receipt, account or expected callback is synthesized by
the scenario. Reset clears the actual stores, grants and receipts after completed
public requests.

`tests/oauth/proxy.test.ts` is the primary public official-client owner:

- successful production exchange and preview signup, current-session identity,
  persisted account/session ownership, foreign rows and consumed-state/code replay;
- foreign callback origin, provider mismatch, authentic expired/future payloads,
  unknown state, malformed payload and invalid ciphertext, then a successful
  legacy completion using the original still-live state;
- actual authenticated linking without session replacement, foreign-session
  preservation, consumed-state replay, mismatched email and an account already
  linked to another user.

All provider forms, user profiles, full encrypted profile bytes and decrypted
payload fields remain compared. The published Source symmetricDecrypt verifies
both runtimes' actual profile/package/inner-state bytes. The retained inner state
uses reversible `{token: actualVerifier}` and `{state: actualOauthState}` wrappers
for existing token/state namespaces. Numeric expiry is represented as an ISO Date;
its exact milliseconds and reconstructed original JSON bytes are asserted locally.
Every other state field and duplicate relationship remains present. Original raw
headers, ciphertext and physical SQL facts remain in independent probe logs.
There is no comparator ignore list or dropped transport field.

Final Source-to-Source: `/tmp/oauth-proxy-sdk-source-complete-state-final.log`,
3 scenarios / 386 assertions. Final Source-to-Native:
`/tmp/oauth-proxy-sdk-complete-state-final.log`, 3 / 386.
Before the authenticated comparison prerequisite, two actual fresh Source flows
failed only on ciphertext/profile timestamp (`/tmp/oauth-proxy-profile-source-self-before.log`);
the actual three-owner Source self-control likewise failed only profile fields
(`/tmp/oauth-proxy-sdk-source-before-atom.log`). Adding full state retention first
exposed literal oauthState comparison in the Source self-control; the reversible
state wrapper repairs observation representation without changing the comparator.
The first post-atom Source-to-Native run passed all 336 local assertions and failed
only missing JSON Content-Type on Rust proxy redirects
(`/tmp/oauth-proxy-sdk-first-atom.log`); the route-local redirect header repair
produces the final green result.

`tests/oauth_proxy_lifecycle_tests.rs` owns the distinct actual native storage
boundary: complete physical rows, exact internal identifier and JSON state,
production nonmutation, consumption/deletion/replay, foreign principal isolation
and expiry after genuine row modification. `/tmp/oauth-proxy-native-final.log`:
2 passed. The ordinary pre-feature native registration mode fails both cases for
the intended production-versus-preview redirect difference
(`/tmp/oauth-proxy-native-meaningful-before.log`). The separate actual pinned
runtime probe records complete Source SQL rows, state and cookies through the
same lifecycle (`/tmp/oauth-proxy-source-lifecycle-final.log`). The Source
verification identifier is the issued state; Native retains its existing
`oauth:` prefix. The public SDK owner does not pretend these internal codecs are
literal storage equivalents.

Focused strict workspace-library Clippy, strict fixture Clippy, client TypeScript
and the new Source fixture's TypeScript check are recorded in
`/tmp/oauth-proxy-{clippy,fixture-clippy,typecheck,reference-focused-typecheck}-final.log`.
The whole Source server TypeScript invocation encounters inherited generic fixture
errors outside this slice; it is not reported as a passing check. OAuth native
siblings are recorded in `/tmp/oauth-proxy-native-oauth-siblings-final.log`.
The coordinator owns full gates, inventories, shared dependencies and publication.

## Remaining issue candidates

- Implement cookie-state proxy restoration, including Source nonce checks, genuine
  cookie expiry/replay and old pending-state consumption. Existing database-state
  cookie signing and verification identifier codecs remain different.
- Support secret rotation / managed `$ba$<version>$...` encrypted envelopes. The
  measured explicit secret and default ordinary single-string secret use bare
  hexadecimal ciphertext; no rotating-key claim.
- Match Source environment/currentURL/productionURL and dynamic base URL resolution,
  custom provider callback paths, POST callback query/body merging, and configured
  errorURL fallback. Current proof uses explicit immutable origins and GET exchange.
- Preserve Source's absent/false distinction for unset provider signup policies,
  provider profile rejection versus thrown errors, custom account-key/profile
  helpers and loose custom passthrough fields. Normal actual GitLab payloads are
  covered; alternate accountId/userInfo.id relationships remain unproved.
- Compose proxy issuance with signed browser preferences, cookie caches and their
  failure ordering. The existing shared issuer behavior is reused; these cross-plugin
  combinations require separate real lifecycle evidence.
- Exercise fractional/nonfinite maximum-age settings, concurrent completion and
  pending state across secret/config changes. Sequential replay is covered; no
  universal concurrent single-winner claim.

No OAuth authorization-server, MCP, CIMD, enterprise SSO/SCIM, Stripe, i18n,
Expo or Electron integration is included.

## Independent review completion: restoration and application failures

The independent review found two genuine stages missing from the initial default
flow slice. Source `restoreOAuthProxyState` catches lookup, decode and deletion
exceptions and redirects `state_mismatch`; Native now applies that catch only to
proxy restoration. The real state-cookie cleanup is queued before deletion,
matching `parseGenericState`. A real SQLite delete-veto trigger proves rejected
consumption retains every principal and verification row; removing the veto
allows that same authentic profile/state to progress.

The shared private `OAuthSignInError::SessionAuth` retains the actual session
issuer failure. Existing ordinary OAuth projections still use the same message
and redirect rules, and the exhaustive OneTap arm keeps its existing 401/message
projection. Only proxy completion distinguishes Source's coded APIError redirect,
ordinary internal exception's empty 500, and typed HookControl cancellation's
`unable_to_create_session` result. Ordinary exceptions discard accumulated
endpoint headers; coded/cancellation/deletion redirects preserve the real state
cleanup cookie. No generic string matching or shared public error mapper changed.

The fourth official-client owner configures an actual application session-create
hook, records its real stored userId, exercises ordinary Error, coded API500 and
HookControl::Cancel, and succeeds after resetting that application policy. Original
state is consumed on session failure; already committed user/account rows survive,
account refresh expiry/update writes are explicitly asserted against the new real
provider payload, no new session/cookie is issued, and foreign rows/sessions remain
unchanged. Every physical observation and authenticated payload remains returned.
The original three owners are retained. State annotations use actual HTTP route
IDs rather than implementation handler identifiers.

Actual pre-correction logs are `/tmp/oauth-proxy-review-delete-veto-before.log`
(500 instead of 302 on the real SQL veto) and
`/tmp/oauth-proxy-review-session-error-before.log` (302 exposing an internal error
instead of the Source empty 500). A first post-correction full run passed every
676 local assertion and complete client observation but exposed the queued-cookie
failure difference at the ordinary-exception trace; the route-local discard fixes
that remaining stage. Source-only fixture setup corrections (initial missing
private control route, selecting an older provider receipt, assuming refreshed
account dates stayed unchanged, and misnaming the authenticated atom container)
are not treated as production before evidence.

Final strengthened proofs are `/tmp/oauth-proxy-review-source-family-final.log`
and `/tmp/oauth-proxy-review-sdk-family-final.log` (four owners), with scoped
strict/focused checks in `/tmp/oauth-proxy-review-{clippy,fixture-clippy,typecheck,reference-typecheck,native}-final.log`.
Broader user/account-store error classification, provider profile rejection and
custom adapter/application hook combinations remain explicit follow-up work;
this review repair closes the measured state-restoration/session-issuer stages.

The completed-response application observer now independently proves the hook
boundary too. It records the actual callbackURL from Source middleware context
and the native request; it does not generate expected receipts. The ordinary
session exception produces no after-request receipt, while state-deletion,
coded APIError, cancellation, replay and successful retry do. The wire-only
correction first failed this real owner with an extra native receipt
(`/tmp/oauth-proxy-review-afterhooks-before.log`). A private typed request marker,
created only by that internal proxy error and consumed by the production dispatch
bridge, suppresses completed-response hooks for the exact branch. Public dispatch
already replaces request extensions, so callers cannot inject/reuse this private
marker. Ordinary 500 responses elsewhere are not remapped. Central cache
composition must retain its own marker and combine suppression at the adjacent
dispatch boundary. Source after-hook paths are route patterns whereas native
request paths are concrete; the observer purposefully records the common actual
query contract, not a fabricated path alias. Final four-owner count is 684.

Final route evidence additionally exercises a valid authentic profile with a
foreign origin on the legacy route. Both completion routes now independently
record genuine 403 rejection/authorization and successful state transitions;
302 responses are not relabeled as rejections. The final Source self-control
`/tmp/oauth-proxy-review-source-family-final.log` and recorded differential
`/tmp/oauth-proxy-review-recorded-sdk-final.log` pass four owners / 694 assertions.
The four actual evidence JSON files are under this checkout's
`compat-tests/client-tests/artifacts/evidence/`; inventory remains coordinator-owned.
The normal account OAuth public native consumers also pass 18 tests in
`/tmp/oauth-proxy-review-account-native-final.log`, protecting the unchanged
nonproxy projections. An attempted OneTap native lib selector finds zero tests;
that setup invocation is not counted as validation.


## Integrated dispatch and required route evidence

The coordinator integrated the immutable feature and review correction with the
stateful compact-cache prerequisite. Dispatch consumes both private suppression
markers independently, retaining cache ordinary-error header discard and proxy
ordinary-error hook suppression. Exact integration review is clear.

Fresh integrated actual fixtures pass 29 owners / 1,898 assertions across compact
cache, both anonymous families and proxy (`/tmp/wrapup-final-cache-proxy-integration.log`).
The inventory enables the real proxy plugin and changes only the two completion
routes' implemented flags. It adds 26 actually qualified requirements, preserves
all previous requirements and all 143 route identities, and uses genuine 403
origin controls for both completion routes. The final canonical gate is owned by
the coordinator; this focused result is not a complete-gate claim.

Remaining proxy configurations are tracked in [issue #227](https://github.com/cschmatzler/better-auth-rs/issues/227).
Shared lifecycle, state codecs and rotation are #181, #189 and #176; account
cookie variants are #230. Default database-state completion is implemented.
