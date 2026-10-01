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
