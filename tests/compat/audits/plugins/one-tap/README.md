# Google One Tap against Better Auth 1.7.6

## Contract and implementation

Pinned `plugins/one-tap/index.mjs` directly uses the core Google verifier, then
`oauth2/link-account.mjs` for identity/account creation and session issuance.
The Rust `OneTapPlugin` exposes POST `/one-tap/callback` and public immutable
`OneTapConfig`/`OneTapClientId`. Optional `OAuthJwksSource` is an application
transport/cache API: signature and claim validation remain in the plugin. The
default transport fetches Google's exact `/oauth2/v3/certs` URL on each valid
RS256 attempt, matching the pinned helper's timing and lack of built-in caching.

The verifier checks actual RS256 signatures, original protected-header and
payload JSON, Google issuer, configured audience, required issued-at age,
optional expiry/not-before, and configured hosted domain. A truthy key ID
filters keys before importing every selected key; falsy IDs select all keys.
Unsupported algorithms fail before fetch, while valid algorithms with invalid
key IDs or critical headers fetch first. Safe `JsValue` parsing preserves raw
JavaScript Number behavior and literal serde-private keys. The installed JOSE
verifier accepts positive-infinite expiry and negative-infinite not-before in
raw signed JSON; this differs from its finite-date signing setters and is
verified through actual pinned requests.

`OAuthConfig` is published once through immutable `ContextExtensions`.
Registered Google configuration adds primary/additional client IDs, a typed
hosted-domain option and required email verification. Authorization still uses
the primary client ID. One Tap overrides configured audiences when its own
client-ID setting is truthy, works with only a plugin client ID, and directly
verifies Google tokens even when the provider's application verifier rejects.

One Tap reuses the OAuth processor and actual account/user/session stores.
Fresh identity/account creation uses the previously frozen atomic prerequisite;
existing account scopes use the separately frozen preservation prerequisite.
The shared link-profile prerequisite applies its independent configured policy
without replacing local email or verification identity. Normalized processing
policy makes One Tap preserve profile fields on repeat sign-in, store its ID
token as pinned plaintext even under OAuth token encryption configuration, and
retain the original user snapshot during an email-verification upgrade. The
persisted verification update precedes the response snapshot and required-email
check, so the upgrade attempt can remain forbidden and its next attempt succeed.
Existing normal OAuth encryption and refreshed-user behavior retain their prior
policy; this audit does not claim those existing paths universally match source.

Verification delivery follows committed identity/account creation and precedes
session creation, reusing the configured delivery callback. Required-email
failure leaves its identity/account persisted and issues no session. Explicit
signup mail suppression and repeat signin delivery follow pinned options.
The callback's validated redirect target is forwarded by the official browser
client, while verification delivery uses `/` because One Tap does not forward
that target into the OAuth processor. Session cookies respect a verified signed
`dont_remember` preference. Account cookies use the existing shared encoder.

## Evidence and test ownership

The local provider fixture contains independent public-test RSA keys. Both
servers physically fetch the same public JWKS over local HTTP. The TS transport
intercepts only Google's fixed JWKS URL and executes the unchanged pinned helper.
The Rust fixture uses the production transport trait. Each test invokes the
official `oneTapClient` action; its minimal GIS shim supplies a real signed
credential and leaves HTTP authentication, validation, storage, cookies and
client callbacks active. Persisted fixture state reads actual users/accounts/
sessions, with full ID tokens. The keys and expected payloads are independent
of the Rust verifier. Wrong-signature and unsupported-token controls cannot
succeed through an always-success verifier; successful persisted-owner flows
cannot pass through an always-reject verifier.

Fourteen SDK scenarios cover lifecycle/foreign cookies, disabled signup,
JavaScript payload numbers/private keys, protected-header lookup order,
cryptographic and claim rejection, callback/media/schema rejection before fetch,
audience/domain configuration, required verification/delivery/suppression,
implicit linking/profile sync, token-storage/account-cookie configuration,
signed browser-session preference, verification snapshots, and admin/TOTP
interactions. They check owner identity, actual account key, exact stored ID
token, scopes, issued session token, unchanged rejected identity rows and JWKS
fetch counts. These are the primary boundary tests; no duplicate native mirror
is added. The distinct earlier native failed-account-insert test covers rollback
and retry at the actual SQLite transaction boundary.

Before evidence:

- `/tmp/one-tap-link-policy-before.log`: actual TS success/Rust failure because
  configured implicit-link profile synchronization was missing.
- `/tmp/one-tap-config-before.log`: actual encrypted configuration stores the
  original ID token in TS while Rust previously encrypted it.
- `/tmp/one-tap-cookie-before.log`: actual browser-session preference succeeds
  in TS while Rust previously emitted a 604800-second session cookie.
- `/tmp/one-tap-snapshot-before.log`: TS returns the original unverified user
  snapshot while Rust previously returned the freshly updated verified row.

`/tmp/one-tap-sdk-final.log` records all 14 passing scenarios / 664 assertions
before the coordinator required restoring complete persisted edge-case tokens;
its temporary digest observation has been removed. With complete raw tokens,
`/tmp/one-tap-oracle-final.log` (TS versus itself) and
`/tmp/one-tap-sdk-freeze.log` (TS versus Rust) expose the same existing comparator
failure at `observation.persisted.accounts.2.idToken.header.kid`: a valid empty
protected-header key ID is rejected as an empty identity. Thirteen scenarios
pass and every direct assertion in the protected-header scenario passes before
that comparison. Complete token fields remain in the frozen tests. Coordinator
owns the narrow comparator regression/repair, final differential rerun, inventory
and canonical gate; this feature introduces no comparator exemption.

`/tmp/one-tap-oauth-native-freeze.log`: 18 existing OAuth native integration
siblings pass. `/tmp/one-tap-clippy-final.log`: production API Clippy passes.
`/tmp/one-tap-typecheck-preserved.log`: SDK TypeScript passes with complete token
observations. `/tmp/one-tap-build-reviewed.log`: final locked fixture build passes.
`/tmp/one-tap-clippy-reviewed.log`: post-source-review API Clippy passes.
`/tmp/one-tap-oauth-sdk-siblings.log`: all 15 existing OAuth SDK siblings
pass. The branch-local numeric prerequisite required restoring the existing
JWT fixture's missing `Map` import; this feature includes that compile-only
import repair. The fixture lock adds only the already resolved `reqwest`
dependency to the compatibility-server package.

## Boundaries and outstanding findings

Live Google/GIS network behavior and browser FedCM UI are outside this local
provider proof; the actual official client callback action and real token
verification are exercised. Generic OAuth provider expansion is not part of
this implementation. Existing normal-OAuth default Google ID-token verification
still requires its application verifier; One Tap uses its own direct verifier.
Existing orphan-account error/order, normal-OAuth ID-token encryption and
refreshed-user/override response policy differences were identified separately
and are not described as universal shared-helper parity. Custom store failure
behavior beyond the established transaction contract remains adapter-specific.
The already investigated OAuth proxy family remains preserved without beginning
new production work while the selected implementation priorities are completed.
