# One Tap audience and retained-account cookie configuration

This bounded follow-up repairs two configuration branches found during independent
review of the One Tap stack, after the separate encrypted account-cookie
prerequisite. Pinned `dist/plugins/one-tap/index.mjs:48-49` uses JavaScript truthiness
for the configured client ID and rejects an empty array, but a nonempty array
containing an empty string is valid configuration. A real RS256 credential with
`aud: ""` is accepted against `clientId: [""]`. The Rust guard previously treated
that array like a missing scalar client ID; it now preserves the public
`OneTapClientId::Multiple` distinction. Existing missing/empty-array, provider
fallback/additional-audience, wrong-audience and hosted-domain controls remain.

Pinned `dist/oauth2/link-account.mjs:208-224` constructs `freshTokens = {}` when
`updateAccountOnSignIn` is false, then merges the original linked account with
that empty object before writing an account cookie. The Rust shared processor
previously left the database unchanged but overlaid fresh token values into its
cookie. With `storeAccountCookie: true`, that cookie could expose a newly received
grant despite the configured retained-account policy. The shared processor now
projects the actual original account into the encrypted cookie for this branch;
default token updates and their cookie overlays retain their previous behavior.
This condition belongs to the shared source account-link processor, also used
by ordinary OAuth, and changes only the explicit false-update configuration.

## Primary evidence

`/tmp/one-tap-review-source-probe.mjs` and its `.log` invoke unchanged pinned
HTTP handlers with real local RSA signatures, physical Bun SQLite state and the
published crypto decoder. They prove array-member acceptance and two successive
combined retained-account/cookie sign-ins preserving the original ID token in
both storage and the whole decoded cookie.

The existing immutable-audience SDK table now includes a real `clientId: [""]`
profile on both servers and a signed empty audience. The existing token-storage
owner enables the two real options together, compares the complete decoded
cookie to the original owner/account/token/scopes, and proves it excludes the
fresh credential while the actual row remains unchanged. Its update-enabled
control stores and emits the fresh credential. No parallel test or production
fixture-control endpoint was added.

Before the audience repair, `/tmp/one-tap-review-config-sdk-before.log` fails the
success control with native `400` missing-client-ID. After independently repairing
the JWE protocol, `/tmp/one-tap-review-retention-before.log` fails specifically
because the decoded cookie contains the fresh ID token rather than the retained
one. The decoder no longer masks that configuration bug.

`/tmp/one-tap-review-config-final-sdk.log` and
`/tmp/one-tap-review-cookie-oracle-final.log` each pass all 15 One Tap scenarios /
746 assertions, including original real-RS256 rejection and identity lifecycle
owners. The 15 OAuth SDK siblings, 11 complete OpenAPI document scenarios / 494
assertions, 18 native OAuth siblings, real failed-account-insert transaction
owner, pinned JWE vector owner, SDK TypeScript, locked fixture build and strict
production API Clippy pass; detailed commands/logs and cookie boundaries are in
[the separate encrypted account-cookie audit](../../core/social/oauth-account-cookies.md).

## Boundaries

The typed One Tap array branch is supported directly. The existing convenience
`OAuthProvider::with_client_ids` collapses a sole empty array member into its
scalar primary client ID, so that separate provider representation still cannot
express every upstream array/scalar distinction. Cookie chunking, compression,
account-specific attributes/TTL, multi-secret rotation and arbitrary custom
account columns remain explicitly bounded in the prerequisite audit. This
follow-up does not claim universal normal-OAuth profile/adapter parity or expand
the selected scope into the excluded OAuth-provider plugin.
