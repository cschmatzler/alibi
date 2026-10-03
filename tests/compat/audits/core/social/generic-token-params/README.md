# Static generic OAuth token parameters — #188 / PR #400

The public `OAuthAuthorizationPolicy` now accepts trusted
`authorization_code_params` and `refresh_token_params` maps. Previously, generic
OAuth providers could configure authentication and grant headers but could not
forward static audience/resource/tenant form parameters through the real code
and refresh transports.

```rust,ignore
let policy = provider.authorization.get_or_insert_with(Default::default);
policy.authorization_code_params.insert("audience".into(), "https://api.example.invalid".into());
policy.refresh_token_params.insert("resource".into(), "configured-tenant".into());
```

These are application configuration, not request-body maps. Validate tenant and
scope entitlements before configuring them. Code additions fill fields absent
from the grant (so existing code, redirect URI and PKCE remain authoritative).
Refresh additions replace ordinary fields, but never `grant_type`,
`refresh_token`, `__proto__`, `constructor`, or `prototype`. Authentication runs
after the merge: post/public authentication replaces `client_id`; post replaces
`client_secret`; Basic preserves an extra body client ID but rejects a body
secret. Public/assertion modes reject secrets. Complete manual assertions are
accepted only without explicit token authentication or configured secrets;
incomplete/conflicting assertions fail before an HTTP request. With additions
and no explicit authentication, credentials select post or public mode. Empty
map defaults preserve the previous factory transports.

Source is the freshly downloaded published npm `better-auth@1.7.6` and
`@better-auth/core@1.7.6`, specifically generic-oauth `index.mjs`/`types.d.mts`
and core `validate-authorization-code.mjs`, `refresh-access-token.mjs`, and
`token-endpoint-auth.mjs`. The source supports `private_key_jwt`; this PR does
not claim to add or reprove that existing transport. Private copies of the Bun
runtime were restored from both fresh archives before execution. The integrity
manifest compares every archive file with the installed runtime and records
private inode/link information; archive hashes are in `receipt.json`.

The single generic SDK owner runs 12 focused scenarios against actual
`SqlxStore` and `SeaOrmStore`, 12 passing comparisons per adapter. Six lifecycle
modes cover explicit post/basic/public, automatic post/public and manual
assertions. They inspect real HTTP bodies (including encoded special characters,
unique form keys, PKCE-to-challenge binding and credential precedence), complete
persisted users/accounts/sessions, signup, consumed-state replay, foreign
refresh denial, rotation, rejection of an attempted foreign-subject takeover,
successful authenticated linking, and logout. Four code conflict cases and two
refresh-only secret conflicts protect pre-outbound rejection and unchanged
persisted rows. No provider-factory inventory was replayed.

The primary post regression demonstrably fails against the original base
handler because the configured `resource` is absent; source completes the same
scenario. `before.log` records the intended failure, not a passing claim. Both
final raw-pair archives retain complete paired SDK transport/state observations
and separately captured original form strings. Receipt comparisons decode form
pairs after asserting wire encoding; per-server URLs and random verifier bytes
remain in the separately retained raw records. The shared comparator and its
exclusions were unchanged.

Production check, scoped strict Clippy, client typecheck, the new source fixture
only typecheck, targeted TypeScript lint/format and diff whitespace checks pass.
Review was self-review using test-audit, authorization and data-exfiltration
skills. No independent reviewer was delegated. GitHub Actions is disabled;
there are no CI results. No full compatibility sweep, development-environment
gate, or coverage run was performed under the latest bounded instructions.

The tested base and production head are in `receipt.json`. Main advanced with
#398; the rebase preserved both fixture module registrations. Retained range and
production diffs show that the only shared OAuth upstream change is visibility
of the social-start helper. The token request function remains byte-identical;
formatting, type annotations and registration formatting add no behavior. No
passing tests were replayed after those unrelated changes.

Issue #188 stays open. Discovery success/failure, issuer/JWKS/nonce/audience
verification, dynamic refresh metadata, and the remaining issue-wide callback
and lifecycle inventory are outside this bounded production change. Existing
factories, popup/start/state/callback, account-cookie, proxy and legacy token
conversion code are untouched by this PR.
