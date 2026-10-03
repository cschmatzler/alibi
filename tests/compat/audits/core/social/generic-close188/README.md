# Remaining supported OAuth contracts — #188 / PR #420

This production change completes the remaining key-backed client assertion,
account refresh/authority, and generic profile contracts against published
Better Auth and @better-auth/core **1.7.6**. It reuses the landed proof rather
than reopening factory closure or replaying the provider inventory.

`OAuthPrivateKeyJwtOptions::into_assertion()` supplies the existing production
`PrivateKeyJwt` transport with a fresh JWK or PKCS#8 assertion for every code
and refresh grant. All ten published algorithms are supported. Configuration
validation, explicit/embedded/default algorithm selection, JWK-over-PEM and
key-ID precedence, issuer/subject/client ID, actual endpoint audience, JWT type,
issued time, UUID token identity, and configured/default lifetime follow Source.
Nonfinite lifetimes construct successfully but reject at signing before outbound
transport. Errors and Debug omit private key material. Source's actual Bun
Ed25519 import accepts missing or mismatched public `x`; the measured outcome is
preserved rather than inventing stricter validation. The two published probe
logs retain these review findings. Private-key JWT is **supported, not excluded**.

`OAuthAccountApi` provides trusted direct calls through the initialized OAuth
context. Explicit user authority selects only that user's physical account;
HTTP `userId` never replaces session authority. Automatic refresh preserves
Source's distinction between newly persisted tokens and response fallback:
null access tokens clear the stored field while returning the prior token;
empty access tokens remain empty; empty refresh/ID tokens retain stored values,
while an explicitly refreshed empty ID token stays empty in the response.
Fallback decryption is lazy when a new access token exists. Missing expiry is
omitted in the public response, and an expired refresh timestamp does not veto
an actual provider refresh. Account-info guest rejection and orphan refusal
happen without account adoption. Changed provider-verified email stays verified
on override while account ownership remains stable.

Generic default expiry applies independently after default and custom grants,
only when the grant omitted expiry. Original profiles and full token sets reach
awaited account-key callbacks after user mapping; mapped user fields cannot
change that account key. Numeric default subjects use Source string conversion;
invalid or rejected subjects stop before account/user/session writes.
`resolve_oauth_account_key`, `oauth_callback_path`, and
`oauth_disable_sign_up_option` are shared application/proxy APIs. Custom callback
paths affect redirect URI generation; Source registers only `/callback/:id`, so
an arbitrary external path needs application routing. No extra core dispatcher
was invented. Explicit absent/false signup configuration remains representable
without changing existing provider boolean defaults.

## Focused proof

Two owner files exercise real published Source APIs, real local token/user-info
HTTP transports, and the actual compiled native adapter. Fixtures supply grant
responses and application configuration, not authorization or persisted output.
Successful and rejected calls retain complete physical users/accounts/sessions,
raw outgoing forms/assertions, endpoint responses, and comparator observations.
Signatures are independently verified with published JOSE and the fixture public
keys; forms must contain unique fields, no secret/Basic credentials, and the
proper client/assertion/grant values. No comparator exclusions were changed.

- Actual SQLx: **54 unique passing owners**, accumulated from focused incremental
  runs. `owner-receipts.json` names each owner's latest accepted run; historical
  fixture failures are retained and are not passing qualification. The last
  six affected expiry/subject owners pass with 168 assertions.
- Actual SeaORM: **54/54**, 2,338 assertions, compiled with `--features seaorm`.
  Fixture inspection/seeding uses the common SQLite scaffold; production
  authentication uses `SeaOrmStore`, not a relabeled SQLx process.
- Historical production controls: changed verified email fails at true versus
  false; orphan error fails at `unable_to_link_account` versus `user_not_found`.
  The original SQLx binary also demonstrates null-grant persistence divergence.
  Nonfinite expiry has its own bounded pre-guard transport control. Exact
  restored-production diffs and original observations are retained.

`raw-proof.tar.gz` contains paired raw observations, before/after rows, server
logs, binary hashes, published integrity, passing-run owner receipts, and the
bounded historical controls. All values are synthetic local fixture data.
Published tarball comparison covers 465 Better Auth and 350 core files, with
zero byte mismatches and every installed file on a private inode. Fresh archive
hashes are retained. No Bun package source was changed during these runs.

Production strict API Clippy, client typecheck, reference fixture-only typecheck,
targeted TypeScript lint/format, and whitespace checks pass. Independent
coordinator review cleared the exact production tree after the finite-expiry fix;
no nested implementation/review contributors were used. Main's #418 Automatic
arms are preserved. The final unrelated admin/device rebase leaves OAuth
production and these owner files byte-identical; range and incoming shared diffs
are retained, and passing adapters were not replayed for it. GitHub Actions is
disabled. No full suite, canonical gate, coverage sweep, or CI-green claim.

## Acceptance reconciliation and closure dependency

| #188 acceptance | Existing/current owning proof |
| --- | --- |
| Discovery, issuer/JWKS/nonce/audience, auth, parameters, custom mapping | [PR403 discovery receipt](../generic-discovery-188/README.md), [PR400 static transport receipt](../generic-token-params/README.md), [PR374 factory closure](../provider-batch-154-170.md), this PR's private-key signing/original-subject/custom-grant owners |
| Original profile/override, orphan, expiry/extremes, empty refresh, trusted authority, guest account-info | This PR's account owners, existing [account cookie](../oauth-account-cookies.md) and [token persistence](../oauth-token-persistence.md) proof |
| Signup/link policy, ownership, replay, refresh/logout, supported state modes | PR374 and PR400 full-state lifecycle receipts, [PR411 dynamic refresh](../generic-dynamic-refresh188/README.md), [PR408 provider logout](../generic-provider-logout188/README.md), landed PR418 Automatic/default and explicit-mode proof |

**Issue #188 remains open after #420.** PR421 owns `AuthConfig.api_error_url`
plus its public builder/default, the ordinary configured OAuth callback error
consumer (including Source `error=state_not_found` and safe existing-query
composition), and actual proxy consumption of these shared key/path/signup/output
helpers. PR421's external-route fixture proves custom redirect URI delivery into
the real callback route. Those production consumers and their genuine paired
proof must land before the coordinator reconciles and closes #188. This PR has
no automatic issue-closing keyword and makes no proof claim for that dependency.

## Reproduction

With the repository Rust/Bun environment and frozen pinned dependencies:

```sh
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/owned-oauth-sqlx cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml
CARGO_TARGET_DIR=/tmp/owned-oauth-sqlx python3 tests/compat/audits/core/social/generic-close188/run-pair.py sqlx
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/owned-oauth-seaorm cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml --features seaorm
CARGO_TARGET_DIR=/tmp/owned-oauth-seaorm python3 tests/compat/audits/core/social/generic-close188/run-pair.py seaorm
```

The runner owns random local ports, terminates its children, verifies published
version health, and records each actual binary hash. Optional test regex filters
support affected-owner runs. Persistent worker evidence survives owned worktree
and cache cleanup at the path recorded in `receipt.json`.
