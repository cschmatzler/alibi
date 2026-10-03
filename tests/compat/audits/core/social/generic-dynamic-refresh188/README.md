# Dynamic OAuth refresh parameters (#188)

PR #411 adds an awaited per-grant parameter resolver and borrowed request context
for application refresh handlers. Explicit refresh, expired access-token retrieval,
and account-info refresh pass the triggering request. Existing token-only handlers
use the default trait method. Custom handlers bypass the parameter resolver.

Published Better Auth 1.7.6 resolves `refreshTokenParams(refreshCtx)` on every
default generic refresh (`dist/plugins/generic-oauth/index.mjs:245–248`).
The Rust resolver replaces the static additions, including clearing them for
`Ok(None)`, without modifying the shared provider. Existing grant-field protection,
credential precedence, response parsing, and persistence remain in their owners.

## Proof

`raw-proof.tar.gz` contains the final six paired HTTP comparisons for each adapter,
raw forms and callback receipts, before/after physical database rows, comparator
observations, server logs, and binary hashes. SQLx and SeaORM were separately
compiled; setting an environment backend label does not select an adapter.

- SQLx: 6 pass, 0 fail, 368 assertions.
- SeaORM: 6 pass, 0 fail, 368 assertions.
- Base-behavior negative control: 2 fail for the intended reasons. Restoring the
  base helper bypasses the resolver and invokes the token-only custom handler.
  The saved patch leaves new types/signatures available so the fixture compiles.
  The production implementation was restored before the accepted runs.

The cases cover consecutive tenant/header/cookie changes, all three entry points,
undefined additions, resolver errors with no transport or database writes, custom
handler precedence, protected grant/refresh-token fields, configured credentials,
and foreign-owner rejection before callback/transport. Successful rotation changes
only the selected account's tokens and timestamps; other accounts, users, and
sessions remain unchanged. Existing static-parameter tests do not reach the new
asynchronous callback or request-context contract. No test-only production API was
added: resolver and context are application configuration APIs.

No scenario-specific comparator exclusions were added. The existing comparator
pairs generated identities, local server URLs, cookies, and timestamps using its
provenance/window rules. The raw archive retains original values and form order;
scenario observations compare decoded form fields while separately asserting
duplicate absence and the encoded resource value.

`source.json` records published tarball hashes and final byte/inode verification.
`published-integrity.json.gz` retains the pre-proof reference file hashes. Published
packages were restored from pinned tarballs to private inodes; final comparison
found zero byte mismatches across 465 better-auth and 350 core files. Reference
fixtures configure public callbacks and local endpoints without modifying packages.

Reproduction (with installed pinned reference/client dependencies):

```sh
CARGO_TARGET_DIR=/tmp/dynamic-refresh188-sqlx cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml
CARGO_TARGET_DIR=/tmp/dynamic-refresh188-seaorm cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml --features seaorm
CARGO_TARGET_DIR=/tmp/dynamic-refresh188-sqlx python3 tests/compat/audits/core/social/generic-dynamic-refresh188/run-pair.py sqlx
CARGO_TARGET_DIR=/tmp/dynamic-refresh188-seaorm python3 tests/compat/audits/core/social/generic-dynamic-refresh188/run-pair.py seaorm
```

The focused API library clippy check, production rustfmt check, client typecheck,
and reference fixture typecheck pass (saved logs). No full suite, coverage sweep,
or unrelated adapter replay was run. GitHub Actions is disabled; no CI green claim.

## Review and remaining bounds

Manual final review traced account selection/session ownership before both
callbacks, resolver errors before transport/persistence, custom handler precedence,
and protected-field/authentication processing after resolution. Request metadata
remains untrusted; applications must validate entitlements before deriving additions.
The token endpoint remains application configured, with redirects disabled. Callback
errors are mapped through existing public endpoint errors. No concrete authorization
or credential-disclosure issue was found in the change.

The test-audit skill's referenced autoreview/openclaw workflows and scripts are not
installed in this repository/environment; focused manual review was used. Current
main has no changes to the production OAuth owner files, so no rebase or repeated
adapter run was needed. #188 stays open for its broader callback, clock, and
concurrency bounds. These runs do not claim comprehensive concurrent-refresh,
cookie-only storage, or every token-endpoint authentication-mode acceptance.
