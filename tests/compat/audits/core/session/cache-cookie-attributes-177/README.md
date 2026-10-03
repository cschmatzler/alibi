# Configured session-cache scope and logout cleanup — issue #177

Bounded production repair in PR #415. The cache renderer hardcoded `Path=/`,
omitted Domain and ignored configured HttpOnly/SameSite/Secure attributes;
`/sign-out` did not expire incoming session-cache chunks. The cache writer and
cleanup now share the existing attribute resolver/serializer. Chunk attributes
resolve against the canonical session-data or account-data base name. Account
rendering delegates to the same numeric-age implementation with its existing
semantics. Logout extends the existing chunk cleanup loop to session data.

Published Better Auth **1.7.6** remains the oracle. The previously downloaded
npm tarballs were restored into the checkout's private Bun node_modules before
any execution. Every published file in better-auth and @better-auth/core was
then compared byte-for-byte; see `provenance.txt`. No oracle code, raw-cookie
comparisons, capability exclusions or receipts changed. Relevant source owners:
`dist/cookies/index.mjs` (`createCookieGetter`, `setCookieCache`,
`expireCookie`, `deleteSessionCookie`) and the published session-store chunker.

## Focused behavioral proof

The existing compact chunking HTTP scenario is extended as a table with
standard settings, inherited defaults, and per-family overrides. The latter
replace deliberately incompatible default scope/attributes. Each real signup
emits three chunks, which retain the existing 4050-byte limit, canonical index
ordering, base precedence, and actual cached reader behavior after a physical
user rename. Logout expires every incoming chunk with matching scope/attributes;
a standards-aware jar independently applies the wire headers and must become
empty. Scoped database inspection confirms the session row was physically
removed. The actor also becomes unauthenticated.

The new assertions guard observable cookie scope/lifecycle at the existing
strongest owner boundary; the previous scenario only covered chunk limits and
reader precedence. A private renderer test cannot observe browser persistence
or the missing sign-out loop. No production test seam was added.

* `before.log`: authentic Source passes; baseline Rust fails on the wrong Path.
* `sqlx.log`: after the renderer repair, native issuance succeeds but logout
  fails because it emits **zero** cache chunk expirations (the second real gap).
* `sqlx-final.log`: **3/3** focused SDK/raw comparison scenarios pass against
  actual SQLxStore and Source.
* `seaorm-final.log`: **3/3** pass against actual SeaOrmStore and Source.
* `*-physical.json`: complete bounded raw signup/logout headers, independent
  standards-aware jar scopes and physically persisted session counts. Before:
  four cookies to three after logout, while rows go one to zero. After on Source,
  SQLx and SeaORM: four cookies to zero, rows one to zero. Only disposable local
  fixture credentials appear in these raw observations.

Commands (checkout-owned ports 3177/3277; baseline 3377):

```sh
CARGO_TARGET_DIR=/tmp/cookie177-target cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml
# SeaORM changes the actual store via its compile-time feature:
CARGO_TARGET_DIR=/tmp/cookie177-target cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml --features seaorm
AUTH_BASE_URL_TS=http://localhost:3177 AUTH_BASE_URL_RUST=http://localhost:3277 bun test tests/core/session/cookie-cache.test.ts --test-name-pattern 'compact cache chunking'
cargo clippy --locked --manifest-path tests/compat/rust-server/Cargo.toml -p better-auth-core -p better-auth-api --lib -- -D warnings
```

Builds/Clippy used `devenv shell` solely to supply compiler/OpenSSL paths;
no devenv test, full suite, sweep or coverage gate ran. Focused oxfmt, oxlint,
client TypeScript and `git diff --check` pass. An early fixture launch lacked
OpenSSL's runtime search path; launching under the same shell repaired it.
The independent jar originally threw on the deliberately invalid default
Domain of a sibling expiration; it now ignores rejected cookies like the real
actor/browser jar, while explicitly validating accepted cache scopes.

## Review and rebase

Single-worker source/security review: encoded cache values keep the exact
existing encodeURIComponent set; the shared numeric policy still floors
nonnegative ages, omits negative/NaN/absent ages and rejects ages over 400 days.
Account input remains an explicit numeric age and retains its prior renderer.
Prefix selection from #401 is untouched; the serializer continues enforcing
Secure on `__Secure-` and Secure/root Path/no Domain on `__Host-`. Cache chunks
use the existing canonical numeric parser; exact base names take precedence.
The logout loop only adds incoming session-data chunk retirement and keeps
account retirement conditional. No callback, store-builder, account codec,
organization or one-time-token changes. No delegation was used.

Tested base: `504633d3`; tested implementation/fixture commit: `cbf4f0d2ca99d848eb02e24f04812315daea7037`.
The final SQLx test differs from that commit only by a brace-formatting fix
around the identical jar issuance loop. SeaORM tests include that fix.
Rebased onto `e2811bf8` after inspecting incoming #414/#412: affected cookie
owners/fixtures are unchanged; the AuthBuilder edit only affects the unrelated
stateless organization store. `range-diff.txt` shows all three implementation
commits unchanged. Passing adapter checks were not replayed after this rebase.

GitHub Actions is disabled and the PR has no CI checks; these are local results.
Issue #177 remains open: real TLS/non-loopback/proxy behavior, cross-subdomain
inference, all family transitions and the broad domain matrix are unproven.
Caller-selected Max-Age/payload expiry remains unchanged; this patch does not
extend advanced Max-Age precedence. Chromium was not run for this slice.
