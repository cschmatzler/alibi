# Account cookie contract repair

Owned clone: `/tmp/better-auth-final-verification-20261004/account-contract-repair`.
Fixed baseline: `30c912a0e808baef91535a963a9cb820683c58e2`.
The coordinator checkout/binding and all other campaign lanes were untouched.

## Findings and independent contract

The untouched baseline reproduces the two cookie-matched rotation failures and
the encrypted-vector failure. `native-before-axum.log` is the narrow reproduction;
`campaign-before.log` (preserved in the external campaign report lane) is the
unaltered diagnostic from the vendor-repaired coverage head `5eae29b9`.
`native-before.log` also records an initial compile command missing the necessary
`axum` feature; it was corrected before reproducing the three test failures.

The native cookie issuer called an OAuth plugin with an uninitialized store.
Default `AccountStore::get_account_record` retains the physical model's honest
snake_case serialized snapshot. Production `BetterAuth::build` initializes
canonical adapter projection through `AuthInitContext` and `PluginStore`.
After #395 introduced raw snapshot preservation, the old fixture therefore
issued a malformed cookie lacking canonical `userId`/`providerId` fields. #420
correctly rejects explicit cookie selection lacking authenticated ownership.
#421 retains callback policy/ownership behavior. No production fix is justified.

The published npm Better Auth 1.7.6 `getAccountCookie` and `symmetricDecodeJWT`
retain JWT claims. `source-probe.log` independently supplies exact decoded
`valid` and `noKid` outputs; the fixture's new `decoded` expectations are copied
from those published outputs, including their distinct claim presence/values.
The original payload and every encrypted vector remain unchanged. Existing
wrong-salt, wrong-secret, expired, GCM, JWS and protected-header/IV/ciphertext/tag
mutation negative controls remain intact. Claims are not stripped by production.

The authentic Source probe uses Better Auth's real `auth.handler` routes and
Bun SQLite migrations/storage. Owner session + signed account cookie selects
the physical row, rotates both grants, and emits a new cookie. A foreign session
returns ACCOUNT_NOT_FOUND with unchanged physical row and zero refresh calls.
The provider hook models an external provider response; real published auth,
cookie selection and SQL persistence perform the behavior under assertion.
Source cookie parsing converts date strings to Date values; raw receipts retain
their JSON form. Probe origins explicitly match the configured base URL to reach
the account owner guard instead of a CSRF denial (an initial 403 diagnostic is
preserved separately).

## Test authoring gate and repair

Two existing route owners are extended, without new test inventory or seams:

* The observable contract is authenticated selection of the physical owner,
  rejection of foreign ownership before any refresh, durable token rotation,
  unchanged other rows, and renewed authenticated cookie contents.
* Credible regressions include malformed callback projection, accepting a
  foreign signed cookie, refreshing before checking ownership, writing the
  wrong row, losing the rotated refresh grant, or renewing stale cookie tokens.
* Existing direct-plugin tests neither initialized adapter projection nor proved
  the SQLx boundary, and the old foreign denial could pass on malformed cookies.
  The cases now use genuine builder initialization, production callback issuance
  and HTTP dispatch with actual SQLx and SeaORM SQLite stores. Independent raw
  SQL verifies writes rather than trusting store getters. Foreign rejection
  checks the complete accounts/users/sessions snapshot and provider call count.
* No new production export, wrapper, hook or test-only seam is introduced.
  Existing backend/physical database support is reused.

The owning vector assertion is updated to the exact independent Source receipt,
not to a native-generated expected value. Assertions/security gates are retained
or strengthened. Production LOC change: zero.

## Commands and bounded proof

All commands run from the owned clone. Each Rust command uses:
`CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
and private `CARGO_TARGET_DIR=/tmp/better-auth-final-verification-20261004/account-contract-target`.

```
git clone --no-hardlinks <coordinator-path> <owned-clone>
git fetch origin main
git checkout -b repair/account-contract-20261004 30c912a0e808baef91535a963a9cb820683c58e2
BUN_INSTALL_CACHE_DIR=/tmp/better-auth-final-verification-20261004/account-contract-bun-cache devenv shell -- bun install --cwd tests/compat/reference-server --frozen-lockfile --backend=copyfile
devenv shell -- bun reports/account-contract/source-probe.mjs
devenv shell -- cargo nextest run --locked --no-fail-fast -p better-auth -p better-auth-api --features axum,seaorm -E 'test(cookie_matched_account) | test(account_cookie_accepts_pinned) | test(test_get_access_token_rejects_cookie_for_the_wrong_user)'
devenv shell -- rustfmt --edition 2024 --check tests/integration/core/account_oauth.rs crates/api/src/plugins/oauth/account_cookie/mod.rs
git diff --check
```

No full suites or expanded differential/coverage campaign were run in this lane.
The original baseline tests were reproduced before changing fixtures. Raw
Source/native before/after, build diagnostics, pinned package hashes and frozen
install receipts are preserved. Root/scoped AGENTS.md were searched in the
coordinator, original repository, owned clone and their ancestors; none existed.
The test-audit skill was read and its owner-boundary authoring gate applied.
Repository Rust/Bun commands are the relevant equivalents of that skill's
Vitest/OpenClaw commands. Independent exact-head review belongs to the root.


Final fixed-baseline outcomes: Source probe PASS; targeted native 4/4 PASS
(each rotation case runs both actual backends); API scoped Clippy PASS;
scoped formatting and diff whitespace PASS. Integration scoped Clippy is blocked
solely by the two pre-existing `unreachable!` uses in
`tests/integration/plugins/admin_identity.rs:1347/1370`, owned by the separate
style/runner #432 lane. No flags were relaxed and no unrelated file was edited.

```
devenv shell -- cargo clippy --locked -p better-auth --test integration --features axum,seaorm -- -D warnings
devenv shell -- cargo clippy --locked -p better-auth-api --tests --features axum -- -D warnings
```

An intermediate compile diagnostic caught a missing `CreateAccount` Default;
the fixture now supplies the actual create fields. The first expanded route run
also exposed the test future's stack size. Boxing scenario and dispatch futures
fixed that without changing stack settings, gate inputs or any assertions. Raw
intermediate diagnostics remain in the external owned report lane.

Root authorized a fixture-only rebase after this fixed-baseline proof. On the
actual #432 landed main, compare range-diff and owning file hashes; rerun only the
originally blocked integration scoped Clippy when incoming commits have not
changed these owners. Root must qualify the exact pushed head before merge.
