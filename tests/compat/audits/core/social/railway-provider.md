# Railway provider contract (issue #158)

Authority: authentic published `@better-auth/core` **1.7.6** tarball's `dist/social-providers/railway.mjs`, declarations and actual authorization, token-auth, code, refresh and expiry helpers. Both installed factories are byte-identical to that tarball. The reference fixture executes the unchanged published factory and redirects only its fixed token/userinfo HTTP destinations. Dependencies are hardlinked; no installed package is mutated. Official-client owner: `tests/core/social/railway.test.ts`.

Authoring gate: this owner protects Railway's actual ordered scopes, fixed destinations, Basic grant authentication, S256 proof binding, direct profile mapping and original `sub` account authority. Credible regressions include replacing Basic with form credentials, removing PKCE, copying Polar's scope order/name fallback, trusting `email_verified`, or allowing mapper ID to replace raw identity. Existing generic or sibling tests cannot exercise Railway's factory. Table variants share setup and production entry points. Fixtures provide responses/receipts, never callback admission or auth-row writes. Comparator, raw observations, pins and excluded package boundaries remain unchanged.

## Native contract

`OAuthProvider::railway` and `railway_with_options(RailwayOptions)` default to authorization `https://backboard.railway.com/oauth/auth`, token `https://backboard.railway.com/oauth/token` and bearer GET userinfo `https://backboard.railway.com/oauth/me`. Default scopes are `openid`, `email`, `profile`, then configured scopes, then requested scopes, preserving duplicates/order. Disabling defaults removes only defaults; empty final scope omits its parameter. Nonempty authorization endpoint and redirect URI override defaults; empty overrides fall back. Caller additional parameters are forwarded; reserved OAuth parameters are rejected by the route. Configured prompt, responseMode, loginHint, display and idTokenNonce are not forwarded by this factory.

Both code and refresh grants require client ID and secret and use RFC6749 form-encoded Basic credentials, without either credential in the form. Missing secret fails before provider HTTP. Optional clientKey is code-only: the actual refresh helper ignores it. Token redirects are refused. PKCE hashes the actual exchange verifier into the issued S256 challenge. Absent/zero expiry has no fabricated default; fractional seconds retain millisecond precision. Refresh rotates the owned account tokens while preserving original scope and all user/session/foreign rows. Local logout removes only the local session.

Account authority derives from original `profile.sub` after the application mapper sees the original profile. Mapper ID may appear in public account-info, but cannot change persisted account identity or admit an invalid raw subject. Numeric subjects, including zero and JavaScript exponential formatting, remain supported. Missing/null/empty subjects deny admission. Name/email/picture use direct profile fields; raw account-info preserves absence, null, empty and numeric name/image values independently from typed persistence. Email verification is always false, even if `email_verified` is true/null, unless the mapper overrides it.

The factory has no issuer/discovery option, ID-token/JWKS/nonce/audience verifier or provider logout. Direct ID-token signin is rejected without provider HTTP. Generic asynchronous userinfo/refresh callbacks and signup policies remain configurable on the returned native provider.

## Review and scope

Authorization review traces state recovery and consumption before exchange, original subject resolution before callback persistence, and refresh/account-info ownership through the authoritative session user and owned account lookup. Tests check actual foreign denials, replay, unissued state, invalid provider, signup-disabled and required-verification behavior against full physical users/accounts/sessions. No authorization defect identified in this change.

Data-exfiltration review traces fixed destinations or trusted application transport overrides into bearer GET; request/profile fields cannot choose a destination. Debug omits the secret. Existing token transport refuses redirects. No new untrusted destination or foreign data access is introduced.

Residuals retained under #158: dedicated asynchronous override/encrypted-token/client-ID-array permutations and instrumented upstream factory coverage are not claimed. Declared string email and scalar name/picture boundaries are exercised; numeric email and arbitrary object/array fields are outside this scoped contract. No Source crash is emulated. This is a scoped implementation, not false full issue closure.

Per explicit user instruction, only targeted dual-backend verification runs here. `full_client_compat`, `scripts/check.sh`, `scripts/compat.sh` and full `devenv test` are never invoked; coordinator owns periodic full proof. Raw paired observations, evidence and logs are retained outside owned cleanup at `/tmp/railway158-evidence` and `/tmp/railway158-*.log`. Current-main validation and negative-control measurements follow below.

## Measured verification

The initial independent Source run identified numeric zero-name signup coercion. After correcting the owner expectation from the Source receipt, native alone failed the intended physical user-name assertion on **both SQLx and SeaORM**: `name: "0"` instead of `name: ""` (Source passed first). Logs: `/tmp/railway158-zero-before-sqlx.log`, `/tmp/railway158-zero-before-seaorm.log`. The initial failed probe is retained; it was not skipped or normalized away. Native repair retains raw zero in account-info and applies signup's falsy-name fallback only to typed persistence. Final paired proofs pass that regression on both stores. This is a measured before/after repair, not a claim of a historical missing-factory baseline run.

After rebasing over the externally merged adapter refactor onto **564a05b6**, targeted Railway + Polar + Paybin + account owners pass **162/162 tests, 5,620 assertions per backend**. Those earlier-base logs remain `/tmp/railway158-{sqlx,seaorm}-final.log`.

Main then advanced through the phone proof fix. Final rebase base is **441807cf1a20fa374f2c5e0edb59da9b8912b655**. Both fixtures were rebuilt and the identical targeted set rerun:

- SQLx: **162/162**, **5,620 assertions**, `/tmp/railway158-current-sqlx.log`.
- SeaORM: **162/162**, **5,620 assertions**, `/tmp/railway158-current-seaorm.log`.
- Each final backend retains **162 complete raw Source/native observation pairs**, including all **47 Railway scenarios**, under `/tmp/railway158-evidence/current-{sqlx,seaorm}`. Auth store selection is the standalone fixture's `seaorm` feature in `backend.rs`; the shared inspection connection is separate from the auth store under test.
- Strict API all-target Clippy with Axum and standalone fixture all-target Clippy with SeaORM pass. Final-main TypeScript typecheck, focused oxfmt/oxlint, diff checks and the coverage harness (**4/4**, **78 assertions**) pass.
- **223 distinct** emitted Railway route/category/scenario requirements are appended across five route families; duplicated inventory entries receive **446** additions. Prior requirements retain order, route flags and the 1.7.6 pin. All eight Paybin/Polar source/fixture/test files remain byte-identical to latest main.
- GitHub Actions are disabled (`actions/permissions.enabled=false`); no hosted CI success is claimed.

The retained runner `/tmp/railway158-evidence/run.py` starts the authentic Bun reference and the owned, explicitly built native fixture, then invokes `bun test tests/core/social/railway.test.ts tests/core/social/polar.test.ts tests/core/social/paybin.test.ts tests/core/account` with `COMPAT_COVERAGE=1` and raw observation capture. Builds run in `devenv shell` with `CARGO_BUILD_JOBS=2` and owned `CARGO_TARGET_DIR=/tmp/railway158-target`. No full suite, test skip, package mutation, broad normalization, comparator weakening, nested delegation, or change to PR #364 was introduced.
