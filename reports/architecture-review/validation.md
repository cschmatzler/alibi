# Refactor and upstream-parity validation

The architecture refactor starts at commit `70eca8ea`; its assessment and baseline inventories refer to commit `14eaeb28`. Follow-up work repairs the previously reported upstream compatibility failures and completes the public facade.

## Follow-up validation

- The nine previously failing SDK files: 245/246 passed after the initial repairs.
- The remaining Microsoft signup-ban repair and user-validation owner replay: 91/91 passed. Together these runs cover all 246 scenarios in the nine files.
- Process-environment compatibility: passed across all four configurations on SQLx.
- Documentation check and production build: passed (67 pages).
- Client formatting, lint and type checking: passed.
- Complete format/lint/type checks, native default and Axum/SeaORM/Redis runs, compatibility-server tests, and doctests: passed. Native runs each passed 1,075 tests.
- Comparator negative controls and SQLx Chromium: passed.
- Full SQLx SDK: 2,849 passed; two timestamp-comparator failures in `core/request/origin-contract.test.ts`; 191 files in 2,593.68 seconds. The original 30 failures all pass.
- The full gate stopped at those two failures; full SeaORM SDK, the final rustdoc stage, and combined coverage were not completed in this run.

The timestamp failures occur after username sign-in. Its session issuance was not recognized by the comparator's email-only request-clock binding, leaving it to compare scenario-relative clocks. A real upstream username-sign-in regression reproduces this harness defect with delayed requests. Repair and runtime investigation are continuing separately from this architecture PR. Issues #466 and #468 are also still open; this PR does not claim to resolve them.

The CAPTCHA HTTP hook now checks protected `OPTIONS` requests before CORS/router dispatch, matching upstream. Microsoft factory configuration retains `disableSignUp` in its authorization policy; ID-token admission therefore rejects new identities even with `requestSignUp: true`.

The compatibility fixtures now query the upstream `magic-link:` and `auth-state:` namespaces, assert the typed magic-link record and JSON rate-limit media type, and decrypt OAuth proxy state/packages/profiles with their distinct purpose-derived keys. These changes retain physical persistence, expiry, replay, origin, foreign-owner and cryptographic assertions. The Microsoft explicit-signup scenario now asserts the actual upstream rejection contract.

All documented application imports use the `better_auth` facade. It now exports user validation, verification policy, callback utilities, cookie-cache types, refresh suppression and `PluginConfig`; consumers do not need a core/API/store-crate dependency.

## Initial architecture validation (before the repairs)

| Check | Result |
| --- | --- |
| Baseline native workspace | 1,074 passed; 305 explicitly skipped |
| Refactored native workspace, default | 1,075 passed; 305 explicitly skipped |
| Refactored native workspace, Axum/SeaORM/Redis | 1,075 passed; 307 explicitly skipped |
| Poem integration, SQLx and SeaORM | Six passed, including disconnect persistence |
| CLI executable schema-generation contracts | Three passed after restoring the generated SeaORM `super` import |
| Workspace and compatibility-server format/lint; TLS/backend feature builds | Passed |
| Updated-main tooling: format and strict Clippy with Axum/Poem/SeaORM/Redis | Passed |
| Client TypeScript formatting, lint and type check | Passed |
| Compatibility-server tests and workspace doctests | Passed |
| Rustdoc, warnings denied | Passed |
| SQLx Chromium compatibility | Passed |
| SeaORM Chromium compatibility | Passed |
| Full SQLx SDK differential suite | 2,821 passed, 30 failed across 191 files |
| Pre-refactor replay of all failing SDK files | 216 passed, the same 30 failed |
| SeaORM process-environment compatibility | OAuth-proxy decrypt failure, also reproduced before the refactor |
| Full SeaORM SDK differential suite and combined coverage floor | Not completed; the complete gate stopped on the existing SQLx SDK failures |

## Existing compatibility failures

Every failing SDK case was replayed against **pre-refactor commit `14eaeb28` in an isolated worktree**, using the same pinned upstream/client dependencies. The sets of failed scenario names are identical: 30 in each run, with no additional refactor-only failure. The separate OAuth-proxy environment failure was also reproduced on that baseline. This does not claim that the entire pre-refactor differential suite was rerun, or that the complete gate is green.

Most SDK failures happen inside TypeScript reference assertions before a Rust scenario is attempted. They include namespaced proof identifiers, proof-existence assumptions, signup-option admission and rate-limit content-type expectations. Other existing differences include CAPTCHA method/body handling and magic-link physical-identifier observations. The follow-up repairs above address those contracts under the expanded upstream-parity requirement.

| Client scenario file | Existing failures |
| --- | ---: |
| `tests/core/auth/user-validation.test.ts` | 2 |
| `tests/core/request/client-ip.test.ts` | 6 |
| `tests/core/schema/additional-fields.test.ts` | 1 |
| `tests/core/schema/verification-storage.test.ts` | 9 |
| `tests/core/social/generic-discovery.test.ts` | 7 |
| `tests/core/social/microsoft.test.ts` | 1 |
| `tests/plugins/captcha/middleware.test.ts` | 2 |
| `tests/plugins/email-otp/callback-context.test.ts` | 1 |
| `tests/plugins/oauth-popup/popup.test.ts` | 1 |

The replay used the existing `sdk::tests::selected_client_compat` runner with `BETTER_AUTH_COMPAT_PATHS` set to these files; the environment replay used `sdk::tests::environment_client_compat` with `BETTER_AUTH_COMPAT_BACKEND=seaorm`. No new skips were added, and no assertions were weakened or production behavior changed to hide these failures.

The only new behavior test checks that the embedded OpenAPI builder uses a custom plugin's declared metadata before instance initialization. Existing initialized-instance tests now declare their reusable annotations through that same static hook, exercising its default configured delegation.
