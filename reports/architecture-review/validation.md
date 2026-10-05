# Refactor validation

The Rust source changes are in commit `70eca8ea`; subsequent commits merge main's documentation/tooling updates and remove a duplicated documentation row. The workspace contains the same refactored Rust source after that merge. The architecture assessment and baseline inventories refer to commit `14eaeb28`.

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

Most SDK failures happen inside TypeScript reference assertions before a Rust scenario is attempted. They include namespaced proof identifiers, proof-existence assumptions, signup-option admission and rate-limit content-type expectations. Other existing differences include CAPTCHA method/body handling and magic-link physical-identifier observations. Changing those authentication semantics is outside this behavior-preserving architecture pass.

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
