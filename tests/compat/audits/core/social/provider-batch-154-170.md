# Consolidated provider acceptance — PR #374

Authority: installed published `@better-auth/core`/`better-auth` **1.7.6**, issue bodies captured verbatim in the retained evidence archive, and current main. All issues #154–#170 are open. This matrix tracks completion; “pending” means no closure claim. The earlier provider audits describe historical slices; their listed residuals are requirements for this PR.

| Issue / provider | Native dedicated factory | Defaults/options/endpoints/PKCE/grants/expiry | Raw mapping/error boundaries/full SQL | State/proof/admission/replay/rotation/foreign ownership | Application callbacks/override/encryption/client arrays | Source branches/cells/mutations | SQLx + SeaORM grouped proof | Final review/coordinator gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| #154 notion | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #155 paybin | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #156 paypal | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #157 polar | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #158 railway | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #159 reddit | contributor implementation in flight | pending | pending | pending | pending | pending | pending | pending |
| #160 roblox | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #161 salesforce | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #162 slack | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #163 spotify | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #164 tiktok | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #165 twitch | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #166 twitter | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #167 vercel | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #168 vk | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #169 wechat | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |
| #170 zoom | factory implementation pending | pending | pending | pending | pending | pending | pending | pending |

Every completed row must link actual factory/declaration hashes, implementation, meaningful official-client owner scenarios, raw observations and HTTP receipts, complete users/accounts/sessions, mutation/negative controls, instrumented Source branch evidence, and backend-specific test logs. Unsupported signature/JWKS/nonce/audience/provider-logout modes are recorded precisely from Source rather than invented. Supported callbacks and malformed profile/token error contracts cannot be deferred as residuals.

Source coverage uses the existing assurance preload's in-memory loader instrumentation and original package checksum validation; dependency hardlinks must never be mutated. No comparison skip, broad coercion or blanket normalization may conceal a gap. User-excluded packages and all existing provider registrations/evidence remain preserved.

Coordinator broad gate: cadence only, next scheduled 12:31 UTC; includes full SQLx/SeaORM SDK/browser, native default/optional matrix, strict docs and canonical scripts/coverage.sh with unchanged 75% floor. The worker never invokes a full suite. Known strict-docs issue #365 remains visible. Selected owners/native Source instrumentation and broader evidence are separate obligations, not substitutes for one another.

Readiness: only after all acceptance implementation, grouped proof and review are complete, push the immutable PR head and write `/tmp/better-auth-compat-sweeps-41593867/provider-batch-ready.json` with `{"ready":true,"pullRequest":374,"commit":"<exact40hex pushedHEAD>"}`; send exact head and complete matrix to the coordinator. Freeze the head for the scheduled final run. Any further change invalidates its qualification. Closing references and authorized merge follow final evidence review, with every provider issue legitimately satisfied.
