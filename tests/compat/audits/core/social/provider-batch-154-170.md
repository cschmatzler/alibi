# Consolidated provider acceptance — PR #374

Authority: installed published `@better-auth/core`/`better-auth` **1.7.6**, issue bodies captured verbatim in the retained evidence archive, and current main. All issues #154–#170 are open. This matrix tracks completion; “pending” means no closure claim. The earlier provider audits describe historical slices; their listed residuals are requirements for this PR.

| Issue / provider | Native dedicated factory | Defaults/options/endpoints/PKCE/grants/expiry | Raw mapping/error boundaries/full SQL | State/proof/admission/replay/rotation/foreign ownership | Application callbacks/override/encryption/client arrays | Source branches/cells/mutations | SQLx + SeaORM grouped proof | Final review/targeted gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| #154 notion | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #155 paybin | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #156 paypal | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #157 polar | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #158 railway | existing factory; residual closure pending | pending | pending | pending | pending | pending | pending | pending |
| #159 reddit | saved implementation integrated; sole-owner review pending | pending | pending | pending | pending | pending | pending | pending |
| #160 roblox | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #161 salesforce | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #162 slack | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #163 spotify | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #164 tiktok | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #165 twitch | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #166 twitter | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #167 vercel | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #168 vk | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #169 wechat | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |
| #170 zoom | factory drafted; contract review pending | pending | pending | pending | pending | pending | pending | pending |

Every completed row must link actual factory/declaration hashes, implementation, meaningful official-client owner scenarios, raw observations and HTTP receipts, complete users/accounts/sessions, mutation/negative controls, instrumented Source branch evidence, and backend-specific test logs. Unsupported signature/JWKS/nonce/audience/provider-logout modes are recorded precisely from Source rather than invented. Supported callbacks and malformed profile/token error contracts cannot be deferred as residuals.

Source coverage uses the existing assurance preload's in-memory loader instrumentation and original package checksum validation; dependency hardlinks must never be mutated. No comparison skip, broad coercion or blanket normalization may conceal a gap. User-excluded packages and all existing provider registrations/evidence remain preserved.

Final gate (latest explicit user override): no full sweeps or canonical full-suite gate. After every provider and residual production change is implemented, run one grouped whole-provider targeted campaign on SQLx and SeaORM, retain complete raw comparisons/SQL/HTTP receipts and meaningful grouped negative controls, review the affected authorization/persistence paths, then merge this single PR. Source cells and coverage obligations remain part of the targeted evidence. No provider readiness file, frozen-SHA sweep protocol, scripts/check.sh, scripts/compat.sh or full_client_compat execution applies.

Strict-docs issue #365 was resolved by main commit 9524783c (PR #376); latest rebase also preserves PostgreSQL CHAR bindings (#377) and quota signatures (#378), based on main ef4c299a.

Implementation checkpoint: eleven missing dedicated factory drafts compile with the API axum feature. Raw verification creation/override and text-scalar adapter paths are drafted, with typed Rust authority retained separately from actual public database output. Callback precedence, malformed error boundaries, token/configuration cases and grouped fixtures remain implementation work. All earlier provider test logs are historical; no batch test or readiness claim has been made.

Implementation checkpoint (unqualified): async partial mapping remains before original-subject resolution; custom userinfo takes precedence and TikTok's ignored mapper stays ignored. Factory-local exception tags retain empty-500/no-clear versus caught userinfo redirects. The actual adapter supplies raw verification output and token TEXT affinity; explicit token nulls are distinct from omitted updates, encrypted truthy nonstrings are rejected, and invalid truthy grant expiries are rejected at persistence rather than silently losing expiry. These paths require the grouped SDK/HTTP/SQL campaign before completion; no passing test claim attaches to this checkpoint.
