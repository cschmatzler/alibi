# Dedicated OAuth providers — consolidated PR #374

Authority: actual installed published Better Auth / @better-auth/core **1.7.6**, including each factory, declarations and shared authorization/token/account helpers. Factory bytes and issue acceptance are retained in the worker evidence archive. This batch implements all dedicated provider issues #154–#170 and supersedes the earlier bounded audits' production residuals.

Eleven new dedicated native factories accompany the existing Notion, Paybin, PayPal, Polar, Railway and Reddit factories. Rust interfaces and independent provider registrations are preserved.

| Issue | Native factory | Targeted owner |
| --- | --- | --- |
| #154 | [notion](../../../../../crates/api/src/plugins/oauth/providers/notion.rs) | `notion.test.ts` plus shared callbacks/overrides |
| #155 | [paybin](../../../../../crates/api/src/plugins/oauth/providers/paybin.rs) | `paybin.test.ts` plus shared callbacks/overrides |
| #156 | [paypal](../../../../../crates/api/src/plugins/oauth/providers/paypal.rs) | `paypal.test.ts` plus shared callbacks/overrides |
| #157 | [polar](../../../../../crates/api/src/plugins/oauth/providers/polar.rs) | `polar.test.ts` plus shared callbacks/overrides |
| #158 | [railway](../../../../../crates/api/src/plugins/oauth/providers/railway.rs) | `railway.test.ts` plus shared callbacks/overrides |
| #159 | [reddit](../../../../../crates/api/src/plugins/oauth/providers/reddit.rs) | `reddit.test.ts` plus shared callbacks/overrides |
| #160 | [roblox](../../../../../crates/api/src/plugins/oauth/providers/roblox.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #161 | [salesforce](../../../../../crates/api/src/plugins/oauth/providers/salesforce.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #162 | [slack](../../../../../crates/api/src/plugins/oauth/providers/slack.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #163 | [spotify](../../../../../crates/api/src/plugins/oauth/providers/spotify.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #164 | [tiktok](../../../../../crates/api/src/plugins/oauth/providers/tiktok.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #165 | [twitch](../../../../../crates/api/src/plugins/oauth/providers/twitch.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #166 | [twitter](../../../../../crates/api/src/plugins/oauth/providers/twitter.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #167 | [vercel](../../../../../crates/api/src/plugins/oauth/providers/vercel.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #168 | [vk](../../../../../crates/api/src/plugins/oauth/providers/vk.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #169 | [wechat](../../../../../crates/api/src/plugins/oauth/providers/wechat.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |
| #170 | [zoom](../../../../../crates/api/src/plugins/oauth/providers/zoom.rs) | `provider-batch.test.ts` plus shared callbacks/overrides |

## Production contracts

Factories implement published default/configured scope order, fixed parameters, authorization/issuer endpoints, PKCE choices, code/refresh authentication and expiry. Distinct transports remain distinct: PayPal Basic and omitted scopes, Reddit code-only header replacement, Twitter Basic plus two profile requests, VK POST userinfo/client arrays, TikTok client_key/comma scopes, and WeChat GET grants/appid/fragment/openid. Salesforce supports production, sandbox and login-domain selection. Slack puts requested scopes before configured scopes. Twitch claims retain JavaScript property order. Zoom omits scopes and its returned factory omits options; Vercel has no refresh hook. Unsupported options are not presented as effective factory controls.

Original account subject remains independent of mapped public ID. Async application mapping and custom userinfo retain Source precedence, TikTok's ignored mapper, and caught versus uncaught exception behavior. Empty-500 callbacks consume state without emitting its pending clear cookie; ordinary error redirects clear it. Paybin malformed grant/raw email behavior is opt-in. One Tap/proxy/global JWT decoding is unchanged.

Raw name/image/verification and token scalars follow actual database affinity separately from typed Rust authority. SQLite numeric verification reads compare with 1; retained TEXT verification remains TEXT in public output. Trusted raw overrides cannot be populated by HTTP deserialization. Explicit NULL token updates remain distinct from omission; encryption rejects unsupported truthy nonstrings and preserves Source's plaintext ID-token contract. Refresh retains falsy-value fallbacks. WeChat always forms its expiry and excludes ID-token output. Stored account scopes use comma boundaries and JavaScript trimming, including the measured NEL/BOM control. Wire output preserves current main's cache omissions and emits raw verification once.

These seventeen published factories declare no ID-token verification/JWKS/nonce/audience hook or provider logout hook. Grant JWT decoding in Paybin/Twitch and PayPal's decoded subject comparison do not claim cryptographic verification. Direct ID-token admission remains unsupported by these factories. Existing owners retain local sign-out and shared account ownership/state/proof/replay/rotation controls; no unsupported verifier/logout mode is invented.

## Focused verification and review

All production provider implementations were completed before grouped testing. Actual pinned Source factories and the official SDK use local real HTTP transports. Fixtures supply responses, never admission decisions. Complete physical users/accounts/sessions/verifications and ambient wire receipts are archived separately from SDK comparisons. PKCE values are checked against their issued challenge before the existing token relationship comparison. Different physical schema names/runtime-added headers are independently inspected and retained, rather than normalized into expected API output. The shared comparator is unchanged.

| Backend | Grouped campaign | Affected residual/fix checks | Unique scenarios |
| --- | --- | --- | --- |
| SQLx | 472/472; 16,498 assertions, ten OAuth/provider/account owners | 20/20; 636 assertions; stored scopes 1/1; 20 assertions | 493 |
| SeaORM | 492/492; 17,134 assertions, same owners including residuals | scope/encryption 4/4; 94 assertions, including one new scenario and three rechecks | 493 |

Recovery integration on main `9ddc1eee`, tested provider head `a93efeb5`: affected raw scalar and all seventeen override scenarios pass on actual SQLx and SeaORM, **20/20 and 624 assertions each**. The existing `without_database_credential_issuance_and_restart` test also passes, preserving omitted image output and automatic cache renewal. Rebase had no conflicts; retained user views, omitted fields and whole-view cache cloning coexist with raw verification output. No clean grouped campaign was replayed. All seventeen archived published factory/declaration bytes match the installed 1.7.6 packages. GitHub Actions is disabled and this PR has no posted CI checks.

Strict fixture Clippy with SeaORM covers the API/core/SQLx/SeaORM build graph; strict API Clippy and client TypeScript also pass. No full suite, canonical sweep, expanded mutation campaign or comprehensive coverage percentage is claimed. Latest explicit user instructions replace earlier canonical full-gate requirements with focused dual-store verification.

Retained before/after failures: reserved SDK additional-parameter setup was repaired; the state fixture now reads actual adapter verification output; SeaORM exposed PostgreSQL placeholders incorrectly used in SQLite SELECT/RETURNING construction, fixed to actual column expressions; WeChat exposed space splitting in the account scope parser, corrected to Source's comma/trim contract. Failed/stopped runs remain historical failures, never passing qualification.

Sole-owner manual authorization/persistence review applied test-audit and authorization/data-exfiltration guidance. Account identity and foreign ownership remain authoritative. Raw output cannot replace ownership checks or account subject. Session persistence policy is unchanged. Main's cache omission, invitation and quota changes are retained. No supported production provider contract is deferred to another provider issue or PR.

Evidence: `/home/cschmatzler/.local/share/better-auth-rs-evidence/issue156/20261003-paypal-worker`; durable recovery archive `recovery/` retains 113 worker logs, raw HTTP/SQL/SDK comparisons, published checksums and tested heads. Original temporary artifacts remain at `/tmp/paypal156-evidence` and `/tmp/paypal156-batch-*.log`. Earlier raw comparisons, source branch/cell artifacts and meaningful mutation/negative controls remain historical and preserved. Installed package source was not mutated.
