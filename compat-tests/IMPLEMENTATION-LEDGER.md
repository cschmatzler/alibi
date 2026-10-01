# Better Auth 1.7.6 implementation ledger

This ledger tracks implementation and unresolved evidence. It is not a parity
completion claim. The full runtime target, including capabilities absent from
selected HTTP profiles, is in [the upstream audit](audits/upstream-target.md).
The oracle remains pinned to 1.7.6. Rust interfaces remain native.

The user replaced the full-parity objective with selected capabilities on
2026-09-30: finish and merge existing work (including SIWE), multiple sessions,
further organization/admin/two-factor/passkey/API-key branches, and successful
username-availability/two-factor-disable flows. Wider pinned parity work resumes
after these priorities are complete. OAuth authorization server, MCP,
CIMD, SSO, SCIM, Stripe, i18n, Expo and Electron are excluded from this work.

## Integrated baseline

Master `ae4aa46` includes scrypt-only password interoperability (Argon2 support
removed), capability-organized tests, identity/verification storage, organization
teams and dynamic roles, signed email verification, core signup/session fixes,
email OTP, magic links, managed JWT/JWKS, and one-time tokens. PRs #2–14 and #19
are merged. The user's setup cleanup (#18) remains intact.

The baseline canonical gate passed: 213 SDK scenarios / 4,140 assertions,
34 harness tests / 177 assertions, two Chromium tests / 22 assertions, and
79.24% source lines (21,012 / 26,518). These measurements describe that tree;
they do not establish all configuration or integration behavior.

## Active capability owners

| Slice | Owner | Dependencies | Evidence and status |
| --- | --- | --- | --- |
| Required configuration evidence | Coordinator; independent SIWE-owner review | Existing strict harness | Merged PR #21 supports all required names per category and preserves existing requirements during regeneration. 35 harness tests / 193 assertions and TypeScript pass; duplicate-entry review finding repaired. |
| JWT/session interaction | JWT owner; coordinator integration; independent SIWE-owner review | Required configuration evidence | Real SQLite refresh/refusal and hostile request-snapshot tests; three additional official client scenarios cover refresh/preferences, original completed-session headers and API-key owner isolation. Merged PR #22 after the final canonical gate: 216 SDK scenarios, 35 harness tests, two Chromium tests and 79.18% source lines. |
| JSON and SQLite numeric semantics | Phone owner; independent JWT-owner and coordinator JWT review | Common safe JSON parser, callback values and numeric binding | Merged PR #26 after independent review. Explicit JsValue preserves raw f64 until validation and JSON emission; organization/API-key SQLite text and tiny-float readback are exact. Five SDK scenarios / 290 assertions plus JWT signing evidence and 112,547 pinned SQLite conversion probes. Canonical gate passed: 244 SDK / 6,190 assertions, 37 harness / 210, two Chromium / 22 and 78.67% source lines (22,900 / 29,109). User metadata and custom remote JWT callback follow-ups remain separate. |
| User JSON persistence | Phone owner; coordinator independent review/integration | Numeric JSON; custom entity compatibility | Public immutable JsonMetadata and derive/manual preparation retain arbitrary keys and exact SQLite text. Stale cached binding regression repaired. Seven numeric/user integrations and public compile-fail contract pass. Canonical gate passes: 244 SDK / 6,190 assertions, 37 harness / 210, two Chromium / 22, 78.74% source lines (22,945 / 29,139). Merged PR #27. |
| Phone authentication | Phone owner; coordinator contracts/integration | Safe numeric prerequisite, identity fields, verification/session helpers | All five routes, server-only consumption, attempts/expiry/replay/concurrency, ownership, signup, external verifier and two-factor/reset interactions have real state evidence. Independent review clear; canonical gate passed: 255 SDK / 7,248 assertions, 37 harness / 210, two Chromium / 22 and 79.00% source lines (23,531 / 29,787). Merged PR #28. |
| SIWE | SIWE owner; coordinator integration; independent JWT-owner review | Canonical user-ID deletion; wallet schema/store/migration | Real EIP-191/ERC-1271 signatures, ownership, replay, expiry, concurrency, bans, dates and nonce aliases. Eleven SDK scenarios / 772 assertions; native wallet upgrade and rollback proofs. Review findings resolved. Full canonical gate passed: 238 SDK / 5,836 assertions, 37 harness / 210, two Chromium / 22, 78.65% source lines (22,225 / 28,257). Merged PR #25. |
| Device authorization | Coordinator; independent JWT-owner review | Unconstrained user reference migration; strict alias/TTL harness correction | Actual baseline failed 11 of 16 scenarios; repaired 19 SDK scenarios / 326 assertions. Async generators, Unicode boundaries, validation/lifetime/polling/URL profiles, installed upgrade preservation and destructive rollback are proved. Review findings resolved; old denial evidence retained with repeated denial. Canonical gate passed: 227 SDK / 5,064 assertions, 37 harness / 210 assertions, two Chromium / 22 assertions, 79.23% source lines (21,526 / 27,170). Merged PR #24. |
| Username availability | Phone owner; coordinator independent review/integration | Existing normalized username store | Real availability/taken lookup and unchanged persisted state, with exact empty-name rejection repaired. Canonical gate passed: 257 SDK / 7,272 assertions, 37 harness / 210, two Chromium / 22 and 79.00% source lines (23,533 / 29,790). Merged PR #29. |
| Two-factor disable | Phone owner; coordinator independent review/integration | Authoritative stored cookie sessions and atomic session issuance | Repaired API-key authority bypass and lost trusted session extensions; actual enrollment/trust/organization state and token retirement are proved. Canonical gate passed: 259 SDK / 7,374 assertions, 37 harness / 210, two Chromium / 22 and 79.21% source lines (23,646 / 29,853). Merged PR #30. |
| Multiple browser sessions | Phone owner; coordinator independent review/integration | Signed browser cookies and atomic session storage | List/select/revoke, same-owner retirement, configured limits, fallback, sign-out, preference and expiry have real state evidence. Duplicate-cookie and signed-empty proof review findings repaired. Canonical gate passed: 262 SDK / 7,568 assertions, 37 harness / 210, two Chromium / 22 and 79.30% source lines (23,849 / 30,076). Merged PR #31. |
| Phone numeric scenario scheduling | Coordinator; independent phone-owner review | Existing exact numeric bindings and fresh scenario resets | All 17 numeric samples, collision owner checks and 1,058 family assertions retained across three bounded cases. Default deadline and strict comparisons unchanged. Canonical gate passes: 264 SDK / 7,568 assertions, 37 harness / 210, two Chromium / 22 and 79.30% source lines (23,849 / 30,076). Merged PR #33. |
| Admin timestamp precision | JWT owner; coordinator independent review/integration | Existing core millisecond serializer | Deterministic six-digit stored fractions reproduce the official client parser shift; two admin serialization attributes fix read/update/list while preserving actual stored precision and both owners. Connected selected gate passed: 405 SDK / 18,164 assertions, 39 harness / 243, two Chromium / 22, 79.68% source lines (28,062 / 35,219). Merged PR #74 closes the earlier intermittent diagnostic; no clock tolerance changed. |
| Admin user deletion | Coordinator; independent phone-owner review | Shared closed-enum SQLite user-reference upgrade | Real factor enrollment, two credentials/sessions, guest/non-admin/self rejection, deletion/reuse and retained orphan factor have state evidence. Installed schema and existing device rollback tests pass. Canonical gate passed: 265 SDK / 7,604 assertions, 37 harness / 210, two Chromium / 22, 79.34% source lines (23,962 / 30,202). Merged PR #35. |
| Organization user invitations | Coordinator; independent SIWE-owner review | Adapter page policy and equivalent verification sender | Real verified HTTP ownership, selector rejection, expired/processed state and trusted server-only limit-before-filter behavior are required. Canonical gate passed: 268 SDK / 7,718 assertions, 37 harness / 210, two Chromium / 22, 79.25% source lines (23,962 / 30,237). Merged PR #36. |
| Organization metadata and selector lifecycle | Coordinator; independent phone/SIWE-owner review | Existing organization store and exact JSON writer | Parsed create/update projections omit only absent metadata; metadata/full getters retain exact raw JSON text. Default and teams profiles prove ownership, missing/blank selectors, denial token retirement, and persisted mutation readback. Canonical gate passed: 270 SDK / 7,974 assertions, 37 harness / 210, two Chromium / 22, 79.20% source lines (24,009 / 30,313). Merged PR #37. |
| Hosted canonical gate | Coordinator; independent JWT-owner review | Source-only Cargo cache and runner disk reservation | PR #34 hosted run 36785187757 completed successfully with the complete gate, unchanged coverage floor and optional configurations. |
| TOTP configuration and trusted generation | Phone owner; independent SIWE-owner review; coordinator integration | Existing factor/token crypto and equivalent private server API | Exact enrollment/provider issuers, reserved URI bytes, integer digits/period, zero defaults, disabled methods, short/Unicode UTF-8 secrets and real enrollment/login transitions are proved. Canonical gate passed: 274 SDK / 8,168 assertions, 37 harness / 210, two Chromium / 22, 78.97% source lines (24,009 / 30,402). Merged PR #38. |
| Atomic two-factor policy storage | Phone owner; coordinator independent review/integration | Nullable factor fields, migration registry and exact-row operations | Installed/fresh SQLite upgrades preserve enrollments and application schema. Eight independent connections prove failure snapshots, lock clearing/reset protection and one backup-code CAS winner; nullable arithmetic matches the actual pinned adapter. Canonical gate passed: 274 SDK / 8,168 assertions, 37 harness / 210, two Chromium / 22, 78.96% source lines (24,148 / 30,582). Merged PR #39; API enforcement is the next dependent capability. |
| Configured session updates | SIWE owner; independent JWT-owner review; coordinator integration | Immutable field policies, actual application columns and hook-aware storage bindings | Validation before authentication, two-stage transforms/defaults, plugin/adapter precedence, current-token-only updates, hidden-column privacy and replacement-field preservation have real SDK/native proof. Canonical gate passed: 277 SDK / 8,550 assertions, 37 harness / 210, two Chromium / 22, 78.97% source lines (24,668 / 31,238). Merged PR #40; broader storage modes remain explicit gaps. |
| Two-factor enrollment and verification policy | Phone owner; independent JWT-owner review; coordinator integration | Atomic factor storage and typed session-create cancellation | Real enrollment generations, per-challenge budgets, default/fractional/zero/disabled lockout, authenticated bypass/reset, backup CAS/replay and hook-cancellation state transitions are proved. Skip enrollment follows the source write order; genuine identical-message Forbidden errors retain their status. Canonical gate passed: 292 SDK / 9,344 assertions, 37 harness / 210, two Chromium / 22, 79.29% source lines (25,132 / 31,698). Merged PR #41; OTP codecs, passwordless and broader trust policy remain separate slices. |
| Organization creation policies | SIWE owner; coordinator independent review/integration | Existing organization/member store and immutable creation policy | Callback allow/limit decisions, numeric limits, trusted server creation, empty/default/custom creator roles and ownership have actual SDK/SQLite evidence. Rejections preserve rows and sessions; trusted calls bypass only the allow decision. Canonical gate passed: 298 SDK / 9,646 assertions, 37 harness / 210, two Chromium / 22, 79.23% source lines (25,161 / 31,757). Merged PR #42; hooks, custom organization entities/fields and concurrent admission remain explicit gaps. |
| Passwordless two-factor policies | Phone owner; independent JWT-owner review; coordinator integration | Authoritative cookie sessions, configured password provider and inherited method schemas | Social-only, mixed credential, empty-hash and explicit child overrides prove schema rejection, real enrollment/backup consumption, owner isolation and token rotation. Full canonical gate passed: 302 SDK / 9,798 assertions, 37 harness / 210, two Chromium / 22, 79.33% source lines (25,270 / 31,855). Merged PR #43; OTP codecs and guest disable validation ordering remain separate slices. |
| Organization input validation | SIWE owner; coordinator independent review/integration | Safe ordered JSON fields and explicit domain API errors | Create/update validate body fields and media before authentication or policy effects. Numeric/private metadata, long slugs, trusted creation, valid guest denial and unchanged organization/session state are proved. Full canonical gate passed: 306 SDK / 10,086 assertions, 37 harness / 210, two Chromium / 22, 79.18% source lines (25,397 / 32,076). Merged PR #44; nullable patches and selection policies remain separate slices. |
| Strict comparison and concurrent transport | Coordinator; independent JWT-owner review | Existing complete-value comparator and tracing fetch | Actual source custom generators prove prefix membership can be false on both runtimes; empty protected JWT selectors remain literal. Negative controls retain identity, key length/start, altered prefix, rotation and claims failures. Concurrent scenarios retain complete canonical transport in semantic outcome order. Full canonical gate passed: 306 SDK / 10,086 assertions, 39 harness / 243, two Chromium / 22, unchanged 79.18% source lines (25,397 / 32,076). Merged PR #45; OTP and passkey concurrency integration follows. |
| Two-factor OTP configuration | Phone owner; coordinator integration; independent phone-owner forward review | Plain/hash/encrypted/custom storage, configured generation/expiry/attempts, OTP enrollment and passwordless interaction have real SDK and persisted-state evidence. Full canonical gate passed: 316 SDK / 10,748 assertions, 39 harness / 243, two Chromium / 22, 79.38% source lines (25,562 / 32,203). Merged PR #46; factor/backup interoperability and guest disable ordering remain separate prepared slices. |
| Two-factor disable validation order | Phone owner; coordinator independent review/integration | Default and passwordless guest null/missing/valid schemas are proved before authoritative-session lookup; existing signed-owner/trust/organization rotation and API-key rejection remain required. Full canonical gate passed: 316 SDK / 10,762 assertions, 39 harness / 243, two Chromium / 22, 79.38% source lines (25,562 / 32,203). Merged PR #47. |
| Nullable admin ban expiry | Coordinator; independent SIWE-owner review | Public tri-state trusted patches preserve absent/null/date through serde and generated/manual actual SQLite stores. SQL NULL clears only expiry; bans, reasons, foreign users and sessions remain unchanged. Exact old failure reproduced. Full canonical gate passed: 316 SDK / 10,762 assertions, 39 harness / 243, two Chromium / 22, 79.38% source lines (25,567 / 32,208). Merged PR #48; duration replacement policy is the next dependent admin slice. |
| Reference/OpenAPI | SIWE owner; coordinator integration; independent SIWE-owner review | Immutable registered route/model metadata, configured application session fields and native custom-plugin fallback | Eleven complete document/reference scenarios and actual independent dispatch inventory passed. Source `/ok` metadata omissions and custom Rust operation identifiers retain distinct contracts. Full canonical gate passed: 327 SDK / 11,256 assertions, 39 harness / 243, two Chromium / 22, 79.95% source lines (26,998 / 33,768). Merged PR #49; minimal-builder default registration and further plugin configuration remain explicit boundaries. |


| Admin permission configuration | JWT owner; coordinator independent review/integration | Omitted versus empty roles, literal persisted grants and configured fallback | Four real differential owners and meaningful pre-fix failures; independent review clear. Connected admin stack full gate passed: 342 SDK / 12,140 assertions, 39 harness / 243, two Chromium / 22, 79.96% source lines (27,044 / 33,823). Merged PR #50. |
| Admin explicit-role initialization | JWT owner; coordinator independent review/integration | Permission configuration and actual native plugin initialization | Public builder tests preserve actual SQLite state, reject unknown explicit roles and prove later-bootstrap ordering. The connected stack canonical gate above includes this native owner. Merged PR #51; source factory timing is an explicit boundary. |
| Admin literal role input and creation authority | JWT owner; coordinator independent review/integration | Explicit-role initialization | Four differential flows distinguish literal comma/whitespace/empty role values, role-setting authority and nested input persistence. Meaningful old failures and independent review clear; connected stack gate passed. Merged PR #52. |
| Admin expired-ban response snapshots | JWT owner; coordinator independent review/integration | Actual persisted unban and session issuance | Two complete differential flows prove original user response fields, cleared stored authority, issued token ownership and unchanged acting/foreign users. Independent review clear; connected stack gate passed. Merged PR #53. |
| Admin duration and re-ban policy | JWT owner; coordinator integration; independent phone-owner review | Nullable expiry, original expired-ban snapshots | Five SDK owners prove fractional/negative/zero/NaN defaults, exact persisted durations, nullable single-write replacement, target-only revocation and typed invalid-date versus genuine application errors. Independent family review passes 22 / 928 assertions; connected stack canonical gate passed. Merged PR #54; native extreme-date and exact equality boundaries remain explicit. |


| Organization nullable logo patches | SIWE owner; coordinator independent review/integration | Existing ordered input schema and authenticated token | Omitted/null/empty/replacement logo values, blank current-token selection and unaffected sibling/foreign state are proved. Connected organization stack gate passed: 362 SDK / 13,476 assertions, 39 harness / 243, two Chromium / 22, 79.79% source lines (27,422 / 34,367). Merged PR #55. |
| Organization stored selection metadata | SIWE owner; coordinator independent review/integration | Nullable patch branch | Actual raw stored JSON text and current-token persistence retain their separate mutation/read projection contracts. Connected canonical gate passed. Merged PR #56. |
| Organization selection defaults | SIWE owner; coordinator independent review/integration | Ordered validation and stored projection | Guest schemas/media, selector precedence, explicit null, missing ID/member current-token cleanup and missing-slug preservation have real required evidence. Connected canonical gate passed. Merged PR #57. |
| Organization signed selection preferences | SIWE owner; coordinator independent review/integration | Authoritative token and signed cookie reader | First-cookie signature and duplicate behavior, cookie lifetime and real refreshed row state are proved. Connected canonical gate passed. Merged PR #58; broader cookie attributes remain explicit configuration boundaries. |
| Organization nullable metadata storage | SIWE owner; coordinator independent review/integration | Registry/store optional field and append-only migration m13 | SQL NULL versus JSON null, raw list/get/selection values, custom installed DDL preservation and failed rebuild rollback have native/SDK owners. The existing exact prepared-JSON integration owner was adapted without weakening its byte assertions. Connected canonical gate passed. Merged PR #59. |
| Organization creation lifecycle callbacks | SIWE owner; coordinator independent review/integration | Nullable metadata and existing team hooks | Seven SDK flows prove immutable actor/draft/member snapshots, supported patches, actual awaited ordering, partial writes on errors, trusted creation and sibling/foreign isolation. Connected canonical gate passed. Merged PR #60; HTTP-disconnect continuation remains an explicitly reproduced framework gap. |
| Organization deletion defaults and retained extensions | SIWE owner; coordinator independent review/integration | Scoped store transaction and closed two-table migration m14 | Five SDK owners, actual abort-trigger store rollback, installed custom-schema preservation and wrong per-table-commit negative control prove deletion scope, retained extensions/key validity, current-token clearing and rejection ordering. Connected canonical gate passed. Merged PR #61; FK-on source configurations, PostgreSQL runtime and migration-ledger commit boundaries remain documented. |

| Factor and default backup ciphertext | Phone owner; coordinator independent review/integration | Existing authenticated token crypto and exact-row consumption | Actual upstream decryption, imported enrollments, wrong-owner/replay and installed legacy reads are proved. Connected two-factor gate passed: 380 SDK / 14,736 assertions, 39 harness / 243, two Chromium / 22, 80.43% source lines (27,751 / 34,503). Merged PR #62; passwords remain scrypt only. |
| Nonpositive OTP rejection | Phone owner; coordinator independent review/integration | Factor persistence and actual OTP delivery | Zero/negative generation returns the exact empty 500 after authentication guards, with unchanged OTP/delivery/session state. Meaningful old wire failure and required evidence; connected canonical gate passed. Merged PR #63. |
| Configured backup codes and session policy | Phone owner; coordinator integration; independent JWT-owner review | Cipher interoperability, exact-row CAS and fixture receipt reset | Fractional/zero/negative generation, plain/encrypted/custom storage, duplicate consumption, stable regeneration, pending disableSession and callback attempt stages are proved. Connected canonical gate passed. Merged PR #64; extreme allocation and malformed installed JSON remain documented boundaries. |
| Configured two-factor trust lifetimes | Phone owner; coordinator integration; independent JWT-owner review | Immutable numeric policy and source snapshot-before-cleanup | Six explicit profiles prove fractional/zero/negative cookie and stored expiry, configured cleanup, foreign ownership, rotation, replay and expiration. Connected canonical gate passed. Merged PR #65; broader invalid-cookie and extreme-date branches remain explicit. |
| Authenticated OTP session cancellation | Phone owner; coordinator independent review/integration | Typed creation cancellation and original session fields | Consumed OTP/enabled user survive cancelled creation, original session survives and replay fails; successful rotation and same-message application errors remain distinct. Actual native hook-stage input controls and connected canonical gate passed. Merged PR #66; shared issuer stage-typing boundary remains documented. |

| Awaited admin ban messages | JWT owner; coordinator integration; independent phone-owner review | Actual stored-user callback and shared session policy | Runtime callback context, errors, expired-ban snapshots and clean current-entity fixture receipts are proved. Connected selected canonical gate above passed. Merged PR #67; generic callback/panic boundaries remain explicit. |
| Admin guest responses | JWT owner; coordinator independent review/integration | Local optional session lookup and existing cleanup headers | Missing, genuine tampered and revoked cookies reject all fifteen valid methods with exact empty JSON401 and unchanged real state; authenticated permission/success controls remain. Connected canonical gate passed. Merged PR #68; malformed schema ordering is a separate active slice. |
| Organization deletion hooks | SIWE owner; coordinator integration; independent phone-owner review | Scoped deletion store and immutable hook snapshots | Six public/trusted owners prove await order, current-token effects, before/after errors, original user/organization/headers and foreign isolation. Connected canonical gate passed. Merged PR #69; global trusted dispatch and custom projections remain explicit. |
| API-key getter/validator callbacks | Phone owner; coordinator independent review/integration | Actual immutable request context and quota storage | Full source callback ordering, cookie fallback, trusted verification, owner/quota and virtual-session behavior are required. Connected canonical gate passed. Merged PR #70; cache/secondary-storage modes remain separate. |
| API-key generation and forced cleanup | Phone owner; coordinator independent review/integration | Ordered permissions and existing locked dependencies | Actual custom generation/defaults, ownership/permissions, callback failures, forced global deletion and SQL abort/retry are proved. Connected canonical gate passed. Merged PR #71; automatic background timing, global throttle and lone UTF16 surrogate behavior remain explicit. |
| Passkey ceremony lifecycle | Phone owner; coordinator independent review/integration | Real ES256 proof and atomic credential/session storage | Freshness, schema/crypto consumption order, expiry/replay and overlapping single winners have actual required evidence. Connected canonical gate passed. Merged PR #72; wider RP/origin/cookie settings remain separate. |
| Passkey trusted registration callbacks | Phone owner; coordinator independent review/integration | Verified immutable registration facts and session creation | Guest resolver/authenticated owner/name/session policy, typed cancellation, genuine callback errors and actual credential/session rollback are proved. Connected canonical gate passed. Merged PR #73; broader custom storage and authentication callbacks remain explicit. |
| Accepted Axum dispatch continuation | Phone owner; independent JWT-owner and coordinator review | Existing creation/deletion lifecycle owners | Merged PR #76. Actual TCP disconnect flows, lazy runtime reuse, persisted completion and tracing pass the connected canonical gate. The runtime-transition regression uses an isolated SQLite file after proving the former memory database lost tables when its last connection closed. Runtime/process shutdown remains explicit. |
| Encrypted account-cookie evidence | Coordinator; independent JWT-owner review | Published symmetricEncodeJWT/symmetricDecodeJWT and complete claims | Merged PR #75. Actual TS-self failure and literal-header negative controls repaired; connected canonical gate passes 40 harness tests / 289 assertions. No fields, lifetimes or exceptions are weakened. |
| Account-cookie encryption and One Tap configuration | SIWE owner; coordinator and independent phone-owner review | Complete published-decoded JWE claims and prepared One Tap | Merged PRs #81–82 implement CBC-HS512/HKDF, full built-in claims, empty-string array audiences and retained-token combinations. Independent Base64-alias finding repaired with actual issued cookies and authenticated ownership; 15 One Tap scenarios / 832 assertions pass. Connected canonical gate passed: 448 SDK / 22,946 assertions, 41 harness / 317, two Chromium / 22 and 79.1492% source lines. Compression/chunks/attributes/secret rotation/custom projection remain explicit. |
| Organization update hooks | SIWE owner; coordinator and independent phone-owner review | Additive optional store update and immutable lifecycle contexts | Merged PR #86. Seven SDK owners / 452 assertions prove trusted patches, authority, awaited callbacks, real deletion/no-row results and before/after error persistence. Focused organization/OpenAPI 82 / 5,002, native API/SeaORM and public consumer checks pass. Connected canonical gate passed: 448 SDK / 22,946 assertions, 41 harness / 317, two Chromium / 22 and 79.1492% source lines. |
| Admin validation ordering | JWT owner; coordinator independent review | Private endpoint schema/media parser and local business email validation | Merged PR #85. Structural validation precedes authentication/permissions; exact coercion and email business order have genuine before-failure and persisted-state proof. Admin 34 / 3,024 plus native, strict Clippy and TypeScript pass. Combined final gate pending; repeated query values remain explicit. |
| Invalid two-factor trust cookies | Phone owner; coordinator independent review | Existing trust reader and immutable cleanup policy | Merged PR #84. Invalid outer proofs do not delete cookies; authenticated inner proofs enforce ownership, lookup/cleanup, rotation and replay. A genuine combined-run late timestamp failure led to six bounded real lifecycles, retaining all cases, rows, transports and the 1.5-second comparator. Full focused factor family 67 / 4,908 passes. Connected canonical gate passed: 448 SDK / 22,946 assertions, 41 harness / 317, two Chromium / 22 and 79.1492% source lines. |


| OAuth scope preservation | Coordinator; independent SIWE-owner review | Existing local provider fixture | Merged PR #77 preserves an existing granted scope when the new provider response omits scope. Actual before-failure and persisted account readback pass. |
| Atomic OAuth user/account creation | Coordinator; independent SIWE-owner review | Transactional existing user/account store | Merged PR #78 rolls back both new records after an actual SQL account veto and permits a genuine retry. |
| OAuth implicit-link profile policy | Coordinator; independent SIWE-owner review | Existing linked-account and user policy | Merged PR #79 updates the linked user only under the configured policy; account/user ownership and existing sessions are retained. |
| One Tap | SIWE owner; coordinator and independent phone-owner review | Local signed Google JWKS and OAuth/account-cookie prerequisites | Merged PR #80 includes the actual route and registered fixture. Official-client signed token, owner, signup, ban, two-factor and configuration evidence passes; cookie/configuration layers are merged PRs #81–82. |
| Literal URL selectors | Coordinator; independent phone-owner review | Strict parsed-URL comparison | Merged PR #83 preserves literal empty/whitespace URL selectors while generated identity fields remain strict. Full harness 41 / 317 and TypeScript pass; connected canonical gate passed. |
| Passkey public authentication snapshots | JWT owner; coordinator and independent phone-owner review | Real ES256 assertions and actual credential update | Merged PR #87 preserves registration device/backup snapshots while verified counters and opaque credentials advance. Focused family 11 / 900 passes; connected canonical gate and required evidence pass. Eligibility upgrades are a measured separate verifier-policy gap. |
| Member-role normalization | SIWE owner; coordinator independent review | Existing invitation and membership storage | Merged PR #88 stores normalized string/array roles without dropping duplicates. Genuine before-failure and public readback pass. |
| Member-role lifecycle hooks | SIWE owner; coordinator review; independent JWT-owner review | Optional-row member store and normalization | Merged PR #89 implements awaited callbacks, target-user snapshots and trusted patches. Six SDK owners / 434 and organization/OpenAPI 89 / 5,466 pass; native zero-row/SQL-error proofs pass. Connected canonical gate and required evidence pass; empty input and body/auth ordering follow in the next reviewed slice. |
| Passkey authentication callbacks | JWT owner | Verified immutable authentication facts | Reviewed frozen 108cd739; coordinator and independent phone-owner review clear. Six genuine signed owners prove callback errors, consumption, full input identity and original verified session ownership despite trusted credential reassignment. Focused passkey 17 / 1,336 passes; next gate pending. |
| Member-role input/auth ordering | SIWE owner | Member lifecycle hooks and existing nested-session policy | Reviewed frozen 2f62e75b; coordinator review clear, independent JWT-owner review pending. Five owners prove schema/media, empty-role/selector precedence, exact Unauthorized, actual row cleanup and sibling/foreign state. Organization/OpenAPI 94 / 6,044 passes. Merged PR #90; complete 460-scenario gate passed. Remaining: nested middleware erases session-fetch errors upstream while later storage/hook errors remain visible. |
| Repeated admin query validation | Coordinator; independent phone-owner review | Ordered query values across actual Axum/dispatch and route-local schemas | Reviewed frozen a4549d07. Source/self 1 / 90 and full admin 35 / 3,114 pass, along with native core/admin/Axum, strict Clippy and TypeScript. Before-repair flattening returned 401 instead of array validation 400. Merged PR #91; complete 460-scenario gate passed. Remaining: accepted filter arrays and other query consumers remain separate. |
| API-key automatic background cleanup | Phone owner; independent JWT-owner and coordinator review | Hot owned task completion and module-global real-clock throttle | Frozen c8bee0bf; API-key SDK 46 / 2,182, source controls 6 / 596, native 52 and strict build checks pass. Genuine old awaited response and generator-order failures preserved. Central integration gate pending; individual-row deferral is separate. |

Full local compatibility/coverage gates and inventory mutations are serialized.
Workers use separate worktrees, ports, databases and logs. Old unpublished dirty
prototypes are preserved; only reviewed family-scoped changes are extracted.


## Remaining success gaps and route families

All eight originally reported routes now have real successful-flow evidence.
Organization user invitations and admin removal passed their integrated gates,
including authorization and persisted state checks. This closes those evidence
gaps without claiming all configurations of the feature families.

Remaining inventoried families include anonymous authentication/deletion,
OAuth proxy. One Tap is merged PR #80. Organization get-organization is now implemented with real evidence.
Prepared old prototypes do not count as integrated capability completion.

## Explicit unresolved target beyond routes

The upstream audit enumerates remaining core configuration, cookie/cache/storage
modes, hooks/server-only operations, middleware plugins, plugin interactions,
OAuth popup, built-in/generic provider defaults and Redis-storage runtime modes.
OAuth authorization server/MCP/CIMD, SSO, SCIM, Stripe, i18n, Expo and Electron
are explicitly excluded at the user’s request, rather than outstanding tasks.
Framework/client, database-adapter and runtime-tooling boundaries are also
accounted for there. None is silently excluded by the route inventory.

The organization raw-metadata getter difference is repaired. Specific known gaps
include create/update input validation, further callbacks and fields; anonymous OAuth linking without the
state cookie; minimal-builder automatic core registration and wider session-field storage
modes; secondary/custom storage branches; and unproven optional configurations
listed in each family audit. These need implementation or explicit equivalence
evidence before full parity can be claimed.

Completion requires resolved independent findings, every applicable success,
rejection, authorization and lifecycle transition, configuration/interactions,
and a passing final canonical gate at the 75% source coverage floor. Existing
green routes do not close the complete target.

## Latest connected validation

The reviewed OAuth/One Tap/transport tree 83b4fc4c passed the complete canonical
gate: 421 SDK scenarios / 19,052 assertions, 40 harness tests / 289 assertions,
two Chromium tests / 22 assertions and 79.4851% source lines (28,528 / 35,891).
Default/optional native configurations, Rustls, Redis, locked fixtures, TypeScript,
docs and LLVM coverage all passed. These numbers belong to that tree.

The following trust/admin/update-hook integration passed 435 of 436 SDK scenarios
but failed the canonical gate on a late trust replay timestamp. It is not a
passing gate. All original trust behavior is retained in six shorter fresh
lifecycles; the repaired integration, including passkey/member slices, is awaiting
its canonical result. No full-parity claim is made.

The 448-scenario reviewed integration passed the entire canonical gate on
9dd39eca and is now delivered through PR #89. Its 22,946 SDK assertions,
41 harness tests / 317 assertions, two Chromium tests / 22 assertions and
79.1492% source lines (28,819 / 36,411) were measured on that exact tree.
Squash/rebase publication preserved its complete tree, and merged master
49579c09 was compared equal. Earlier failed timing evidence remains recorded
above as historical evidence; it does not describe the repaired result.

The next integrated tree adds reviewed authentication callbacks, member-role
HTTP input/cleanup and repeated admin query validation. Its full gate is pending.
Unicode role normalization, source-compatible WebAuthn UV/backup/origin policies,
member removal lifecycle and automatic API-key cleanup are active owners.

## Delivered validation and current next wave

PRs #90–92 are merged: verified passkey authentication callbacks, ordered
member-role HTTP input/session semantics, and repeated admin query validation.
Master b676a5fe is full-tree equal to the tested 3311ff51 integration. The full
canonical gate passed 460 SDK scenarios / 24,072 assertions, 41 harness tests /
317 assertions, two Chromium tests / 22 assertions and 79.0773% source lines
(28,917 / 36,568). All native configurations, Rustls/Redis builds, TypeScript,
strict Clippy and documentation checks passed.

The next integration contains independently reviewed Unicode member-role input
(2b8ca3dc), automatic API-key background cleanup (c8bee0bf), and typed Source
passkey authentication policy (1f21591c). Unicode focused members pass 17 / 1,216;
passkeys pass 24 / 2,164, including genuine signed UV/backup/origin negatives,
replay and actual public counter increase/decrease. The existing locked core
0.5.4 dependency is wired directly without any dependency version changes.
Required evidence is additive and the raw exception list remains empty.

Member removal is actively owned by the organization agent, with immutable
callback snapshots and scoped transactional membership/team cleanup contracts.
Deferred individual API-key deletion and UV-absent passkey registration follow
the current frozen slices. The coordinator is investigating accepted admin
filter arrays using the actual pinned SQLite runtime. These remain unresolved
until implemented, independently reviewed and integrated through the full gate.
