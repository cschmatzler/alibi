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
| Intermittent admin creation timestamp | Coordinator; independent JWT-owner investigation | Existing impersonation/list-users scenario | One full run reported a list-user createdAt mismatch; focused admin and a subsequent complete gate passed without comparator/source changes. Exact observation remains under investigation in `/tmp/phone-numeric-evidence-canonical.log`; no unexplained timestamp difference is treated as parity evidence. |
| Admin user deletion | Coordinator; independent phone-owner review | Shared closed-enum SQLite user-reference upgrade | Real factor enrollment, two credentials/sessions, guest/non-admin/self rejection, deletion/reuse and retained orphan factor have state evidence. Installed schema and existing device rollback tests pass. Canonical gate passed: 265 SDK / 7,604 assertions, 37 harness / 210, two Chromium / 22, 79.34% source lines (23,962 / 30,202). Merged PR #35. |
| Organization user invitations | Coordinator; independent SIWE-owner review | Adapter page policy and equivalent verification sender | Real verified HTTP ownership, selector rejection, expired/processed state and trusted server-only limit-before-filter behavior are required. Canonical gate passed: 268 SDK / 7,718 assertions, 37 harness / 210, two Chromium / 22, 79.25% source lines (23,962 / 30,237). Merged PR #36. |
| Organization metadata and selector lifecycle | Coordinator; independent phone/SIWE-owner review | Existing organization store and exact JSON writer | Parsed create/update projections omit only absent metadata; metadata/full getters retain exact raw JSON text. Default and teams profiles prove ownership, missing/blank selectors, denial token retirement, and persisted mutation readback. Canonical gate passed: 270 SDK / 7,974 assertions, 37 harness / 210, two Chromium / 22, 79.20% source lines (24,009 / 30,313). PR #37 ready for publication. |
| Hosted canonical gate | Coordinator; independent JWT-owner review | Source-only Cargo cache and runner disk reservation | PR #34 hosted run 36785187757 completed successfully with the complete gate, unchanged coverage floor and optional configurations. |
| Reference/OpenAPI | SIWE owner | Typed route/model metadata and application schema override | Frozen source metadata, reference page and complete default/custom-session documents are ready for coordinator integration after update-session. Eleven document scenarios / 494 assertions and sixteen session scenarios / 696 assertions pass; integrated canonical gate remains pending. |

Full local compatibility/coverage gates and inventory mutations are serialized.
Workers use separate worktrees, ports, databases and logs. Old unpublished dirty
prototypes are preserved; only reviewed family-scoped changes are extracted.

## Remaining success gaps and route families

All eight originally reported routes now have real successful-flow evidence.
Organization user invitations and admin removal passed their integrated gates,
including authorization and persisted state checks. This closes those evidence
gaps without claiming all configurations of the feature families.

Remaining inventoried families include anonymous authentication/deletion,
update-session,
OAuth proxy, One Tap, and reference/OpenAPI. Organization get-organization is now implemented with real evidence.
Prepared old prototypes do not count as integrated capability completion.

## Explicit unresolved target beyond routes

The upstream audit enumerates remaining core configuration, cookie/cache/storage
modes, hooks/server-only operations, middleware plugins, plugin interactions,
OAuth popup, built-in/generic provider defaults, and the separate OAuth-provider,
MCP, CIMD, SSO, SCIM, Stripe, i18n, Expo, Electron and Redis-storage packages.
Framework/client, database-adapter and runtime-tooling boundaries are also
accounted for there. None is silently excluded by the route inventory.

The organization raw-metadata getter difference is repaired. Specific known gaps
include create/update input validation, further callbacks and fields; anonymous OAuth linking without the
state cookie; default OpenAPI completeness and additional session-field update
policy; secondary/custom storage branches; and unproven optional configurations
listed in each family audit. These need implementation or explicit equivalence
evidence before full parity can be claimed.

Completion requires resolved independent findings, every applicable success,
rejection, authorization and lifecycle transition, configuration/interactions,
and a passing final canonical gate at the 75% source coverage floor. Existing
green routes do not close the complete target.
