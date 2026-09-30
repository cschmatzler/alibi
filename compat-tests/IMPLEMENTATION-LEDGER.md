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
| Multiple browser sessions | Phone owner; coordinator independent review/integration | Signed browser cookies and atomic session storage | List/select/revoke, same-owner retirement, configured limits, fallback, sign-out, preference and expiry have real state evidence. Duplicate-cookie and signed-empty proof review findings repaired. Canonical gate passed: 262 SDK / 7,568 assertions, 37 harness / 210, two Chromium / 22 and 79.30% source lines (23,849 / 30,076). Ready for publication. |
| Reference/OpenAPI | SIWE owner | Typed route/model metadata and application schema override | Pinned generator/runtime/configuration investigation complete; generator and reference implementation underway. Default document remains incomplete until update-session lands; equivalent disabled-path profiles only prove that explicit configuration. |

Full local compatibility/coverage gates and inventory mutations are serialized.
Workers use separate worktrees, ports, databases and logs. Old unpublished dirty
prototypes are preserved; only reviewed family-scoped changes are extracted.

## Remaining success gaps and route families

The integrated tree has two remaining successful-flow gaps: organization user
invitations and admin removal. Each
has a prepared reviewed implementation/evidence slice awaiting its integrated
gate. Device approval/denial/token and GET /ok have real successful evidence.

Remaining inventoried families include anonymous authentication/deletion,
update-session,
OAuth proxy, One Tap, organization get-organization, and reference/OpenAPI.
Prepared old prototypes do not count as integrated capability completion.

## Explicit unresolved target beyond routes

The upstream audit enumerates remaining core configuration, cookie/cache/storage
modes, hooks/server-only operations, middleware plugins, plugin interactions,
OAuth popup, built-in/generic provider defaults, and the separate OAuth-provider,
MCP, CIMD, SSO, SCIM, Stripe, i18n, Expo, Electron and Redis-storage packages.
Framework/client, database-adapter and runtime-tooling boundaries are also
accounted for there. None is silently excluded by the route inventory.

Specific known gaps include organization get-full metadata returning an object
where upstream returns stored JSON text; anonymous OAuth linking without the
state cookie; default OpenAPI completeness and additional session-field update
policy; secondary/custom storage branches; and unproven optional configurations
listed in each family audit. These need implementation or explicit equivalence
evidence before full parity can be claimed.

Completion requires resolved independent findings, every applicable success,
rejection, authorization and lifecycle transition, configuration/interactions,
and a passing final canonical gate at the 75% source coverage floor. Existing
green routes do not close the complete target.
