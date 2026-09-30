# Better Auth 1.7.6 implementation ledger

This ledger tracks implementation and unresolved evidence. It is not a parity
completion claim. The full runtime target, including capabilities absent from
selected HTTP profiles, is in [the upstream audit](audits/upstream-target.md).
The oracle remains pinned to 1.7.6. Rust interfaces remain native.

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
| JSON and SQLite numeric semantics | Phone owner; independent JWT-owner review and repair | Common JSON parser, safe callback representation, numeric binding | Frozen prototype withheld after actual runtime review exposed reserved-key corruption and JWT numeric/date differences. Replacing unsafe global serde features with explicit `JsValue`, safe metadata persistence and JS serialization. Repaired review/gate still required. |
| Phone authentication | Phone owner; coordinator contracts/integration | Safe numeric prerequisite, identity fields, verification/session helpers | Prepared production and deterministic SMS/server-only fixtures; completing extraction after prerequisite repair. All five routes, consumption API, proof/attempt/expiry/replay/ownership, optional signup, custom verifier and two-factor interactions require final integrated evidence. |
| SIWE | SIWE owner; coordinator integration; independent JWT-owner review | Canonical user-ID deletion prerequisite; wallet schema/store/migration | Canonical ID prerequisite merged as PR #23. Real EIP-191/local ERC-1271 and wallet/session persistence pass eleven SDK scenarios / 724 assertions. Independent review resolved media validation before state consumption and all-digit hour-24 date validation; focused Rust/SQL/Clippy/TypeScript pass. Inventory integrated; canonical gate/publication remain. |
| Device authorization | Coordinator; independent JWT-owner review | Unconstrained user reference migration; strict alias/TTL harness correction | Actual baseline failed 11 of 16 scenarios; repaired 19 SDK scenarios / 326 assertions. Async generators, Unicode boundaries, validation/lifetime/polling/URL profiles, installed upgrade preservation and destructive rollback are proved. Review findings resolved; old denial evidence retained with repeated denial. Canonical gate passed: 227 SDK / 5,064 assertions, 37 harness / 210 assertions, two Chromium / 22 assertions, 79.23% source lines (21,526 / 27,170). PR #24. |
| Reference/OpenAPI | SIWE owner | Typed route/model metadata and application schema override | Pinned generator/runtime/configuration investigation complete; generator and reference implementation underway. Default document remains incomplete until update-session lands; equivalent disabled-path profiles only prove that explicit configuration. |

Full local compatibility/coverage gates and inventory mutations are serialized.
Workers use separate worktrees, ports, databases and logs. Old unpublished dirty
prototypes are preserved; only reviewed family-scoped changes are extracted.

## Remaining success gaps and route families

The merged baseline still needs real successful flows for organization user
invitations, admin removal, device approval/denial/token, username availability,
and two-factor disable. Device repair above closes its three gaps only after
integration. GET /ok already has successful evidence.

Remaining inventoried families include anonymous authentication/deletion,
multiple-session listing/activation/revocation, update-session, phone, SIWE,
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
