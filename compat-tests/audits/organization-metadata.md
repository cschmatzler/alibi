# Organization metadata lookup (Better Auth 1.7.6)

This prerequisite implements `GET /organization/get-organization`, independently
of full-organization retrieval and its members, invitations and teams.

Pinned source is `better-auth/dist/plugins/organization/routes/crud-org.mjs`
(`getOrganization`), `call.mjs` (`orgSessionMiddleware`), and `adapter.mjs`
(`findOrganizationById`, `findOrganizationBySlug`, `setActiveOrganization`).
The official client invokes the real endpoint against both implementations.

A valid session is required; absence returns `401` with `UNAUTHORIZED` and
`Unauthorized`. A nonempty slug takes precedence over a nonempty ID; otherwise
lookup uses the current session's active organization. Empty strings behave as
omitted selectors. No selection returns JSON null. Missing organizations return
`400 ORGANIZATION_NOT_FOUND` and retain active session state. Existing foreign
organizations return `403 USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` and clear
only the authenticated session token's active organization. Membership is read
from storage using the authenticated principal, before any organization data is
returned. Other sessions for the same user retain their independent selection.

Unlike create/full responses, this metadata-only endpoint returns metadata as its
raw stored JSON string. Omitted metadata returns null, explicit `{}` returns
`"{}"`, and an object such as `{ "tier": "gold" }` returns its serialized JSON
string. Creation now stores omitted metadata as JSON null, and parsed responses
preserve explicit empty objects. No entity columns, migrations or existing rows
are rewritten. Older Rust rows stored omitted metadata as `{}`; absence cannot
be reconstructed from those values. Such rows remain empty objects in parsed
responses and `"{}"` in the new metadata-only response.

Two official-client scenarios own wire behavior, selectors, default/team-enabled
configuration, raw metadata, and denied-token persistence. The SQL-backed
`readUserState` helper exposes its existing session projection plus the actual
`activeOrganizationId`; it neither seeds a receipt nor substitutes session state.
The tests prove an unrelated same-user session survives denial, successful reads
omit full-organization relations, and missing selectors preserve stored sessions.

The native SQLite/public-handler test owns only the deliberately blank ID
selector and unchanged stored session. The differential identity harness rejects
blank identity-shaped query values even when both runtimes match, so the SDK
retains the blank-slug control while this one literal-ID case uses the native
boundary. Comparator rules and exclusions are unchanged.

Both regression controls were observed before repair: the original Rust endpoint
returned 404 while TS returned null, and restoring the old empty-object
normalization made the SDK fail because explicit `{}` disappeared from creation.
The logs are `/tmp/organization-metadata-baseline.log` and
`/tmp/organization-metadata-empty-baseline.log` in the implementation workspace.
The existing three organization core lifecycle scenarios also validate parsed
response compatibility. Focused results are recorded with the frozen commit;
full gates, inventory and final publication belong to the coordinator.

Focused validation: both new SDK scenarios and all three existing organization
core scenarios pass (alongside nine OpenAPI scenarios: 14 scenarios / 576
assertions). The native blank-selector test, client TypeScript check and strict
production Clippy for root/core/API/SeaORM pass.
