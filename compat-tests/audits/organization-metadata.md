# Organization metadata lookup (Better Auth 1.7.6)

This prerequisite implements `GET /organization/get-organization`, and repairs full-organization lookup, authorization ordering and raw metadata.

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

Both lookup endpoints return metadata as its raw stored JSON string;
create and update responses retain parsed metadata. Omitted metadata returns null, explicit `{}` returns
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
full gates and final publication belong to the coordinator.

Review also demonstrated and repaired exact JavaScript numeric serialization,
full retrieval returning parsed metadata, missing full organizations returning
membership errors, and denied full retrieval retaining the current selection.
The full handler now fetches the organization before its membership check and
clears only the requesting token on denial. Independent review confirmed that
another same-user session remains unchanged and foreign data is never returned.

Before-repair logs: `/tmp/organization-metadata-numbers-before.log`,
`/tmp/organization-full-metadata-before.log`,
`/tmp/organization-full-lookup-order-before.log`, and
`/tmp/organization-full-denied-session-before.log`.
Focused final validation: 25 SDK scenarios / 1,440 assertions including both
lookup scenarios and existing organization/team/dynamic-role families, plus the
native blank-selector contract for both actual routes. Logs are
`/tmp/organization-metadata-reviewed-final.log` and
`/tmp/organization-metadata-blank-final.log`. The client TypeScript check and
strict production Clippy passed before the final reviewed handler adjustments;
the canonical integrated gate must validate the final tree.

Custom adapter internal query ordering and physical SQL NULL versus JSON null
storage are not established by these SQLite response and lifecycle tests.

Independent creation-policy review also exposed absent-metadata update responses:
upstream omits metadata while Rust emitted null. The mutation handler now shares
the parsed response projection with create, preserving every base field while
omitting only missing metadata. Getter/full/list policies remain separate.
The existing official-client selector scenarios now update absent, empty and
populated metadata organizations and verify actual stored names/metadata through
getters. Both profiles fail on the prior owner solely at the missing-field
assertion (`/tmp/organization-update-metadata-absence-before.log`); the repair
passed 28 organization scenarios / 1,582 assertions
(`/tmp/organization-update-metadata-absence-after.log`). Independent review is
clear; the final gate includes additional persisted-name assertions. Default
create/update metadata input-type validation is a separate confirmed branch
under investigation by the organization owner.
