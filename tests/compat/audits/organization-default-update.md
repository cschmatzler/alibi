# Default organization updates against Better Auth 1.7.6

The unchanged pinned `dist/plugins/organization/routes/crud-org.mjs`
`updateOrganization` checks session, organization selection, membership,
permission and duplicate slug before calling the organization adapter. The
adapter's `updateOrganization` (`adapter.mjs:352–369`) returns null when the
actual update returns no organization. It does not install an update callback
when the plugin's hook option is absent.

The primary official-client owner is
`tests/organization-extensions/update-default-storage.test.ts`. Its empty,
schema-valid patch reaches the real Bun/Kysely prepared query; the reference
server logs `SQLiteError: near "where": syntax error`. The actual response is
HTTP 500, body `""`, with no Content-Type. An ordinary retry succeeds. A real
SQL ABORT veto independently returns the same empty-500 response and retains
all stored rows. Foreign-user and member denial, guest authentication and a
duplicate slug all reject before that failing update, retaining physical state.
The retry selects the sibling token's active organization through a blank
selector, clears a nullable logo and preserves exact stored metadata.

A SQLite BEFORE UPDATE trigger separately exercises RAISE(IGNORE) without
changing any row and independently committed deletion of the selected
organization, its members and invitations during the attempted UPDATE. The
owner membership exists in the pre-request physical snapshot; neither branch
runs an organization update callback. Both return HTTP 200 with exact body
`"null"` and Content-Type `application/json`. The deletion's final physical
snapshot proves absence, while the ignore snapshot proves that no row was
changed. Snapshot member queries use a LEFT JOIN so dangling memberships cannot
be hidden by a missing organization. Users, unrelated organizations, unrelated
members and every issued owner/sibling/foreign session are observed and retained.

## Storage and compatibility

The additive public `OrganizationStore::patch_organization_if_present` operation
stages exactly the supplied patch columns through SeaQuery. It uses the same
query builder for ordinary and empty patches: no injected malformed SQL,
synthetic database error, or timestamp-only update produces the empty branch.
Prepared-query errors remain real `AuthError::Database` values. The default
organization HTTP route alone represents those errors as the source's empty
500. On returning backends, an actual absent RETURNING row becomes None. On
backends without RETURNING, successful execution is followed by a physical
lookup; a zero changed-row count alone cannot classify an unchanged MySQL row
as absence. Generic database/backend guarantees remain tracked by #192.

The native `update_organization` method and its signature/missing-row behavior
remain intact. The new operation defaults to NotImplemented, explicitly
requiring custom OrganizationStore implementations that serve the default HTTP
update route to implement the bounded patch contract. This is an intentional
adapter migration requirement, rather than silently guessing absence from a
custom store's error. PluginStore forwards it. MemoryStore's already unsupported
organization mutations remain unsupported. SeaOrmStore's bounded patch writes
bundled organization columns directly and does not dispatch ActiveModel model
callbacks or change its native-only updated_at column. The existing configured
organization hook path still uses `update_organization_if_present`, retaining
ActiveModel before_save/after_save and the before/after organization callbacks.
The bundled ActiveModelBehavior is empty; custom physical organization models
are outside the existing schema API's promise.

The distinct native public-store owner
`organization_database_patch_retains_unrequested_native_columns` confirms
preserved native timestamps and metadata, nullable logo, a genuine empty-query
Database error with readback and deleted-row absence. The existing native
optional-update owner protects the original update method's missing-row error. Existing update-patch and update-hook scenarios own
raw metadata normalization, patched callback values and callback ordering;
these are not reimplemented as synthetic test-store behavior.

## Regression evidence

The unchanged pinned runtime passes both official-client scenarios (122
assertions), including wire-body/Content-Type receipts captured by the official
client's onResponse callback. The strict comparator also compares request and
response transport, headers and cookie protection with its existing rules.
The original Rust production code fails both scenarios: the empty patch wrongly
succeeds and the genuine zero-row update wrongly returns an error. These failures
were recorded before applying the production changes, with the same fixtures
and comparator. After repair both pass. Independent production review checked
permission ordering, the absence/error distinction and preservation of configured
hook behavior. Broader checks and exact run results are recorded in the PR.
