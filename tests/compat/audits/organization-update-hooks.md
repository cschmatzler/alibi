# Organization update hooks against Better Auth 1.7.6

Pinned `dist/plugins/organization/routes/crud-org.mjs:188-235` validates the
request before authentication, resolves the current actor and actual membership,
checks update permission and the initially supplied slug, then awaits the before
hook, adapter write and after hook. The before callback receives the validated
PATCH as `organization`, not a stored organization. The after callback receives
parsed adapter output, including null when no row was updated. Actor and member
arguments keep their original values across independently committed hook writes.

`OrganizationConfig.update_hooks` captures an immutable application-owned Arc.
Public `OrganizationUpdateHooks` has default no-op before/after methods;
`OrganizationUpdateContext` carries the original core patch, actor UserView and
canonical Member. `OrganizationUpdatedContext.organization` is an optional parsed
`CreatedOrganizationResponse`. Typed `OrganizationUpdatePatch` supports bundled
name/slug/logo/metadata overrides. A missing patch field preserves validated
input; logo `Some(None)` clears it. Metadata `Some(None)` writes literal JSON null,
not SQL NULL: `dist/plugins/organization/adapter.mjs:352-368` JSON-stringifies
null because its JavaScript type is object. Empty metadata stores `{}` and absent
metadata keeps the original patch. This differs from the creation hook's
explicitly supported falsy-null policy.

Hook patches merge after initial validation and permission checks without another
schema/slug validation pass, matching source. A before-hook error stops the
adapter operation; an after-hook error retains its committed write. No new
lifecycle transaction or authority from public `userId`/request privilege fields
is introduced. The update-only duplicate-slug guard now uses the source's exact
400 `ORGANIZATION_SLUG_ALREADY_TAKEN` code/message before invoking callbacks.
The separate check-slug endpoint is unchanged.

## Additive storage contract

`OrganizationStore::update_organization_if_present(id, update)` returns an actual
updated row or `None` for no row; other failures remain errors. Its default and
unsupported MemoryStore implementation fail closed with NotImplemented.
PluginStore forwards the operation. SeaOrmStore shares the existing typed
column staging and executes `ActiveModelTrait::update`, preserving before_save
and after_save dispatch (`sea-orm 2.0.0-rc.37 src/entity/active_model.rs:337-345`).
Only a real `RecordNotUpdated` result maps to absence; query/model errors remain
errors. Bundled organization ActiveModelBehavior is currently empty; custom
organization model replacement is not promised by the existing schema API.
The original public `update_organization` API and missing-row error behavior
remain intact. The optional model-hook operation is used only by configured update hooks.
The default path has a separate bounded column-patch operation; see
[the default-update audit](organization-default-update.md).

The native primary owner invokes this real public store against migrated SQLite:
actual update/readback, SQL ABORT veto with unchanged row, SQL IGNORE zero-row
RETURNING result with unchanged row, deletion followed by genuine absence,
original API error behavior and a fully preserved unrelated organization. Source
runtime `/tmp/organization-update-ignore-source-probe.log` independently confirms
that a real pinned SQL IGNORE returns HTTP200null and calls the after hook with
null while its organization row remains unchanged. Missing-row lookup and
zero-row update are separately exercised, not simulated by a fake adapter.

## Evidence and test ownership

`tests/organization/update-hooks.test.ts` is the primary official-
client owner. Seven scenarios observe actual callback receipts and physical SQLite
rows on both servers: supported patches/parsed output, before/after rejection
ordering, validation/authentication/foreign membership/duplicate guards before
callbacks, original authority snapshots despite independently changed user and
member rows, real before-hook organization deletion and HTTP200null after result,
an actually awaited async callback before any SQL mutation, and raw Infinity,
negative Infinity and signed-zero metadata observed by the callback before JSON
normalization. Later requests
use the stored downgraded membership and are denied before callbacks. Sibling
sessions and foreign organizations retain their complete observed rows.

The application-controlled private fixtures deliver receipts only from actual
registered callbacks, capture actual snapshots at those phases, and execute real
store/adapter writes. No request field selects a hook or trusted actor. The
missing-row callback uses Rust's public organization store deletion and the
corresponding source member/invitation/organization adapter deletes, retaining
source original callback snapshots. Async release uses a separate tracing fetch
and appends its complete transport record after the pending update, preserving
both requests without comparing incidental concurrent completion order.

`/tmp/organization-update-member-hooks-source-probe.log` records the actual
unchanged pinned callbacks, trusted patch/null semantics, before/after errors and
independent row deletion. `/tmp/org-update-hooks-sdk-before.log` reruns the new
owner with only callback execution removed from the Rust update handler: five
scenarios fail for missing receipts, absent mutations/rejections or incorrect
null behavior; the existing guards control passes. Fixtures and comparator are
unchanged. No production test-only seam is added.

Original metadata is kept as an ordered `IndexMap<String, JsValue>` in the
private parser and `OrganizationUpdateInput`. Supported metadata patches use the
same values; conversion to storage JSON occurs after callback execution. The
actual pinned probe `/tmp/organization-update-raw-number-source-probe.log` sees
Infinity before writing JSON null. The numeric regression
`/tmp/org-update-hooks-raw-sdk-before.log` temporarily reconstructs the callback
input from normalized storage JSON: its actual persisted classification is
`other`, failing the expected `positive-infinity`. The correct callback receives
Infinity, negative Infinity and negative zero and persists the source's null,
null and zero JSON values alongside its independently calculated sign flag.
Receipt HTTP serialization follows JavaScript JSON normalization while the
callback input itself retains its original numbers.

`/tmp/org-update-hooks-oracle-final.log`: 7 TS-versus-itself scenarios / 452
assertions. `/tmp/org-update-hooks-sdk-final.log`: 7 strict dual-runtime scenarios
/ 452 assertions. `/tmp/org-update-hooks-family-final.log`: all 71 organization
scenarios / 4508 assertions pass.
`/tmp/org-update-hooks-openapi-final.log`: all 11 complete-document/configuration
OpenAPI siblings / 494 assertions pass (`tests/open-api`, the actual owner path).
The organization and documentation runs together cover 82 scenarios / 5002
assertions; the canonical integration gate remains coordinator-owned.
`/tmp/org-update-hooks-store-native-final.log`: the distinct real SQLite store
owner passes. `/tmp/org-update-hooks-seaorm-native-final.log`: all 50 SeaORM native
siblings pass. `/tmp/org-update-hooks-api-native-final.log`: all 332 API native
siblings pass. Production and fixture strict Clippy pass in
`/tmp/org-update-hooks-production-clippy-final.log` and
`/tmp/org-update-hooks-fixture-clippy-final.log`. SDK TypeScript, the locked
fixture build and the public rustls/axum/SeaORM/Redis consumer check are recorded
in `/tmp/org-update-hooks-typecheck-final.log`,
`/tmp/org-update-hooks-final-build.log` and
`/tmp/org-update-hooks-consumer-rustls-final.log`. Canonical gates, inventory,
locks and publication remain coordinator-owned.

## Explicit boundaries

The typed Member snapshot covers canonical membership columns. The source
adapter may additionally attach joined user data or arbitrary application member
columns; JavaScript-only undefined/prototype behavior, direct callback-argument mutation,
unknown hook patch columns and custom
physical organization columns are not claimed. The source update hooks do not
supply request/headers; no invented callback request is added here. This slice
does not create a global trusted server-API dispatcher or assert API-key-only
middleware equivalence.

Source default adapter absence and schema-valid empty-patch prepared-query
failure are now covered by the separate
[default-update audit](organization-default-update.md). That route does not alter
this configured hook path or manufacture a SQL failure.
Nullable SQL metadata upgrades, creation/deletion/member-role lifecycle callbacks
and global HTTP cancellation/continuation ownership are separate capabilities.
This frozen baseline does not independently prove disconnected-request lifecycle
continuation or application shutdown semantics.
