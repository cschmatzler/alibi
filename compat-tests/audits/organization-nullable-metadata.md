# Nullable organization metadata (Better Auth 1.7.6)

This capability distinguishes absent metadata stored as SQL `NULL` from a
stored JSON literal `null`. The pinned organization schema declares metadata
as an optional string (`better-auth/dist/plugins/organization/organization.mjs:732`).
The creation adapter omits absent metadata and parses present stored JSON for
its creation response (`adapter.mjs:142–153`). Update returns parsed metadata
(`adapter.mjs:353–368`), while get, full, set-active and list return the stored
text. List filters joined organization rows without parsing metadata
(`adapter.mjs:474–486`). The HTTP create/update schemas still require metadata
to be a record; accepting `metadata:null` in those request bodies is not part
of this repair.

The bundled organization entity now stores `Option<JsonMetadata>`, and the
organization model registry describes `Option<Json>`. The public organization
store persists `None` as SQL `NULL`; `Some(Value::Null)` is JSON text `"null"`
on SQLite. An omitted update retains either state. Entity conversion preserves
this distinction. Creation/update wire projection no longer conflates a real
JSON null with absence. The list handler now uses the same stored-metadata
projection as get/full/set-active, retaining owner filtering and exact
JavaScript JSON text for metadata created through the supported API.

Fresh schemas allow a nullable metadata column. Installed schemas gain appended
named migration `m20260930_000013_nullable_organization_metadata`; older
migration names and ordering remain intact. SQLite uses the existing SQL
tokenizer and the established pinned-connection rebuild procedure. It removes
only the metadata column's `NOT NULL` rule, its optional constraint name and
`ON CONFLICT` clause. It retains defaults, checks, custom columns, generated
columns, indexes, triggers, views, row identity and stored bytes. Foreign-key
and rename settings are restored; failed relationship checks roll back the
replacement table and leave the migration unapplied. PostgreSQL uses `ALTER
COLUMN metadata DROP NOT NULL` and is compile-checked, without a claimed
PostgreSQL runtime migration test.

Three native SQLite tests own distinct storage/upgrade contracts: public-store
omission versus literal null and subsequent patches; an installed custom schema
with retained noncanonical JSON bytes, rowids, default/check constraints,
generated fields, index, view, trigger and real foreign-key deletion; and an
invalid existing reference causing rollback with enforcement/settings and
migration ledger preserved. The public-store regression fails before the
repair with `Some(Null)` versus `None`; the upgrade regression fails because
the named metadata `NOT NULL` constraint remains.

The existing absent-metadata official-client case now observes raw SQL `NULL`
and follows get/full/list, an unrelated update and set-active without changing
the persisted selection or membership. Its pre-fix failure observes stored
text `"null"`. One new lifecycle case uses a controlled private legacy-row
action: parameterized Bun SQL writes `"null"`, while Rust exercises its public
organization store with `Some(Value::Null)`. Authentication still goes through
unchanged pinned Better Auth and the Rust public handlers. It verifies stored
text, each owner endpoint, parsed null on an unrelated update, exact numeric
record text on list, preserved sibling-token/other-organization state, and a
foreign-owner rejection with only that foreign current token cleared.

The new lifecycle independently fails with the old null-normalization
projection at the real getter. With storage fixed but the old list projection
retained, it fails because list emits null/object instead of stored strings.
The final metadata scenarios pass at the same boundaries (3 scenarios, 176
assertions). Focused organization/configuration proof passes 46 SDK scenarios
with 2,780 assertions; API library tests pass 321 and SeaORM library tests pass
45, including the three new migration/storage tests. Strict API/SeaORM library
and fixture Clippy, client and changed reference-fixture TypeScript, formatting
and diff checks pass. Comparisons and coverage requirements are unchanged.

Installed rows containing `"null"` are preserved, including rows an older Rust
version created for an omitted field. Their original intent cannot be inferred;
they now behave as present JSON null rather than silently being rewritten to
SQL `NULL`. Physical JSON column affinity differs from the pinned string
schema. Arbitrary invalid JSON text, noncanonical legacy JSON spelling on HTTP
readback, and application-selected custom organization models are separate
boundaries: this storage path uses the bundled organization entity, and the
existing decoded wire projection reconstructs JSON text. Migration byte
preservation does not claim exact legacy whitespace/number lexemes on HTTP.
