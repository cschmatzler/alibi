# Legacy organization-role permission JSON (#220)

PR #404 repairs actual SQLx and SeaORM decoding, role response/mutation parsing,
and dynamic loader/API-key authorization. Stored `OrganizationRole.permission`
now uses `StoredOrganizationPermissions` (literal text via `String::into()` and
`as_str()`); typed create/update inputs remain ordered records. SQL schema and
store trait signatures are unchanged.

Published Better Auth 1.7.6 is verified against the npm tarball SHA512 integrity
and the installed Source file SHA256s (`published-source-integrity.json`). Source
SQLite probes establish non-record reads/lists/deletes without AC, malformed
empty 500s, exact invalid-record loader errors, page-limited target updates,
and the false/zero/empty-string response fallback. Genuine SQL NULL is rejected
by the unchanged NOT NULL schema; literal JSON `null` remains intact.

Three grouped HTTP/SQL regressions and PR393's existing duplicate-row regression
pass against Source and both actual adapters: four scenarios / 518 assertions
per adapter. Pre-fix actual SQLx fails all three new representation cases.
The API-key owner shortcut fails its valid-control/invalid-denial scenario before
the inline correction on both actual adapters and passes afterward. Focused
existing cache/delegated/API-key checks are retained. No full compatibility,
coverage, environment suite, mutation inventory or hosted check is claimed;
Actions reports disabled. The existing comparator and exclusions are unchanged.

`receipt.json` identifies tested and rebased base/head commits. The rebase onto
#402 has matching patch IDs and zero diff in organization owners, fixtures or
comparison code, so passing checks were not replayed for that unrelated change.
The evidence archive preserves raw Source/Rust response pairs, Source probes,
before/after and build/lint logs, fixture controls, Source files, self-review and
rebase inspection. Extract with `tar -xzf evidence.tar.gz`.

#220 remains open for alternative public authorization operators and arbitrary
custom adapter values/model mapping. Other engines, unbounded/deep JSON and
scheduler-level races beyond the existing callback proof remain unclaimed.
