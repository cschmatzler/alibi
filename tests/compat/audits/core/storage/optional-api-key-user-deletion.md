# Optional API-key cleanup during user deletion (#448)

Core-only CLI schemas have no `api_keys` table. Both bundled stores previously
queried it unconditionally in `delete_user`, breaking public self deletion and
admin removal after otherwise successful signup. Both adapters now inspect the
optional table through the **held deletion transaction** and skip only an absent
table. Metadata failures and failures deleting credentials still propagate.
Present tables are cleaned by the deleted user's `reference_id` even when the
API-key plugin is no longer registered. No plugin-registry or Auth core changes
are involved; existing team/wallet optional cleanup uses the same mechanisms.

## Native regression owners

The generated-schema owner compiles actual CLI core-only output, installs its
migrations, explicitly verifies `api_keys` is absent, and calls a shared public
HTTP deletion workflow on both SQLx and SeaORM. Each uses a single-connection
SQLite pool, so reacquiring a connection while the transaction is held would
block. Independent SQL verifies the target's user/account/session rows disappear
and the administrator's rows remain. Deleted session and password reuse fail.

`storage/users.rs` owns that shared workflow and installed-key variants. Real
public signup and key creation precede both self deletion and admin removal.
Independent SQL and the real API-key verification endpoint distinguish the
removed owner's invalid credential from the foreign owner's valid credential.
Retaining the table while unregistering the plugin still cleans owned keys.
A credential-delete veto must fail deletion. A later user-delete veto fires
only after keys have disappeared inside the transaction; retained user/key rows
after failure therefore demonstrate rollback, rather than skipped cleanup.
The old direct-store-only HTTP-flow cleanup test is replaced by this owner.
There is no test-only production seam or duplicated lower-level assertion.

This protects two distinct contracts: generated core-only installation/deletion
and installed credential lifecycle/rollback. Existing all-plugin fixture tests
cannot detect the absent-table defect; the original direct-only cleanup test
covered only a migrated bundled store. A credible regression is unconditional
cleanup, blanket swallowing of deletion errors, registration-only cleanup,
foreign-owner deletion, or moving table inspection to a newly acquired pool
connection. No assertions are derived from source text or the implementation.

## Actual Source stage and limits

Source was inspected from a frozen Bun installation of the repository's pinned
`better-auth@1.7.6` and `@better-auth/api-key@1.7.6`. The actual
`better-auth/dist/db/internal-adapter.mjs` `deleteUser` deletes sessions,
accounts and user; the API-key plugin's `dist/index.mjs` does not install this
native polymorphic credential cleanup transaction. Rust deliberately retains its
existing credential cleanup/security guarantee. This is Source **inspection**,
not a passed differential Source run or a claim of upstream transaction parity.
Neither the oracle pin nor the separate 1.7.7 review issue #453 is changed.

The store transaction covers native owned-key/user deletion, including existing
team/wallet cleanup. Account/session deletion earlier in each HTTP handler is
outside it and can remain committed after a later failure. Whole-endpoint
atomicity, handwritten API-key views and arbitrary custom schema mappings are
not promised. PostgreSQL, full compatibility, coverage and the full repository
gate were not run for this scoped fix.

## Evidence

Baseline: `93a9d1bded75314477425980df4fac4eb7f5c7a5`, including the human
Bun/Rust dependency migration and recorder #454. Production uses its locked
SQLx 0.9 and SeaORM 2.0 dependencies. Actual CLI commands, with no `--plugins`:

```sh
cargo run --locked -p better-auth-cli -- generate --backend sqlx --output tests/fixtures/cli/sqlx_core.rs
cargo run --locked -p better-auth-cli -- generate --backend seaorm --output tests/fixtures/cli/seaorm_core.rs
```

Both committed fixtures byte-match fresh output from that CLI. Original and
final-owner pre-fix runs fail all four generated-core public deletion cases with
500; installed-key cases retain their existing guarantees before the fix.
After the two store guards, 16 focused owner/sibling cases pass: generated
schemas, nullable user flags, installed-key deletion, and team/wallet deletion.
Formatting and `git diff --check` pass. Exact logs, source snapshots, fixture
outputs, baseline test patch and dependency/source hashes are preserved in
`/tmp/better-auth-final-verification-20261004/reports/sixissues-user-deletion/`.
The attached checkout remains clean at `aa0d1388`; this work uses its own fresh
`--no-hardlinks` clone and target/cache/module directories.
