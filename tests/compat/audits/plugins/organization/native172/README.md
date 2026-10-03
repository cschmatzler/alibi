# Native organization storage, issue #172

`AuthBuilder::without_database` now owns instance-local organization, member,
invitation, team, team-member, and dynamic-role rows. The initialized plugin
store retains ephemeral sessions; organization transaction scope changes publish
only after successful adapter completion and cannot resurrect a logged-out
session. SQL adapters keep their existing implementations.

## Bounded proof

`raw-proof.tar.gz` preserves the original published 1.7.6 probe, raw responses,
physical-effect workflow assertions, three failing before-fix regressions, and
focused passing results. It uses a private Bun binary under the task runtime.
Before and after integrity receipts compare every regular published package
file against `better-auth-1.7.6.tgz` and `memory-adapter-1.7.6.tgz`; both have
zero mismatches. No published package bytes were changed.

The same public handler workflow runs through NoDB, SQLx SQLite, and SeaORM
SQLite. It exercises role creation/change/deletion, invitation recipient and
capacity denial, acceptance, membership changes, cross-organization denial,
team cleanup, and organization deletion. Independent SQL queries check physical
rows, permission bytes, and zero physical sessions; rebuilding SQL stores retains
organization/role rows, while a fresh NoDB instance loses organization authority.
A surviving cookie cannot authorize an organization update in the fresh instance.
An aborted transaction leaves both original session scope fields unchanged.

The saved Source workflow has three signup responses and a final delete response
outside the 22-response differential window. `compare.py` compares the 22 raw
handler responses after decoding, mapping generated IDs consistently in sorted
key traversal, removing createdAt/updatedAt/expiresAt, and removing optional
logo/teamId/image/name null projections. Cookies and tokens are outside the
comparison. Literal metadata nulls and permission payloads remain. All three
backends match within these unchanged exclusions, including after rebase.

Run `python3 compare.py <extracted-proof-directory>` to reproduce the comparison.
Focused Rust command: `cargo test --features seaorm --test integration
storage::native_organizations:: -- --nocapture`. Five passed after rebase onto
`d02ba407` (main includes #409, #411, #413, #414). Core Clippy with `-D warnings`
passed. Actions are disabled; no CI, full-suite, coverage, PostgreSQL, or
production deployment result is claimed.

## Production review and open bounds

Store lookups and role mutations retain organization scoping; handler permission
checks use current stored membership/role data. Invitation status mutation is
conditional. Capacity and foreign-recipient denials leave the relevant
membership and pending invitation unchanged. Raw role permission bytes retain
the existing late-validation contract; no owner changes were made for #177/#210.
Current main's organization access operator change and dispatch change were
validated by the affected three-backend handler workflow, without replaying
unrelated OAuth checks.

Native organization transactions stage only organization-family rows. Existing
identity provisioning and application hook side effects are not rolled back.
Transactions reconcile changed rows with the live state; they do not serialize
workflow awaits. A concurrently deleted team stays deleted while a newly staged
membership may commit, matching the saved Source result. Concurrent edits to a
changed row can be overwritten. Locale-sensitive Source string sort collation
is not reproduced by Rust string ordering. State is instance-local and not shared
across instances or durable across restart. This completes the organization
slice only; the wider #172 lifecycle issue remains open.
