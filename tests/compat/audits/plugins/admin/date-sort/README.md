# Explicit admin sort field defaults to ascending (#198)

Published Better Auth 1.7.6 `plugins/admin/routes.mjs` supplies `direction:
ctx.query.sortDirection || "asc"` when `sortBy` is present. Rust's shared user
query helper previously defaulted every missing direction to descending. The
repair selects ascending for an explicit field and preserves descending when
no field is supplied. Explicit directions, filtering and pagination retain
their existing behavior.

The public regression owner is `tests/integration/plugins/admin_identity.rs`.
Actual SQLx and SeaORM SQLite stores use integer user IDs and deliberately
unsorted dates. The public admin route combines a date range, offset 1 and
limit 2. Omitted and explicit ascending directions return IDs 42, 3; explicit
descending returns 3, 42. The pre-fix run fails on both adapters with 3, 42
instead of 42, 3. Both fixed scenarios pass, including complete physical
user/account/session preservation. The fixture session uses the configured
seven-day lifetime to avoid intentionally triggering normal session refresh.
No production test seam was added.

The Source control is `reference-server/fixtures/admin-date-sort-control.mjs`.
It uses authentic published 1.7.6, real migrations, serial IDs, session creation
and the public handler. Its physical account table is empty; the native fixture
has five accounts. Both runtimes independently verify all physical columns.
The npm tarball SHA-512 matches registry integrity; all 465 installed files
were byte-verified and given private inodes before Bun. No dependency was
modified. `source-integrity.txt` records that verification.

Retained gzip artifacts contain original pre-fix failures, fixed native raw
observations, Source raw observations and six raw paired responses. Pairing
compares status, pagination, order, IDs, names, emails, verification/image,
dates and ban fields. Explicit exclusions are fixture-specific roles, native
optional username/displayUsername/twoFactorEnabled defaults, and generated
session IDs/tokens/runtime timestamps. Physical preservation is independently
asserted within each runtime, including those excluded fields.

Focused proof ran through a temporary Cargo target importing only the existing
owner module, with `--features sqlx,seaorm date_sort_default_pages_ascending
-- --nocapture`: 2 passed, 2 unrelated identity scenarios filtered out. The
temporary manifest target was removed. Focused Clippy passes with warnings
denied except the existing core `double_must_use` warning, explicitly allowed;
no unrestricted strict-Clippy pass is claimed. Scoped Rust and Source formatting,
Source lint and `git diff --check` pass. Existing unrelated repository-wide
formatting differences are outside this change. No full suite or coverage gate
was run. GitHub Actions is disabled; there are no hosted check results.

Self-review traced public route validation, authoritative session lookup,
`user:list` authorization, unchanged query forwarding, both actual adapter
paths and the shared sorting/filtering/paging owner. Sorting occurs after
authorization; no permissions or user projections change. Incoming main commit
5fd23226 affects generic OAuth discovery only, so passing adapters were not
replayed for that rebase.

This bounded repair does not close #198. Custom numeric/JSON interactions,
alternative access-control operators and strict ban-expiry equality/mutation
hook ordering remain open. Canonical target identity behavior is unchanged.
