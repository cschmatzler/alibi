# Supported storage reconciliation, Better Auth 1.7.6 (#192)

The production work is one PR, #427. The base is fetched main
`b476f488` (including #419 and #423). It repairs three measured PostgreSQL
parameter discrepancies in both actual SQLx and SeaORM stores. No universal
backend/schema equivalence, hosted CI result, or full-suite result is claimed.
The issue's old full `devenv test` instruction is superseded by the user's
explicit targeted-only instruction.

## Actual source and driver observations

Fresh authentic npm archives and every installed published file were verified:
465 Better Auth files, 350 core files, 10 Kysely adapter files. All installed
files had private inodes before Bun execution and remain byte-identical afterward.
`source-integrity.json` retains exact npm SHA-512 integrity and archive hashes.
The modified `/tmp/.d774fec071c1d447-7.better-auth/dist/state.mjs` cache was never
used. Source package bytes were not modified. The standalone oracle uses the
published adapter factory, actual `pg` / `mysql2`, and isolated synthetic tables.
It is an adapter contract probe, not an official-client HTTP scenario.

PostgreSQL is **18.6**, owned local `initdb` service on `127.0.0.1:55492`.
MySQL is **8.4.11**, owned `mysql:8.4` container on `127.0.0.1:55493`, image digest
`sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242`.
Neither service uses application databases, existing services, credentials or
shared configuration. Both Rust adapters executed on actual PostgreSQL.

* Source `pg` sends Number text. Fractional LIMIT/OFFSET returns SQLSTATE
  `22P02`; native float8 parameters previously rounded `1.5` to two rows.
  Both paging helpers now bind `ryu_js::Buffer::format` text with `::bigint`.
  This preserves signed zero, Infinity spelling, exponents, Number precision,
  range failures and the PostgreSQL parser. No client integer cast/clamp is used.
  Negative LIMIT/OFFSET is rejected on PostgreSQL; SQLite's negative LIMIT
  means unbounded. The primary existing member-page owner retains these bounds.
* Source's team seat predicate is `memberCount < Number`, within its configured
  transaction. On the matching physical BIGINT schema, PostgreSQL rejects
  fractional and nonfinite Number text. Native float comparison previously
  admitted fractions and NaN. Both native seat predicates now bind text with
  `::bigint`. Errors roll back the upward counter synchronization and leave
  memberships and the complete team row unchanged. The independent-store owner
  uses Source-valid `2.0` on PostgreSQL and retains `1.5` on SQLite; eight stores
  still compete for two seats, preserve retries, release seats, and retain one
  invitation-acceptance winner. Source's INTEGER schema has its narrower integer
  range; the raw INTEGER and matching BIGINT observations are both retained.
* Source numeric custom filters succeeded on a renamed `app_people`/`mailbox`
  schema while both native stores failed `double precision > text` (`42883`).
  PostgreSQL native operands now cast to the declared int4/int8/float4/float8
  type; the actual indexed column stays unchanged. SQLx gains precise Int and
  BigInt categories in the existing generated scalar metadata. Its old write
  arm still returns these values unchanged. Timestamp, typed-null, UUID, bpchar
  and ordinary string binding behavior is retained. Unmapped fields fail closed;
  handwritten Other metadata is not guessed to be numeric.

The actual published core `transformWhereClause` gates numeric scalar conversion
with `typeof newValue === "string" && newValue.trim() !== ""`. Arrays parse every
nonempty trimmed string, then replace the array only if every result is not NaN.
Whitespace/empty operands stay as text, and one invalid operand leaves the entire
array as its original strings. The excerpt and raw Kysely parameter logs are
retained. The native coercion follows this rule only for declared numeric
PostgreSQL columns. On PostgreSQL 18, raw `0x1` is accepted by the integer parser;
the discriminating native/source mixed-array control therefore uses
`["1e0", "NaN"]`, whose first uncoerced operand is rejected. Source empty numeric
IN/NOT IN emits invalid SQL on PostgreSQL; this rejection is preserved, while
SQLite predicates and float bindings retain their existing semantics.

Source MySQL separately rejects fractional/negative pages with parse errors;
NaN/Infinity have MySQL-specific errors. These are Source measurements, not native
MySQL results. SQLx only exposes SQLite/PostgreSQL features and URL branches.
The shipped SeaORM integration enables only those two engines; externally
unifying SeaORM's MySQL feature is not a supported/proven complete native store.
In particular explicit SQLite/PostgreSQL-only CAS/conversion branches must not
be turned into invented MySQL emulation. No native MySQL runtime or compile-only
claim is used to satisfy this issue.

## Remaining acceptance and valid prior receipts

| Acceptance | Current evidence and precise bounds |
| --- | --- |
| PostgreSQL pages, raw Numbers, order and query typing | This PR's actual dual-native member-page and numeric application-model owners; Source parameter/response/error logs. Limits and offsets genuinely execute the repaired helpers. Counts and complete owner/foreign physical rows survive success and SQL failures. |
| PostgreSQL RETURNING, verification CAS, hooks and transactions | Reuse #357's 70 actual PostgreSQL shared-store contracts, including independent-pool consume/reserve/CAS races, queued hook commit/rollback and cancellation, compound invitation transactions and bounded hook snapshots. This PR directly adds rollback proof for failing PostgreSQL seat casts and retains real concurrency. No unrelated contracts were replayed. |
| Application models, custom physical fields and identities | This PR executes derived models from both adapters on populated renamed `app_people`, `mailbox`, `score32`, `score64` columns and int4/int8/real/float8 values. The real prepared numeric query retains its indexed column and Index Cond on 10,000 rows, without planner settings. Reuse #366's String application models and naive/aware PostgreSQL lifecycle under UTC/Europe/Berlin; #377's actual CHAR(30) ID/FK types, CRUD and prepared index plans; #357's actual UUID verification lifecycle; #389/#423's numeric primary-identity/canonical authority and custom numeric/date/JSON SQLite receipts. This does not imply every identity/model combination on every driver. |
| Populated schemas, constraints and defaults | The numeric PG owner adds a defaulted CHECK-constrained application column to 10,000 populated rows and retries the application's DDL, with UNIQUE, PK, dependent FK and numeric index retained. Actual native create/update preserve the omitted upgraded field/default and dependent application row. Read/error snapshots include all rows and physical constraint definitions. Current bundled migrations/ledger idempotency and switching stores reuse #357. Arbitrary application upgrades remain owned by the application's versioned migrator, as current database documentation states. |
| Installed historical upgrades | #357 removed legacy upgrade machinery and squashed bundled migrations. The old #306 pre-consolidation recovery proof is historical, not evidence that current main auto-upgrades old application schemas. No automatic arbitrary-schema/old-ledger conversion is promised or fabricated. |
| Exact token CAS and whole write-failure effects | Reuse #399's actual dual-store populated SQLite physical identity/token CAS and explicit transaction repair for RAISE(FAIL), including stale/reassigned/deleted/NULL/plain cases and untouched fields. Its PostgreSQL conversion branch compiled but was not executed; this is not mislabeled as a PostgreSQL conversion receipt. It does not substitute for #357's actual PostgreSQL verification CAS proof. |
| Default limits and quota ordering | Reuse #357's configured bounded hook/public-list pages with unrestricted owned cleanup, #378's Source/raw quota/read/callback-order SQLite receipts and #423's actual numeric/custom-order/hook receipts. This PR closes their measured PostgreSQL numeric parser differences, retaining public Option<f64> and Source's driver-specific physical integer bounds. Explicit public admin pages are distinct from omitted adapter default-findMany limits. |
| Custom-store capabilities | Current core raw-page/atomic transaction/CAS defaults explicitly return NotImplemented, rather than implementing nonatomic read/write fallbacks. Configured column mapping is required for custom queries. Third-party stores must opt into the actual operations; no blanket capability allow or new AuthStore/schema API was added. |

Prior PR merge commits and changed paths are retained in the provenance JSONs.
This reconciliation closes the supported scoped issue; it is not certification
of arbitrary third-party adapters, external engine-feature combinations, all
custom physical SQL types, historical automatic upgrades, or all-driver parity.

## Reproduction and focused validation

The source oracle manifests/lock and programs are retained as gzip files. Inflate
into a private temporary directory, install only that manifest, then replace any
Bun hardlinks with private inodes and verify installed published bytes against
fresh integrity-verified archives before running the oracle. The standalone
native proof's manifest and source are retained too; its absolute owned worktree
path is an explicit reproducibility input, not a portable package.

Create only owned synthetic services:

```sh
initdb -D /tmp/better-auth-close192-services/pg -A trust -U close192
pg_ctl -D /tmp/better-auth-close192-services/pg \
  -l /tmp/better-auth-close192-evidence/pg.log \
  -o '-h 127.0.0.1 -p 55492 -k /tmp/better-auth-close192-services' start
docker run -d --name better-auth-close192-mysql \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=close192 \
  -p 127.0.0.1:55493:3306 mysql:8.4
```

From the owned checkout, the targeted PostgreSQL owners are:

```sh
devenv shell -- env CARGO_TARGET_DIR=/tmp/better-auth-close192-target \
  BETTER_AUTH_TEST_POSTGRES_URL=postgres://close192@127.0.0.1:55492/postgres \
  cargo nextest run --test integration --features seaorm --run-ignored only \
  -E 'test(public_numeric_pages_bind_raw_limits) | test(independent_stores_enforce_team_capacity) | test(declared_numeric_filters_preserve_rows_types_and_index)'
```

The original page and seat owners pass after repair and both fail after reverting
only their respective production helpers. The numeric owner passes both actual
adapters, and both fail `integer >= text` when the numeric production delta is
reverted to `f54eef5f`. An initial final run's extra discriminating assertion
incorrectly expected PostgreSQL 18 to reject `0x1`; correcting it to `1e0` makes
both numeric owners pass. Passing page/seat owners were not rerun for that
assertion-only correction. Logs retain these exact failures and successes.

Strict production lint uses:

```sh
devenv shell -- env CARGO_TARGET_DIR=/tmp/better-auth-close192-clippy \
  cargo clippy --no-deps -p better-auth-sqlx -p better-auth-seaorm --lib -- \
  -D warnings -A clippy::double_must_use
```

The allowance is the documented preexisting core warning. Scoped formatting and
`git diff --check` are required. No full suite, compatibility script, coverage,
mutation campaign, scheduler or hosted Actions result is claimed. Independent
coordinator production/security review cleared `f54eef5f` and the numeric delta
through `697023d7`, with the published trim/all-or-none rule separately qualified.
The sole later production lint delta removes an intermediate redundant clone;
parameter expressions still clone the same borrowed values into the same SQL.
