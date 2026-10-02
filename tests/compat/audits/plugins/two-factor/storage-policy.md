# Two-factor verification policy storage prerequisite

Pinned Better Auth 1.7.6 defines nullable `verified` (default true),
`failedVerificationCount` (default zero), and `lockedUntil` fields in its factor
schema. Enrollment explicitly writes verified false unless configured to skip
verification. This prerequisite adds that representation; API policy is a
separate capability commit.

The fixed TwoFactor DTO remains the store's factor result. AuthTwoFactor's new
optional accessors default to absent for manual implementations. CreateTwoFactor
defaults match legacy/schema behavior while preserving explicitly nullable
values. UpdateTwoFactor mutates only secret, backup codes and verified status
on an exact row ID. No associated factor model or broad derive contract changes
are introduced. The schema registry now emits the corresponding extra entity.

Store operations follow the source adapter's exact-row predicates: atomic
counter+1 returning its snapshot; threshold-guarded lock; conditional
expired-lock clearing; unconditional success reset; and backup-code compare and
swap against the stored generation. Unsupported custom stores return explicit
NotImplemented errors. PluginStore forwards every operation. MemoryStore uses
those fail-closed defaults rather than pretending mutation succeeded.

Bundled SQLite keeps INTEGER counter affinity, including integral storage and
fractional/NULL values. Bounded REAL projections at store reads and INSERT/UPDATE
RETURNING prevent SQLx f64 decoding from losing integral values. Aliases retain
the original field name. Every mutation is one parameter-bound atomic SQL
statement; RETURNING captures its winning snapshot without a later SELECT.
Unchanged updates only read. New source field-only updates preserve factor
timestamps; the existing backup-update operation retains its timestamp policy.
SQLite and PostgreSQL support RETURNING; PostgreSQL uses double precision for
numeric counters. Only SQLite has runtime proof in this slice. Unsupported
backends are rejected before insertion or atomic updates. Independent review
found insertion lacked the update path's backend guard; the coordinator repaired
it so an unsupported RETURNING dialect cannot persist a row before reporting
a missing return value.

The namespaced `m20260930_000012_two_factor_verification_policy` migration adds
missing nullable columns in place. It preserves existing factor rows, secret
and backup bytes, owner identity, custom columns/indexes/triggers, rowids and
timestamps. Both fresh and installed migration runs use the same registration.

Two native SQLite tests own distinct risks. An installed pre-policy table proves
actual upgrade defaults, preservation, repeated migration, live trigger/index
behavior and store readback of integral, fractional and null counters. It fails
on the true frozen a1bd1c9 baseline with `no such column: verified`
(`/tmp/two-factor-storage-upgrade-before.log`). The concurrent test uses eight
separately opened, single-connection databases against one file. It proves all
eight zero-based counter increments survive with unique returned snapshots, a
future lock resists clearing, expired clearing has one winner, a stale threshold
write cannot recreate a reset lock, and backup CAS has one winner. A second
generation for the same owner remains byte-for-byte unchanged. The fixture
removes the preexisting unique owner index to represent an installed/custom
schema that permits multiple generations; this prerequisite does not silently
change that unrelated existing constraint.

The published plugin comment says nullable historical counters are supported,
but the actual 1.7.6 Kysely adapter assigns `field + delta` without COALESCE.
Actual Bun SQLite failed-verification requests therefore retain NULL, and the
threshold comparison cannot lock that row even with threshold zero. The API
owner SDK configuration case preserves this behavior; the installed-store test
also asserts NULL increment/readback and no threshold-zero lock. That assertion
fails against a1f2d431's original COALESCE implementation (Some(1) versus None),
recorded in `/tmp/two-factor-storage-null-before.log`. Success still explicitly
resets the counter to zero. Other upstream adapters can handle NULL differently;
this SQLite prerequisite does not claim their nullable arithmetic semantics.

One core extension-contract test proves all unsupported security operations
return 501 instead of succeeding. The real SQLite tests cannot exercise that
custom-store default boundary. Existing nine native two-factor tests and three
CLI generator tests remain passing. Focused storage tests, production workspace
Clippy with seaorm2, formatting and diff checks pass. No dependency versions,
locks, comparator, inventory or coverage policy changes occur. The coordinator
owns canonical gates and independent review. Account/challenge enforcement,
verified transitions, callbacks and official-client proofs follow separately.

Coordinator independent review checked the pinned nullable arithmetic and all
exact-row mutations, parameter binding, backend guards and upgrade registration.
The existing installed user-reference regression now seeds the actual legacy
SQL table before both upgrades, preserving its application-view/link proof and
asserting new defaults. That focused test passed; no new production test seam
was introduced. Full `devenv shell -- ./scripts/check.sh` passed: 274 SDK
scenarios / 8,168 assertions, 37 harness tests / 210 assertions, two Chromium
tests / 22 assertions, 78.96% source lines (24,148 / 30,582). Log:
`/tmp/two-factor-storage-reviewed-canonical.log`. Shared locks/inventory and
comparison policy are unchanged; the default and optional configurations,
Rustls/Redis builds, generated schema tests and documentation checks passed.
