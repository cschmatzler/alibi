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
COALESCE(counter,0)+1 returning its snapshot; threshold-guarded lock; conditional
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
numeric counters. Only SQLite has runtime proof in this slice.

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
eight nullable-counter increments survive with unique returned snapshots, a
future lock resists clearing, expired clearing has one winner, a stale threshold
write cannot recreate a reset lock, and backup CAS has one winner. A second
generation for the same owner remains byte-for-byte unchanged. The fixture
removes the preexisting unique owner index to represent an installed/custom
schema that permits multiple generations; this prerequisite does not silently
change that unrelated existing constraint.

One core extension-contract test proves all unsupported security operations
return 501 instead of succeeding. The real SQLite tests cannot exercise that
custom-store default boundary. Existing nine native two-factor tests and three
CLI generator tests remain passing. Focused storage tests, production workspace
Clippy with seaorm2, formatting and diff checks pass. No dependency versions,
locks, comparator, inventory or coverage policy changes occur. The coordinator
owns canonical gates and independent review. Account/challenge enforcement,
verified transitions, callbacks and official-client proofs follow separately.
