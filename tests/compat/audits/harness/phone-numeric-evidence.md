# Bounded phone numeric evidence

The integrated admin gate exposed a test scheduling defect in the existing
numeric-phone signup scenario. It executes 17 successful scrypt signups against
each runtime, collision signups and failed logins, and additional schema flows.
Bun's default five-second deadline expired under concurrent compilation load.
The timed-out async function then continued after the next serial scenario's
database reset, so its previously occupied number incorrectly appeared available.
`/tmp/admin-selected-canonical.log` records the deadline and subsequent late
collision assertion. This was a fixture lifecycle failure, not an admin change.

Split the independent numeric ownership cases into three serial scenarios. All
17 original raw literals and expected exact SQLite text values remain. Rounded
integer and both infinity collisions stay with the successful owner's group.
Every original wire, stored account/session, owner-preservation, rejected-login,
disabled-plugin and unconsumed-schema-proof assertion remains; the final group
owns the disabled/overflow schema controls once. Each group has a fresh reset and
uses its own complete transport/identity graph. The original scenario name
continues to own rounded uniqueness. Inventory requires all three names for
signup and get-session success and state evidence.

The default five-second deadline, comparator, empty exception list and source
coverage floor are unchanged. Independent family review is clear: all 17 samples and each collision owner
remain covered exactly once. The focused phone suite passes 13 scenarios and
1,058 assertions, exactly the previous family assertion count, with the default
deadline intact (`/tmp/phone-numeric-split-focused.log`). Client TypeScript and
diff checks pass. The final canonical gate passes: 264 SDK scenarios / 7,568 assertions,
37 harness tests / 210 assertions, two Chromium tests / 22 assertions and
79.30% source lines (23,849 / 30,076). Log:
`/tmp/phone-numeric-evidence-reviewed-canonical.log`.

## Phone live-proof rotation ordering (#369)

The frozen `aa0d1388` SeaORM sweep rejected the newly delivered code in
`phone raw numeric attempts-infinity governs delivered proof and consumption`
before differential comparison. The retained log does not include the actual
rows, so it cannot by itself prove the historical database state or an adapter
fault. A focused baseline on `d4135473` passes; the defect is intermittent.

Pinned Better Auth 1.7.6 recreates the phone proof after each invalid attempt.
With `allowedAttempts: Infinity`, the fourth invalid request leaves a live
`originalCode:4` row. Reissuance appends `nextCode:0`.
[Source consumption](https://github.com/better-auth/better-auth/blob/v1.7.6/packages/better-auth/src/db/internal-adapter.ts)
selects `createdAt DESC` with no secondary ordering; equal millisecond timestamps
do not guarantee selection of the newly delivered proof. Both Rust adapters
use the same ordering. The original owner's ID assertion compared against the
*initial* row, already consumed and recreated by invalid attempts, so it could
not distinguish the two live rows.

A controlled BEFORE uses the real pinned Source profile, real delivery callback,
actual distinct generated codes and four genuinely invalid `incorrect` inputs
(the generator emits digits, so this input cannot collide with a delivered code).
Only the new row's creation timestamp is set equal to the actual live predecessor.
The original owner then fails at its original line 364 with `INVALID_OTP` in the
Source stage, before Rust executes. A separate direct Source probe records both
complete physical rows and shows the older code recreated at attempt 5 after
that rejection. This establishes the owner's unsupported ordering assumption and
reproduces the frozen signature without changing infinite policy or OTP values;
it does not retrospectively establish the frozen run's unobserved timestamps.

The owner now reads the complete live predecessor, proves its actual code and
four attempts, and schedules issuance in a later millisecond with one timer.
There is no retry or error acceptance. It requires strict persisted ordering,
`nextCode:0`, exact preservation of the complete older row (ID, identifier,
value, expiry and timestamps), and no session before consuming the real newly
delivered code. Existing foreign-recipient rejection, finite budgets, raw numeric
policies, expiry, two-row deletion, account/user/session state and replay checks
remain. No production, fixture, comparator or coverage exception changes.

The forced-tie negative control fails the new strict-order assertion instead of
reaching an ambiguous consumption. Two independent Source mutations are killed:
accepting an invalid proof fails the first invalid-request error assertion;
retaining stale identifier rows after consuming the newest proof fails the
post-consumption zero-row assertion. All mutations are removed before AFTER.
Bun dependencies use hardlinks: replace a package file with a private inode before
any mutation, including temporary experiments.

Evidence is retained in `/tmp/better-auth-369-evidence/`:
`frozen-seaorm-full.log`, `baseline-seaorm.log`, `source-tie-before.log`,
`source-tie-diagnostic.ts`, `tie-mutated-phone-fixture.ts`,
`owner-tie-before-seaorm.log`, `owner-tie-negative-control.log`,
`invalid-proof-mutation.log`, and `stale-proof-mutation.log`.
Focused AFTER commands use `devenv shell`, `CARGO_BUILD_JOBS=2`, an owned target,
`BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1`,
`BETTER_AUTH_COMPAT_PATHS=tests/plugins/phone-number/phone-number.test.ts` and
`cargo nextest run --locked --test compat --run-ignored only --no-capture
-E 'test(=sdk::tests::selected_client_compat)'`, once with
`BETTER_AUTH_COMPAT_BACKEND=sqlx` and once with `seaorm`.
Full sweeps remain coordinator-owned.

Dependency restoration and proof provenance: the temporary invalid-proof Source
mutation ran from 2026-10-03 10:57:34 UTC until restoration by 10:58:04 UTC.
The only owned phone run overlapping it, `invalid-proof-mutation.log`, failed
intentionally and is excluded from passing proof. The coordinator's frozen sweep
ended at 10:30:49 UTC and was unaffected. Earlier passing AFTER runs were SeaORM
10:54:14–10:54:34 UTC and SQLx 10:56:27–10:57:17 UTC, before that mutation.
The later stale-proof mutation used a private inode and also failed intentionally.
At 11:00:10 UTC, both dependency installs' restored phone routes and internal
adapter matched a fresh npm `better-auth-1.7.6.tgz` byte-for-byte, independently
of the saved working copies. The tarball, extracted pinned files and four SHA-256
comparisons are retained in `authentic-source-verification.json`. Post-restoration passing
proof uses the post-verification `final-sqlx.log` and `final-seaorm.log`,
with UTC start/end timestamps, on latest main after rebase. No mutation run counts
as a passing baseline or AFTER proof.

Initial post-restoration/rebase proof on main `24ed4f3c`: SQLx and SeaORM each pass all 30 phone
scenarios / 1,790 assertions against authentic pinned Source. SQLx ran
11:00:10–11:01:43 UTC; SeaORM finished 11:03:46 UTC. Client TypeScript, targeted
oxfmt/oxlint and diff checks pass. GitHub Actions is disabled for this repository
(`actions/permissions.enabled=false`), so the PR has no scheduled CI checks.
The frozen historical failure lacks physical snapshots; its specific tied
millisecond remains an inference, while the owner defect and matching Source
failure are directly demonstrated. Source's undefined ordering of tied
creation timestamps remains unchanged; this owner explicitly tests ordered
rotation and retains strict rejection/consumption controls.

Latest-main confirmation before merge: rebase onto `564a05b6` after PR #364
was merged externally; this worker did not change or merge that PR. Both affected
adapters again pass 30 scenarios / 1,790 assertions against authentic pinned
Source: `latest-main-sqlx.log` (11:05:13–11:07:38 UTC) and
`latest-main-seaorm.log` (11:08:15–11:09:16 UTC). These are the final passing
proof. All 462 Better Auth distribution files in each dependency install match
the independently downloaded pinned tarball, whose SHA-512 matches the frozen
Bun lockfile. `frozen-owner-equality.json` also proves the baseline owner and
both numeric phone fixtures are byte-identical to frozen `aa0d1388`. Latest-main
TypeScript, targeted format/lint, local self-review and diff checks pass.
