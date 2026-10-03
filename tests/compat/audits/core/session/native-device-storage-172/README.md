# Native no-database device storage — issue 172

`StatelessStore` rejected every device-code operation. The production change adds
instance-local native `DeviceCode` records to `IdentityState` and implements the
existing store interface. No schema, SQL adapter, handler, admin or logout changes.
Records share the auth instance's lifetime and disappear on restart.

## Focused evidence

The integration owner is `tests/integration/storage/native_device_codes.rs`.
Its generic backend implementations construct actual SQLx and SeaORM stores over
fresh file-backed SQLite databases. The third owner uses
`AuthBuilder::without_database` and opens no SQL connection. All use real signup,
cookie, device issuance, verification, decision and token handlers.

The shared workflow proves unclaimed decision rejection, wrong-client denial
without a polling write, pending polling, anonymous/non-owner field hiding,
first-owner claim, cross-owner decision denial without ownership changes,
approve/deny, repeated decision denial, redemption, physical record removal,
replay rejection and expiry. SQL owners independently inspect physical tables
and assert zero `device_code` and `sessions` rows at completion. Session issuance
is checked against the issuing user's actual session record.

`after-repaired.log.gz` records all three passing owners. `after-lifecycle.log.gz`
adds a NoDB-only lifecycle extension: original records survive in their old auth
instance, while a fresh instance rejects both redemption and review with an
original authentic cookie. Absent-record update returns NotFound; claim,
conditional decision and consumption return false and never recreate authority.
The passing adapters were not replayed for that NoDB extension.

The fixture `tests/compat/reference-server/fixtures/native-device-172-evidence.ts`
runs published BetterAuth **1.7.6** without a database, exercising the same handler
workflow and genuine adapter records. Source absence measurements are null for
update/consume and zero for claim/decision; native uses NotFound/false per its
existing typed interface. Both leave the fresh instance empty. Neither result
is supplied by a mock. Source restart and raw record effects are retained.

`raw-pairs.json.gz` retains 78 paired raw device responses: 26 per native mode.
The bounded comparator also verifies restart rejections. It compares full parsed
device JSON after substituting independently generated device/user codes and
access tokens; session lifetime may differ by at most one second. Signup is setup
and its stable public name is checked separately. Raw signup responses remain in
the individual workflows. Repository raw comparison and exclusion infrastructure
is unchanged. This is sequential lifecycle proof; no stronger concurrency claim.

Installed Source modules were never edited or reinstalled after recovery. Before
and final integrity receipts retain the authentic downloaded tarball hashes;
all 462 published BetterAuth JS/type files and both memory-adapter files match
the extracted published packages byte for byte. Bun only executes the fixture;
no hardlinked package inode was mutated or restored.

## Original failures and repairs

`before.log.gz` and `baseline-rustls.log.gz` retain the missing pkg-config/OpenSSL
build failures. The owned command environment supplies pkg-config, OpenSSL's pc
files and its runtime library path. The recovered test needed the `AuthSession`
trait import. The initial SQL expiry probe hit fixture rate limiting; disabling
rate limiting exposes the intended endpoint, and the independent physical table
name was corrected from `device_codes` to `device_code`.

`before-focused.log.gz` then records the intended NoDB issuance regression:
501, `create_device_code requires an application store`. The SQL failures in that
same run are the final fixture table-name typo, not a production adapter defect.
`after-focused.log.gz` retains the first production compile failure: two lookup
methods needed to propagate the fallible state lock. Both were repaired inline;
`after-repaired.log.gz` is the passing focused result.

Strict core Clippy passes with `-D warnings` and no lint-category allowance.
Targeted rustfmt and `git diff --check` pass. Actions are disabled and the PR has
no hosted checks; no CI-green claim. No full suite, devenv test, coverage gate,
mutation inventory, broad audit or nested delegation ran.

## Review and rebase

Applied test-audit's authoring gate: the real handler boundary owns the production
regression; the additional fresh-instance store checks protect absent-generation
writes that handler-only token rejection cannot exercise. No test-only production
seam was added. Applied wrdn-authz and traced PluginStore delegation, cached-session
resolution, client matching, first-owner claim, owner checks, expiry, conditional
pending decisions and approved-row consumption. Native operations only mutate
stored records under the state lock, and hold no lock across an await. Cache
identity cannot manufacture a grant. SQL implementations remain unchanged.

Rebased onto `8015b45d` after inspecting incoming #403 OAuth discovery/nonce paths
and #406 default admin sort direction. Neither changes device handlers or storage.
The three implementation commits retain identical diffs in `rebase-range-diff.log`.
Only core/API compilation was run after rebase; passing adapters were not replayed.
Incoming diffs and the compilation result are retained.

Issue **172 remains open** for organization/member/invitation/team/role and JWK
storage and broader application-model/cache-aware authority work. Issue **213
remains open** for broader custom generator/configuration acceptance, including
collision behavior and arbitrary physical models. Existing captured-cache session
replay limits remain unchanged. Native records are intentionally ephemeral.
