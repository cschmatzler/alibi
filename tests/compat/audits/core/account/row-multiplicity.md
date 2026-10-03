# Physical OAuth account rows

Pinned reference: published Better Auth 1.7.6, `db/internal-adapter.mjs`
(`findAccountOwnerByKey`, `findAccountByKey`, `findAccounts`,
`findCredentialAccount`), `oauth2/link-account.mjs`, sign-in and update-user
routes, and the actual generated SQLite account table.

The account row ID is unique; the provider/account pair is not. Global lookup
reads at most two rows and throws on multiplicity even when both rows have the
same owner. Authenticated row-ID operations retain their ordinary ownership
checks. User-scoped lists retain physical adapter order, including a newly
inserted backdated row. Credential authority is the first physical row matching
both provider `credential` and account ID equal to the user's ID; a null first
password does not make the second row authoritative.

The new public `DatabaseError::AmbiguousAccount` keeps global lookup fail-closed
without treating ordinary query failures as ambiguity. OAuth sign-in redirects
to the configured default error page with `internal_server_error`; authenticated
linking returns an empty 500. Code callbacks retain the actual Source state
consumption and error-cookie behavior. The same production error is propagated
through direct ID-token, One Tap and proxy callers. Only GitLab code callbacks
and genuinely signed Google direct tokens are replayed as primary transport
owners; the shared callers are also inspected rather than duplicating these
owners for every provider. Other callback error behavior remains unchanged.

The bundled account table has no unique provider/account index, only a
nonunique lookup index. The single squashed auth migration installs this shape; there is no upgrade path from earlier bundled shapes. Application uniqueness constraints remain
application-owned.

Primary official-client evidence is `account-management/duplicates.test.ts`:

- Same-owner and foreign-owner duplicates are real adapter inserts after genuine
  GitLab authorize/token/profile linking. Global sign-in and link denial preserve
  every physical account/user/session. Replaying the consumed sign-in callback returns
  state_mismatch without another token/profile request or write. Own row-ID access,
  refresh and unlink work;
  foreign operations reach and fail the actual ownership guard while its other
  linked account prevents an unrelated last-account denial.
- A backdated second credential retains full genuine scrypt bytes. Sign-in and
  password-protected user deletion reject the null first credential. Deleting
  that exact row makes the remaining credential authoritative; foreign state is
  unchanged.
- A genuine RS256 Google token is cryptographically verified against the actual
  controlled JWKS transport before duplicate identity lookup. Guest sign-in has
  the Source default redirect, foreign authenticated linking has empty 500, and
  all persisted rows and previous sessions remain unchanged. The full token,
  header, payload, signature and actual HTTP trace are observed.

A native store owner covers a risk unreachable through those public scenarios:
two independently opened SQLite connections admit both real inserts with
distinct row IDs while global lookup rejects the resulting ambiguity and
foreign rows survive.
Concurrent create does not promise a deterministic winner or scheduler order.
Actual Source overlapping credential creation is separately captured in
`/tmp/issue-185-source-dual-create.json`; the server-only setPassword operation's
concurrency owner belongs to issue #185 rather than this storage contract.

Meaningful pre-fix failures are retained in
`/tmp/issue-187-migration-before.log` (the bundled unique index rejects the actual
second insert), `/tmp/issue-187-credential-before.log` (the native selector accepts
the second password when Source rejects), and `/tmp/issue-187-direct-before.log`
(the signed-token path returns JSON 500 instead of Source's 302). The focused
final differential run on code/test head `4c86946697c9725aa0442a77d950ddeac9472a07`
is `/tmp/issue-187-immutable-sdk-proof.log`: four owners, 342 assertions. Fixture
build and strict all-target Clippy, TypeScript, default workspace 794 tests,
feature workspace 845 tests, fixture 2 tests, harness 70 tests, Axum 36 tests,
endpoint 3 tests and coverage inventory 2 tests passed on the stable dependencies.
Independent coordinator production, migration, authorization and test review
found no issue within this scope.

The actual canonical `devenv shell -- bash scripts/check.sh` stopped at full SDK:
717 passed and 22 failed; all four duplicate-account owners passed. Twenty failed
owner names also fail in the independent issue #256 full run. The two additional
trust-syntax failures contained only timestamp/lifetime drift under simultaneous
gates; each unchanged owner passed separately with a 30-second harness timeout
(318 assertions each). The comparator, assertions and Source remain unchanged.
Logs are `/tmp/issue-187-canonical-exact.log` and
`/tmp/issue-187-trust-syntax-individual.log`. Separately invoked Chromium tests
(2), strict workspace docs and all 845 instrumented native tests passed.
The original 75% coverage gate failed: native LCOV reports 27,924 / 38,035 lines
(73.42%). `/tmp/issue-187-canonical-remaining.log` retains this failure; no coverage
pass or complete canonical pass is claimed. GitHub's gate could not fetch the
pinned private SSH development-shell input and stopped before executing tests.

No comparison exception, oracle normalization, test-only production export,
synthetic write receipt, or permissive ownership fallback is added. Private
fixture controls perform genuine configured adapter and SQL operations; ordinary
public responses and full physical state remain the comparator's input.
