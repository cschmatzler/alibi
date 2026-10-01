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

The appended `m20261001_000016_account_key_multiplicity` migration leaves the
recorded initial schema unchanged, removes only the bundled pair unique index,
and adds a nonunique lookup index. No account table is rebuilt or deduplicated.
Incoming SQLite application composite foreign keys are inspected using bound
catalog names and refused before any schema mutation. Applications must migrate
such references to the stable account row ID first. PostgreSQL/MySQL native
constraint checks refuse dependent index removal without CASCADE; those upgrade
branches have not been measured as part of this issue. Application uniqueness
constraints remain application-owned. Downgrade refuses existing duplicate rows;
it does not invent a row to delete. With multiplicity resolved, downgrade restores
the unique index before removing the lookup index, and re-upgrade is supported.

Primary official-client evidence is `account-management/duplicates.test.ts`:

- Same-owner and foreign-owner duplicates are real adapter inserts after genuine
  GitLab authorize/token/profile linking. Global sign-in and link denial preserve
  every physical account/user/session. Own row-ID access, refresh and unlink work;
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

Four native migration/store owners cover independent risks unreachable through
those public scenarios: a populated prior schema retains full rows, rowids,
application columns/check/index/trigger/view bytes; an incoming composite FK
refuses unchanged and succeeds after a real application ID-reference migration;
downgrade refuses duplicates then round-trips without row loss; two independently
opened SQLite connections admit both real inserts with distinct row IDs while
global lookup rejects the resulting ambiguity and foreign rows survive.
Concurrent create does not promise a deterministic winner or scheduler order.
Actual Source overlapping credential creation is separately captured in
`/tmp/issue-185-source-dual-create.json`; the server-only setPassword operation's
concurrency owner belongs to issue #185 rather than this storage migration.

Meaningful pre-fix failures are retained in
`/tmp/issue-187-migration-before.log` (the bundled unique index rejects the actual
second insert), `/tmp/issue-187-credential-before.log` (the native selector accepts
the second password when Source rejects), and `/tmp/issue-187-direct-before.log`
(the signed-token path returns JSON 500 instead of Source's 302). The focused
final differential run is `/tmp/issue-187-final-primary-proof.log`: four owners,
326 assertions. Stable-dependency exact-head checks and independent review are
recorded with the final PR; focused evidence is not a complete canonical gate.

No comparison exception, oracle normalization, test-only production export,
synthetic write receipt, or permissive ownership fallback is added. Private
fixture controls perform genuine configured adapter and SQL operations; ordinary
public responses and full physical state remain the comparator's input.
