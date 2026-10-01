# OAuth registration commits user and account together

Pinned Better Auth 1.7.6 `handleOAuthUserInfo` creates a fresh user and its
provider account under `runWithTransaction`. An actual pinned Bun SQLite oracle
installed an account-insert veto and used the official client with ordinary
application OAuth verifier/profile callbacks. Failure left zero users,
accounts and sessions (`/tmp/one-tap-atomic-oracle.log`).

Rust previously created the user and provider account in separate writes.
It now uses the existing `store::transaction` contract, including the configured
PluginStore transactional user transforms. The account receives the actual
created user's ID. Commit precedes session creation; no transaction/callback API
or schema changes are introduced. Other existing OAuth response differences
are outside this persistence prerequisite.

The native public-builder regression installs a real SQLite account-insert
trigger, invokes public social sign-in, and checks that neither user nor account
survives and no session cookie is emitted. Removing the trigger then retries the
same principal and checks the actual persisted account/session/user binding.
This protects transaction failure and recovery; browser crypto/lifecycle tests
cannot install a driver-level failure. It uses existing application verifier and
profile APIs and no new production test seam.

Before `/tmp/one-tap-atomic-before.log` fails specifically because the user
survives account failure. After `/tmp/one-tap-atomic-after.log` passes rollback
and retry; existing 18 account OAuth integration tests also pass. Coordinator
owns inventory and the canonical full gate.
