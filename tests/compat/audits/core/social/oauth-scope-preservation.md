# OAuth sign-in preserves granted scopes

Pinned Better Auth 1.7.6 `oauth2/link-account.mjs` intentionally omits `scope`
from existing-account sign-in updates. Explicit account linking owns scope
changes. One Tap calls the same OAuth user processor with its initial account
scope `openid,profile,email`; it must preserve a previously linked account's
scope too.

The shared Rust sign-in path previously updated the existing account's scope
from fresh token response scopes and placed that replacement into account
cookies. Both now retain the existing account's scope. New account creation and
explicit linking retain their existing scope behavior. No schema, migration,
fixture, comparator or public interface changes are needed.

The official-client regression seeds a real Google account with independent
`calendar,drive` scopes, runs the actual provider callback through the public
OAuth route, checks the resulting session owner, then reads persisted scopes
through `listAccounts`. A token-response scope replacement fails this test;
ordinary preexisting OAuth tests do not exercise differing stored/provider
scopes. The test adds no production seam and has no duplicate native mirror.

Before proof `/tmp/one-tap-scopes-before.log` fails with received
`openid,email,profile` instead of `calendar,drive`; after proof
`/tmp/one-tap-scopes-after.log` passes the same official-client observation and
unchanged transport comparator. TypeScript validation is recorded separately.
Coordinator owns inventory and the canonical full gate.
