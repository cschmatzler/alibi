# OAuth linking and consumed-state rejection wire

The pinned `better-auth@1.7.6` session middleware returns HTTP 401 with
`{"code":"UNAUTHORIZED","message":"Unauthorized"}` when public linking has
no valid session. `dist/api/routes/account.mjs` attaches `sessionMiddleware`
to `linkSocial`; `dist/api/routes/session.mjs` owns the nested session read and
cookie cleanup. Rust's existing OAuth session guard rejected the same request,
but exposed the generic `AUTHENTICATION_REQUIRED` error instead.

The pinned `dist/state.mjs` database branch looks up the verification first.
An absent verification throws `StateError` with `state_mismatch`, including a
previously consumed state. Rust instead redirected with
`please_restart_the_process`. The correction changes only that absent-row
branch, preserving lookup, signed state-cookie validation and consumption order.

The two official-client owners in `tests/oauth/rejection.test.ts` exercise
missing cookies, a modified signature from an actual issued owner cookie, a
revoked actual signed cookie, successful owner linking and successful new-user
OAuth login followed by consumed-state replay. They retain every SDK result,
callback redirect, canonical transport trace and observed owner/foreign/retired
user, account and session row. Rejections leave those complete state snapshots
unchanged. Successful linking adds exactly one provider account to the original
owner without replacing its session; successful login creates a genuine provider
account and session for the new owner, which replay cannot rotate or duplicate.

Meaningful baseline `/tmp/oauth-rejection-meaningful-before.log` has two intended
failures: generic linking error versus the source's coded error, and consumed
state's restart error versus `state_mismatch`. The unmodified pinned Source-self
control `/tmp/oauth-rejection-source-control.log` passes 2 scenarios / 88 assertions.
The baseline uses the saved original handler consumer and the same deterministic
application fixtures; the Google provider's actual published flow uses local
fixture transport and controlled test identities, without external accounts.

The scope is valid-body public linking and consumed **database** state. Body
validation ordering, missing query-state spelling, cookie-strategy invalid-state
errors, other providers/configurations and shared session-hook policy are separate
capabilities. Existing authorization guards remain in place; this is response
fidelity, not an authorization-bypass fix. No comparator exceptions, global error
mapping or reference-runtime behavior changes are included.

One early after-check accidentally selected an already occupied Source port 3941;
its server startup failed with `AddrInUse`. `/tmp/oauth-rejection-sdk-final.log`
is excluded from differential evidence. The real rebuilt Rust fixture uses its
independently reserved port 3979 and `/tmp/oauth-rejection-native-server-current.log`.

The local linking rejection reuses the existing session-cookie deletion headers
only when the original guard reports unauthenticated and extraction verifies a
signed token. Missing or tampered cookies do not queue cleanup. Every other
`AuthError` propagates unchanged; the shared guard and global error mapping are
unchanged. The initial rebuilt differential log
`/tmp/oauth-rejection-sdk-final-current.log` proved the replay repair and detected
the missing revoked-session cleanup, rather than being accepted as a green check.

Final `/tmp/oauth-rejection-sdk-final-owned.log` passes both owners plus all 15
existing OAuth SDK siblings: 17 scenarios / 118 assertions. Native existing
account OAuth tests pass 18/18 in `/tmp/oauth-rejection-native-siblings.log`.
Client TypeScript and strict fixture Clippy pass in
`/tmp/oauth-rejection-client-typecheck.log` and
`/tmp/oauth-rejection-fixture-clippy-final.log`. `git diff --check` is clean.
The larger directory run included four unfinished provider-policy owners and
correctly failed those; it is not prerequisite success evidence. An attempted
reference `tsc --noEmit` had no project configuration and printed compiler help;
it is excluded, not reported as a reference type-check success. No full gate,
inventory, lockfile or schema updates were performed in this worker slice.
