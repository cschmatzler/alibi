# Anonymous authentication and account upgrades

Reference: pinned Better Auth 1.7.6 `plugins/anonymous/index.mjs`,
`db/internal-adapter.mjs`, `cookies/index.mjs`, and `api/state/oauth.mjs`.
The implementation uses the public immutable `AnonymousConfig`, application
identity/link traits, actual database hooks, and the original-session/trusted
OAuth-context prerequisite documented in `request-lifecycle-foundation.md`.

## Measured behavior

Anonymous issuance creates an unverified anonymous user and a real session,
without a credential account. A current anonymous user cannot issue another
anonymous session. Configured asynchronous name/email generation is exercised;
an empty name falls back to Anonymous and a malformed generated email fails
before persistence. The default random identifier remains generated with the
existing 32-character alphanumeric generator: the store lowercases the email,
matching Source's actual persistence boundary. An optional nonempty domain uses
the `temp-` prefix. It is not a new lowercase-only random generator.

Only actual `HookControl::Cancel` from user creation produces the typed
`UserCreationCancelled` primitive. Its default response remains 403, while the
anonymous endpoint maps that exact variant to 500 `FAILED_TO_CREATE_USER`.
Session cancellation maps to 400 `COULD_NOT_CREATE_SESSION`. Genuine application
Forbidden errors with the identical cancellation messages retain their own
403 response. User cancellation leaves no rows; session cancellation retains
the already-created user without a session/account.

Issuance inherits a genuinely signed browser-session preference and emits a
browser session token and signed preference cookie. Altering a real preference
signature gives ordinary durable issuance instead. Session persistence retains
the configured session expiry in either case. No request body can nominate an
anonymous owner or provide a trusted preference.

Deletion requires the authoritative current session, rejects regular users,
deletes that anonymous user's sessions and user, and clears session cookies.
Disabled deletion rejects the endpoint but still permits the configured link
callback while retaining the old anonymous rows. A callback's explicit API
error is preserved after the new account/session has already been committed;
the old anonymous rows remain. Successful email signup transfers the original
completed snapshots before cleanup, even when a real session-after hook changes
the stored new user's name. Current-session and storage reads expose the changed
name. The callback is an observation of completion, not permission authority.

The OAuth owner uses the actual local GitLab token and user-info transport.
Client-supplied serverContext/proof cannot choose a foreign anonymous user.
The actual callback works without the anonymous cookie using newly issued,
authenticated server-owned context; it transfers only the captured anonymous
owner, cleans up that owner, and rejects consumed-state replay. Foreign users,
sessions and accounts are retained in every primary state observation. Native
foundation controls separately exercise altered owners, state-bound proof
copying, malformed historical context fields, expiry and wrong state cookies.

## Primary evidence and credible failures

`tests/plugins/anonymous/anonymous.test.ts` has five official-client owners for issue/delete,
original snapshot transfer, stage-specific cancellation/configuration effects,
cookie-less OAuth transfer, and signed preference inheritance/tampering. Each
retains the actual SDK results, complete canonical transport, real callback
receipts and stored owner/foreign rows. Application receipt/counter reset happens
at the existing reset-state boundary after completed requests. It does not
synthesize receipts or account authority.

The prepared anonymous draft fails three independent owners at the intended
behavior in `/tmp/anonymous-sdk-meaningful-before.log`: mutated callback name,
user-cancel 403 versus 500, and absent cookie-less OAuth transfer receipt. The
basic lifecycle owner already passes. The separate preference control fails
that same draft at its absent preference cookie in
`/tmp/anonymous-browser-preference-meaningful-before.log`.

Final focused evidence:

- `/tmp/anonymous-source-sdk-feature-final.log`: Source self, five owners / 384 assertions.
- `/tmp/anonymous-sdk-feature-final.log`: Source versus Native, five / 386.
- `/tmp/anonymous-sdk-core-family-final.log`: all 35 core owners / 1264.
- `/tmp/anonymous-default-native-first.log`: genuine public native default identity,
  actual stored session, repeat denial, deletion and stale replay; one table owner.
- `/tmp/anonymous-default-native-clippy-final.log`: strict default-owner Clippy.
- `/tmp/anonymous-feature-production-clippy.log`: strict workspace library Clippy.
- `/tmp/anonymous-feature-fixture-clippy-final.log`: strict fixture Clippy.
- `/tmp/anonymous-feature-typecheck-final.log` and
  `/tmp/anonymous-feature-reference-typecheck-final.log`: client and new reference fixture TypeScript.
- `/tmp/anonymous-feature-fixture-final-build.log`: current-tree fixture build.
- `/tmp/anonymous-source-boundaries.log`: actual Source default/random identity,
  custom domain, cancellation, same-message application errors, validation method,
  browser preference and cache issuance raw observations.

The random default has a distinct native public shape/lifecycle owner because
independently generated email strings are application literals to the strict
comparator. The SDK uses real configured deterministic email generation rather
than suppressing those fields. It does not claim default random literal-wire
comparison.

## Cookie and configuration boundaries

Every parsed cookie name, reversible encoded value, ordinary attribute and
extension is retained under the existing token graph. Active expiry follows
the existing cookie-parser Max-Age precedence; the original header and all
parsed attributes are preserved independently in
`/tmp/anonymous-cookie-evidence-{port}.jsonl`. Local crypto checks bind signed
session payloads to the actual returned token and state-cookie payloads to the
actual issued state. The native JWT state cookie's real header and date claims
are independently verified. This does not claim literal parity for the existing
Source signed-state/native JWT-state codecs, physical verification namespace,
or inactive Expires attributes accompanying Max-Age.

General `user.validateUserInfo` is a separate missing native contract. Source
passes `{ method: "anonymous", action: "create-user" }` after email lowercasing
and before database hooks; ordinary native database hooks are not a substitute
for that policy. The current typed link callback projects `UserView`/`SessionView`,
not arbitrary custom application user columns. Ordinary thrown-exception wire
handling, custom anonymous table schemas, secret rotation/nondefault state
strategy, multiple-active-session recovery ordering, and other configured login
method branches are not claimed by these five owners.

Cookie-cache issuance/reads are a separate capability being implemented by its
owner. These anonymous profiles disable cache. Composition must publish the
original completed pair only after successful cache emission, because Source
can queue a token and persist a session while a cache callback fails without
setting `ctx.newSession`; that failure must not trigger anonymous transfer.
No cache issuer change is included here. No comparator, inventory, dependency,
lockfile, schema or full gate is changed or run by this slice.
