# Trusted endpoint dispatch

Reference: Better Auth 1.7.6. Discovery starts from exact merged main
`a6326641cd4a3c24396f4444041efc6f919204e7`. No root or scoped `AGENTS.md` exists.
The test-audit authoring gate and authorization review apply to this owner.

The existing typed low-level helpers intentionally skip the host dispatch.
The missing contract is a real trusted endpoint call through the installed
plugin middleware and lifecycle pipeline, with actual signed cookies/API keys,
post-hook validation, and an optional physical request. An authenticated
principal must come from verified input or trusted plugin code, never a fixture
receipt. Direct exported JWT signing/keyring functions retain their plain-call
semantics; registered `auth.api.signJWT` is a separate endpoint operation.

Before committing a public interface, real Source-only discovery uses the pinned
published packages, SQLite migrations, actual signup, actual issued API key and
the real `auth.api` operations. `/tmp/issue205-source-dispatch-probe.log` retains
the complete before/after/generator observations and every verification field;
`/tmp/issue205-source-dispatch-expanded.log` extends this to organization
create/add/remove, OTP create/get, JWT token, OTT generate/verify/replay, factor
enable/view and API-key verify, retaining all eight actual tables.

Measured boundaries:

- The configured user hook runs first, then installed plugins in order.
  Returned patches accumulate without changing the input seen by later before
  hooks. Nested objects merge, null patches do not overwrite defaults, and
  arrays replace. The actual handler validates the patched input. Its generator
  receives the stripped validated body, while after hooks retain the full
  patched raw body.
- A raw matcher sees an absent path. `createAuthMiddleware` supplies `/` in its
  callback, while a pathless handler supplies `virtual:`. Actual API-key
  middleware mutates shared session state immediately and returns its own
  normalized context, so later before hooks see the real principal and the
  subsequent pathless handler sees `/`. These are distinct runtime phases.
- Headers are independently optional. An absent physical request yields null
  virtual IP/UA even when logical headers contain those values. A token call
  with absent headers rejects with `Headers is required`/400; an explicitly
  empty header collection reaches session authentication instead.
- Cancellation stops later before hooks, validation, handler and all after
  hooks. Before callback errors propagate without after hooks. A matcher error
  becomes Source's generic matcher API error. Handler API/validation errors
  reach completed hooks; an after API error becomes the returned error and
  later after hooks continue, while an ordinary exception stops the pipeline.
- Verifying the real issued key while that same key authenticates the logical
  call consumes two real uses, one in middleware and one in verification.
  Rejected middleware does not reach later callbacks or the OTP write.
- Registered OTT verification returns an actual Set-Cookie header without a
  physical request; the existing plain `verify_token` helper remains distinct.

The primary differential owners will cover those actual endpoint boundaries,
full callback inputs, projections, quotas and persisted/session state. Credible
pre-fix failures are absent installed hooks and API-key principals in the old
helpers, unchanged pre-hook typed input, and omitted endpoint cookie/header
effects. Existing per-plugin owners explicitly disclose this shared gap and do
not guard it. The new dispatcher is a production application capability, not a
test-only seam. The Source package and comparator remain unchanged.

The repository canonical gate is `devenv shell -- bash scripts/check.sh`;
`devenv test` is a no-op. OpenClaw/Crabbox/autoreview/PR helper tools are not
installed here. Actual repository gates and independent review are used, with
their terminal evidence recorded separately rather than claiming those tools ran.

## Draft implementation checkpoint

The concrete API/production slice is composed on actual main
`fa8837ec322e94486829f12677a83bdecc10ef03`. Workspace Clippy with all targets and
`axum,seaorm2,redis-cache`, locked dependencies and `-D warnings` passed at this
checkpoint (`/tmp/issue205-initial-strict4.log`). All six adapters are compiled:
organization, email OTP, JWT, one-time token, API key and two-factor.

This is an unfinished draft. No new differential owner, pre-fix fixture proof,
full canonical, browser or clean coverage run is claimed. Existing capability
cells are untouched. The production API and all Source observations are open
for independent review while the real boundary owners are implemented.

## Expanded draft boundary proof

The actual Source legacy/task-local probe
`/tmp/issue205-source-legacy-request.log` demonstrates distinct full callback
arguments and exported frames. A before callback has normalized `/`, while
its exported frame retains the raw absent path and original Request. The
handler sees `virtual:` and the genuinely patched Request. Completed callback
arguments see the patched Request, but the exported outer frame retains the
original Request and raw path. Source's header patch initializes or updates
that outer Headers property before copying other context fields; both absent
and initially present logical-header branches are retained. The first owner
that exposed the initially absent header distinction remains in
`/tmp/issue205-phase-context-owner11.log`; no expected observations were
supplied by a fixture bridge.

The same unchanged request-patch owner against checkpoint `3306a319` with the
current genuine native fixture fails at its exported before path `/` instead
of the actual raw absence, 60 assertions
(`/tmp/issue205-tasklocal-before-owner.log`). The repaired actual owner passes,
96 assertions (`/tmp/issue205-tasklocal-after-owner.log`). The primary phase
owner keeps both full callback and exported input/session snapshots, plus
actual legacy Request metadata at each phase. The legacy metadata is derived
from the actual request frame, not projected from logical headers.

A read-only actual Source hashing probe uses `ctx.context.password.hash` in
before, the real OTP generator and after. Its custom application callback
executes genuine scrypt and verifies all three hashes. The installed HIBP
plugin with paths `['/', 'virtual:']` makes exactly one genuine local range
HTTP request at the handler. Raw absent path and original optional Request
remain authoritative before/after; the handler uses `virtual:` and the patched
Request. Full hash, range, input and SQLite receipts remain in
`/tmp/issue205-source-hash-phase.log`.

After composition with merged #135, the genuine three-branch owner reproduced
the missing native frame preference: physical clean hashing made no range
request, a logical call without a Request treated its real raw frame as missing,
and a compromised physical handler reached the original hasher. All Source
branches passed; the exact three native failures and 176 assertions remain in
`/tmp/issue205-hash-before-owner22.log`. `AuthContext::hash_password` now chooses
the present actual EndpointCall, including its absent raw path and optional
Request, before the existing physical fallback. All three unchanged owners
pass, independently verifying every complete real scrypt hash and rejecting a
foreign password. The genuine bound range service checks only the handler;
all raw input and original/patched Request body/query/header receipts remain.

The real API-key getter and validator now record full actual callback
arguments separately from their exported frames, retaining matcher/handler
repetition and exact quotas. Verified endpoint principals retain their actual
config and store Arcs, and shared cache/physical readers check both before
using the private verified model. The unchanged scope owner failed on
checkpoint `3306a319` because a second genuine auth context reused the first
instance's virtual principal (`/tmp/issue205-scope-before-owner.log`); its
repair passed (`/tmp/issue205-scope-after-owner.log`). Cached/virtual SessionView
snapshots retain absence instead of being reprojected through store defaults.

Nested API-key permissions originally escaped registered validation as an
ordinary native error instead of a 400 API validation error. The actual Source
completed all rejection/state checks; the unchanged native owner then failed
at the owning status, 105 assertions
(`/tmp/issue205-api-schema-before2.log`). Registered schemas now validate all
nested issues in Source schema order after accumulated patches and before
callbacks, quotas or writes. The existing HTTP DTO remains unchanged. Direct
Source NaN/Infinity/-Infinity diagnostics are retained in
`/tmp/issue205-source-nonfinite-validation.log` and
`/tmp/issue205-source-nonfinite-string-validation.log`.

Strict TypeScript, the genuine fixture build, and locked workspace optional
Clippy with all targets and `-D warnings` passed for this expanded slice
(`/tmp/issue205-fixture-typecheck15.log`, `/tmp/issue205-native-build15.log`,
`/tmp/issue205-expanded-strict15.log`). Sixteen phase/principal/validation
owners passed, 1,014 assertions
(`/tmp/issue205-phase-context-schema-owner15.log`). The real JWT and OTT owners
passed with the separately reviewed #284 signed-header comparer, 236 assertions
(`/tmp/issue284-composed221-real205-consumers3.log`). The initial stronger OTT
header proof exposed a genuine native registered serializer drift; full real
controls remain in `/tmp/issue205-ott-header-real-control.json`. Registered
publication now uses the existing canonical cookie serializer, and the plain
exported helper semantics remain distinct. No comparer is edited here.

Composition onto main `4bcd25c3` preserves #221 successful cache/stored/virtual
read memo, config/store/header binding, transient cookie cleanup, publication
and pending-factor retirement, as well as #135 and every provider profile.
The native virtual read retains the exact verified SessionView. Actual locked
optional workspace strict checks, fixture strict/build and TypeScript passed
with `MBX_DISABLE=1` and a fresh target directory
(`/tmp/issue205-main288-strict-build19.log`,
`/tmp/issue205-hash-after-strict-build23.log`,
`/tmp/issue205-hash-typecheck23.log`). All 20 existing dispatcher owners pass,
1,492 assertions (`/tmp/issue205-main288-owners20.log`). With the three new hash
owners and unchanged #135 siblings, 38 of 39 pass, 4,116 assertions; the sole
failure is the previously measured #174 proof-length observation
(`observation.observations.0.proof.length`,
`/tmp/issue205-hash-after-owners23.log`). All 23 dispatcher owners pass in that
same combined execution. The initial composed owner launch preceded native
READY and failed health admission only; its terminal log is retained separately
as `/tmp/issue205-main288-owners19.log`.

An actual Source-versus-Source compact counterfactual passes its real SDK
signup, authenticated compact decoder, cached SDK get-session, OTP and persisted
rows, but reports 21 raw Cookie header aliases. Each co-present session_data
envelope differs between independent valid issuances. Full Source captures and
cookie hashes are frozen in `/tmp/issue205-compact-source-captures.json` and
`/tmp/issue205-compact-source-frozen-manifest.json`; the exact unmodified failures
remain in `/tmp/issue205-compact-source-counterfactual.log`. This needs a separate
harness prerequisite; no comparer is edited in #205.

Compact cache/retained projection and complete additional state proof remain
required before #205 closure. This draft has no full canonical or clean
coverage claim. The state owner reads all fields of verification/API-key/org/
member rows and the selected installed session columns; it intentionally omits
unrelated global SessionFields fixture columns and does not claim full factor,
user or JWK storage proof until those owners are completed.

## Cached and stored organization completion

Composed on actual main `bb4142faa155e60b745184401c531b2db9dfd34d`, retaining
all #221/#135/#291 and separate #295 comparer owners. Read-only actual Source
controls in `/tmp/issue205-cache-source-member-phases.{ts,json,log}` and
`/tmp/issue205-signed-source-member-phases.{ts,json,log}` retain full ten-table
SELECT * captures and real SDK/JWT/OTT/API-key observations. Cached and ordinary
signed organization create/add/remove/delete keep their authenticated session
inside the handler; completed outer hooks observe null. Trusted direct userId
create/add do the same. An actual API-key principal established by middleware
remains visible before and after organization remove/delete. JWT and OTT nested
completion expose only user/session, while direct cached getSession alone
retains its original updatedAt number and version string. That separate direct
cache-metadata observation remains unfinished and is not normalized away.

The uncached Source control initially completed every contract and wrote its
full JSON, then its diagnostic printer dereferenced a generator event lacking
current context. The complete initial artifacts remain under `-attempt1`;
correcting only the diagnostic print produced a terminal successful rerun.

New actual cached/ordinary boundary owners independently verify every compact
HMAC and published decoder output, signed SDK issuance, real JWT with JWKS,
OTT consume/restore/replay, scoped organization reads/writes, foreign rejection,
trusted userId operations, virtual credentials and exact remaining uses. Both
full callback arguments and exported frames remain recorded. Complete repeated
Set-Cookie values use the actual Headers.get('set-cookie') combined value and
matching native header collection; the published cookie splitter restores every
actual cookie. This corrects Bun Object.fromEntries losing earlier repeated
values, without constructing an expected runtime receipt.

`/tmp/issue205-cache-before-owner27.log` retains the genuine ordinary Native
completed-principal failure and cached Native OTT restoration failure after
both Source branches complete. Removing only organization handler-added
observations preserves middleware establishment and all authentication checks.
Registered OTT always queues its canonical token/preference cookies before
successful cache publication, preserving #221 runtime semantics. The unchanged
owners then fail at the missing native active-organization store update in
`/tmp/issue205-cache-intermediate-owner28.log`. The registered organization
adapter now performs the same post-core scoped token/team update as its HTTP
owner, honoring keepCurrentActiveOrganization. It never sets the outer principal.
Actual cached Source deletion can leave the stored active organization ID
unchanged when the authenticated snapshot is stale; the owners retain that
relationship to the real created organization and independent stored-session
HTTP readbacks. Foreign session rows stay unchanged.

Initial setup/representation assumptions are separately retained in
`/tmp/issue205-cache-before-owner24.log` (ordinary updatedAt write and a combined
header incorrectly treated as one cookie), owner25 (cached stale active-org
state), owner26 (the actual later native storage/restoration gaps), owner29
(native physical nanosecond timestamp versus public millisecond readback), and
owner30/31 (raw cookie arrays/nonstandard header field compared as literals).
The final owner32 preserves complete standard response.headers Set-Cookie
observations and reaches only the existing physical signup cookie serializer
difference, three signup headers per branch. All actual decision, completion,
restoration, quota and stored-state checks pass within both runtimes. No comparer
is changed here. Full raw Source/native signup controls are frozen in
`/tmp/issue205-signup-header-controls.json`, SHA256
`6d01e50dbcb66f9c613f8649fb7163b4adda4d85ccf072ca4b3fad45f0e8e2ba`.
Source uses Max-Age/Path/HttpOnly/SameSite, while the old physical native token
issuer adds Expires and changes attribute order. That requires a separate
physical-cookie prerequisite; broader #177 remains open.

Actual locked optional workspace and fixture all-targets strict Clippy plus
TypeScript pass (`/tmp/issue205-cache-strict33.log`). No full canonical, docs,
browser or new clean coverage result is claimed for this expanded checkpoint.

## Nested session getter context

The real application cache-version callback exposed an additional dispatch
boundary. Source `getSessionFromCtx` calls the genuine nested getter with the
caller's body/path/headers/optional Request, method GET and its own parsed query.
It retains the real outer logical operation rather than constructing an HTTP
request. The new cached-version lifecycle extends the existing signed/cached
organization owner: JWT/OTT and organization reads retain exactly one version
callback, while a middleware-established API-key virtual principal does not
invoke a redundant cached read. Callback captures retain full user/session and
both exported current and legacy physical contexts.

`/tmp/issue205-version-before1.log` retains the pre-fix native query-null versus
Source query-{} failure after Source completes the whole lifecycle (652
assertions). An initial AuthContext-only repair still missed the JWT adapter's
direct shared runtime call, preserved in owner2. The shared authenticated reader
now scopes only actual EndpointCall nested reads through a cloned GET context
whose query retains the recognized disableCookieCache/disableRefresh flags.
Its original body/headers/optional physical Request, shared extensions and
config/store-bound authority remain intact. Direct reads and physical AuthRequest
readers retain their existing behavior. Owner3 reaches 704 assertions with all
real callback, ownership, persistence and lifecycle checks passing within both
runtimes; only the three separately owned #301 physical signup cookie headers
remain different. No comparison policy changes here.

The separate real incoming POST owner sends a constant literal JSON RPC body
and actual authenticated Cookie header to the controlled fixture, then passes
that actual Request and header collection into the public server invocation.
Nested callbacks observe logical GET/query-{} while preserving the original
Request's POST/query/body/all headers. It independently verifies real owner and
foreign JWS subjects, proves guest401 and a single authenticated version callback,
and keeps all selected physical SQL rows unchanged. Owner7 passes 1/1 with 148
assertions (`/tmp/issue205-version-incoming7.log`). Standalone cookie bytes are
recorded as actual headers.cookie so the existing independent signed-cookie
proof applies; no bytes are removed. Its unpublished duplicate corrupted-cookie
subcase was removed because the seven primary #301 lifecycle owners already
own genuine HMAC corruption and unchanged SQL, and the existing comparator
deliberately rejects invalid cookie receipts even when both sides are corrupt.
All previously published #205 negative owners remain.

Initial incoming controls remain preserved: owner4 passed a real Request to an
unrelated trusted-userId creator without authenticated logical headers and
received the genuine Source401; owner5 placed independent credentials/IDs inside
the raw Request body, producing literal request-byte differences; owner6 retained
full functional proof but recorded standalone valid cookies as literals and
intentionally invalid cookies under authenticated header receipt checks. These
are fixture/representation discoveries, not additional production repairs.
Locked optional workspace and fixture all-targets strict Clippy, actual fixture
build, formatting and TypeScript pass after the bounded reader change
(`/tmp/issue205-version-strict8.log`). Full canonical/docs/browser/coverage and
the separate direct cached metadata observation are still pending; this remains
a draft and does not close #205.
