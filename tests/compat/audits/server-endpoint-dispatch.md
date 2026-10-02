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
`/tmp/issue205-source-hash-phase.log`. Native #135 frame-preference composition
is still pending and is not claimed proved by this Source-only receipt.

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

The existing organization/factor proof still depends on the separately reviewed
entity selector prerequisite #287 and signed-header prerequisite #284. Compact
cache/retained projection, #221 memo/publication and #135 hash-context composition
remain required before #205 closure. This draft has no full canonical or clean
coverage claim. The state owner reads all fields of verification/API-key/org/
member rows and the selected installed session columns; it intentionally omits
unrelated global SessionFields fixture columns and does not claim full factor,
user or JWK storage proof until those owners are completed.
