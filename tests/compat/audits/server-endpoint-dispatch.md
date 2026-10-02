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
