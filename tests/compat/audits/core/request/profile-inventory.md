# Profile inventory quota regression

Issue #362 was reproduced against pinned Better Auth 1.7.6 on SQLx and SeaORM
with `rate-limit.test.ts` followed by `profiles.test.ts` in one fixture process.
The rate-limit owners passed; the inventory received `rate-limit-ordered -> 429`.

The registry contained 1,394 entries for 765 distinct profiles. The Naver
integration (`aa9fa9eb`) duplicated existing declarations. Inventory requested
`rate-limit-ordered/api/auth/ok` twice with the same probe IP within its 60-second,
one-request policy. This was repeated inventory traffic, not leaked signup or
OTP quota: those requests use different IPs and endpoint paths.

Pinned installed `better-auth/dist/api/rate-limiter/index.mjs` declares a
module-level memory map, normalizes the endpoint relative to the auth base path,
and keys consumption by client IP and endpoint. An admitted request writes the
bucket in the request phase. A second `/ok` for that client legitimately returns
429; resetting database rows does not clear this map. The fixture policy and
both runtime implementations remain unchanged.

Remove duplicate source declarations while preserving exactly the original set
of 765 profiles. Keep the strict inventory owner, and check its existing
uniqueness invariant before issuing quota-consuming requests. This makes future
duplicate declarations fail directly without hiding the cause behind a later
rate-limit response. No runtime deduplication, quota reset, route exclusion,
status relaxation, comparison change or profile skip is introduced.

The existing real HTTP inventory is the primary regression owner. It failed on
the baseline for the intended duplicate-probe reason. Its strict 200 assertions
and complete trace comparison cover all retained profiles after repair. The
rate-limit owner retains literal 429 responses, retry headers, signed cookies,
user/account/session preservation, foreign-client admission, asynchronous
bypass without reset, zero-window reset, disabled-route admission, and valid OTP
preservation/redemption/replay controls. No additional production seam or
redundant test is needed.

Focused validation uses `sdk::tests::selected_client_compat` with
`BETTER_AUTH_COMPAT_PATHS='tests/core/request/rate-limit.test.ts tests/core/request/profiles.test.ts'`
and `BETTER_AUTH_COMPAT_BACKEND=sqlx` / `seaorm`. Per-workpiece full sweeps are
coordinator-owned and were not run. Preserved logs:
`/tmp/better-auth-profile-quota-362-logs/`.

Before repair on each backend: two rate-limit scenarios passed, one inventory
scenario failed with the exact reference `rate-limit-ordered -> 429` response
(119 assertions). After repair on each backend: all three scenarios passed
(122 assertions). Typecheck, focused formatting/lint, and `git diff --check`
passed. An independent live HTTP probe additionally retains full responses for
two same-client `/ok` requests and requires exactly 200 then 429, the literal
rejection body, and `X-Retry-After: 60` from both runtimes with each backend.
