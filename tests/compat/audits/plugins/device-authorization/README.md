# Device authorization — pinned 1.7.6

The official client proves issuance, owner claim/approval, bearer redemption
with a persisted session, denial, consumption/replay, expiry cleanup, polling,
prebinding and foreign-user rejection. Additional profiles exercise asynchronous
custom generators, exact custom-code spelling, Unicode limits, custom lifetime,
interval, client validation and verification URL query/fragment behavior.

The actual baseline failed 11 of the initial 16 scenarios. Schema/media
validation now runs before decision authentication and matches upstream error
bodies. Generated-code uniqueness retries at most three times and does not
repeat the application issuance callback.

The unconstrained optional device user reference permits upstream-supported
prebinding. The single squashed auth migration installs this shape; there is no upgrade path from earlier bundled shapes.

Strict harness aliases relate persisted camel-case codes to issued snake-case
codes. TypeScript-versus-TypeScript independently reproduced the previous false
failures. The one-second bearer TTL floor allowance requires an observed real
session with matching token/absolute expiry and execution intervals; changed
expiry, unobserved tokens and larger TTL differences still fail. The new device-code aliases do not apply to caller data, custom JWT
claims or trace shapes. Existing runtime user identity checks remain intact. Raw exceptions remain empty.

Independent review found and resolved pre-authentication validation ordering,
missing media rejection and unscoped aliases in JWT claims. Focused proof: 19
SDK scenarios / 326 assertions, production Clippy and native
generator/collision/concurrency checks. The final canonical `scripts/check.sh` gate passed
with 227 SDK scenarios / 5,064 assertions, 37 harness tests / 210 assertions,
two Chromium tests / 22 assertions, and 79.23% source lines (21,526 / 27,170).

The delayed/custom-adapter decision boundary is measured and repaired in the
[closure receipt](decision213/README.md). Pinned Source validates a pending
snapshot and writes by ID; two overlapping validated owner decisions may both
succeed, with the last completed write determining redemption. Rust now uses
that same handler ordering. This does not promise universal adapter atomicity.
OAuth-provider grant extensions are outside this standalone plugin issue.


## Configuration workpiece (#213)

Pinned executable source is `better-auth/dist/plugins/device-authorization/{index,routes}.mjs`
and `@better-auth/core/dist/api/index.mjs` in the reference server's installed
1.7.6 packages. The constructor rejects numeric `expiresIn` and `interval`
(including zero, negative and fractional values), while accepting signed
fractional duration strings. [Raw constructor observations](options-observations.json)
record both keys and their complete error messages. Reproduce from this checkout:

```sh
devenv shell -- bun -e 'import {deviceAuthorization} from "./tests/compat/reference-server/node_modules/better-auth/dist/plugins/device-authorization/index.mjs"; for (const key of ["expiresIn", "interval"]) for (const value of [0, -1, 1.75, "1.75s", "-0.25s"]) { try { deviceAuthorization({[key]: value}); console.log(JSON.stringify({key,value,accepted:true})); } catch (error) { console.log(JSON.stringify({key,value,accepted:false,message:error.message})); }}'
```

Rust's typed `chrono::Duration` configuration preserves millisecond storage;
response seconds now floor signed fractions like Source's `Math.floor`.
Differential cases exercise positive subsecond polling, expired negative
lifetimes, negative intervals that allow repeated pending polls, relative
verification URIs and the empty-URI default. The actual pre-fix run returned
`expires_in: -1` where Source returned `-2` for `-1.25s`.

Empty synchronous device and asynchronous user generators are accepted upstream.
The complete differential flow proves their empty codes persist, a foreign
client cannot redeem them or mutate the row, the owner can claim and approve
them, redemption creates the owner's session, and consumption rejects replay.
The fixture selector now distinguishes an absent parameter from an empty code.
Empty codes compare literally (empty/nonempty and empty/whitespace differences
fail); identity and session-token emptiness checks remain strict. Harness
controls cover those failures in both directions, alongside the existing code
relationship, rotation, session TTL and JWT-claim controls. No raw comparison
exceptions were added.

Both generators, client validation and the issuance callback are real configured
callbacks. Explicit application API failures retain their public bodies and
`no-store`/`no-cache` headers; ordinary exceptions produce an empty 500 response
without persisted grants or private error details. The pre-fix run missed API
error headers and returned a JSON error body for an ordinary exception. Schema
and media rejections remain outside the handler's no-store scope, as verified by
the existing endpoint validation scenario. The data-exfiltration review traced
callback failures through the HTTP serializer and confirmed that ordinary
exceptions use the existing redacted callback-failure transport; application API
errors intentionally retain the caller's public payload.

Focused validation uses the actual official client, unchanged complete raw
traces and persisted rows against both backends:

```sh
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/device-213-target devenv shell -- tests/compat/client-tests/run-against-both.sh plugins/device-authorization
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/tmp/device-213-target BETTER_AUTH_COMPAT_BACKEND=seaorm devenv shell -- tests/compat/client-tests/run-against-both.sh plugins/device-authorization
devenv shell -- bun test tests/compat/client-tests/harness/compare.test.ts
```

Verification on this workpiece: SQLx and SeaORM each pass 22 scenarios / 474
assertions; the comparator passes 34 controls / 340 assertions, and all 18
existing native device tests pass. Targeted API Clippy with warnings denied,
TypeScript checking, changed-file Oxlint, formatting and `git diff --check` pass.

The complete suite and coverage-floor run remain coordinator-owned under the
current task instruction. Existing coverage requirements are preserved and the
new scenarios are registered in `capabilities.json`; targeted passes do not claim
completion of issue #213 by that earlier configuration workpiece alone.
