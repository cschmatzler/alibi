# Supported lifecycle composition, issue 181

Published Better Auth **1.7.6** is the reference. This closes the remaining
HTTP composition gap alongside the existing lifecycle receipts below. No route
inventory, callback classification campaign, full suite or coverage sweep was
replayed. Actions are disabled; this is targeted local proof, not CI qualification.

## Production behavior

The public plugin interface now supports physical request replacement,
first-replacement HTTP response hooks, and an explicit raw endpoint response.
Configured `EndpointHook` callbacks also run for real HTTP endpoints, before
legacy plugin callbacks, using the existing typed `EndpointCall` machinery.

Request-local configuration resolves **once against the original request**, as
published `auth/base.mjs` does. Replacement changes the subsequent physical
Request, routing, parsing and authority checks. Fresh request state discards
incoming/replaced principal extensions, recovered server context, session/cache
state and queued headers, retaining initialized instance globals. Disabled-path
checks and rate limiting precede physical request hooks; route visibility,
media/body parsing and origin protection apply to the effective request.

Configured before patches remain deferred until plugin before callbacks finish.
Explicit plugin header replacements retain their precedence. The selected
endpoint does not reroute when a logical path/method patch changes its input;
completed callbacks receive that patched logical input. Physical Request and
logical headers/body remain distinct. Existing adapter projection already uses
the patched Request from `EndpointCall`; an executable control passed without an
extra `RequestHookContext` scope, so that unnecessary change was omitted.

Intentional handler errors remain errors in after matcher/hook `EndpointResponse`,
recorded at the actual handler error stage. HTTP status alone never establishes
error identity. Ordinary configured hook exceptions use the scoped empty-500
policy; explicit API errors preserve their public status/body and the stage's
header contract. No global `Internal` reclassification was introduced.

Raw endpoint output bypasses completed endpoint callbacks and their accumulated
headers, while physical response hooks still run. The first physical response
replacement ends that hook chain and replaces the old headers/cookies. Native
CORS decorates the final physical response, preserving its original before/
preflight position ahead of custom middleware. Custom after middleware still
precedes physical response hooks. CORS is a native transport extension, not a
claimed Source configuration API.

Source nuance: a normal `createAuthEndpoint` returning `Response.json()` is
wrapped in a returned-value envelope and still runs after callbacks. The raw
case uses a genuine declared endpoint callable returning a direct `Response`
(retaining its public `.path` and `.options`), which reaches dispatch's native
Response bypass. Neither published package nor dependency source was modified.

## Primary owner and evidence

`tests/integration/storage/http_composition.rs` owns one bounded composition
scenario on both actual file-backed SQLx and SeaORM stores. Two genuine signup
users and signed cookies establish actors A/B; a replacement authenticates A
first, then changes the physical cookie to B. Endpoint and database observations
must use B, discard A's trusted extension and leave A's physical user untouched.
Independent SQL reads capture full users/accounts/sessions after every request.

Seventeen Source requests and seventeen per native store cover ordered init
context replacement, physical request replacement, deferred/no-patch input,
handler ordinary/API errors, after ordinary/API errors, HTTP response replacement
and ordinary/API errors, physical request ordinary/API errors, early response,
before cancellation, raw output, unknown route and disabled route. An added
context-request case checks distinct patched physical/logical paths without
rerouting. A final native-only configured-CORS observation protects pre-CORS
hook input and CORS survival on the final replacement response.

The Source/native comparison checks complete event order, principal bindings,
logical/physical input, response status/body/headers/cookies, committed user
names and user/session counts. It normalizes generated actor IDs, JSON object/
header ordering and the independent SQL observer's row representation. For
direct rejected handler calls it compares rejection and status, retaining raw
exception text without claiming Rust/JavaScript exception message equivalence.
All full physical rows are retained; differing schema defaults, random account/
session IDs, tokens, password hashes and realtime dates are not asserted byte
equal across runtimes. There is no response-header comparison exclusion.

`global-before.log` retains both stores' original missing-global-hook failure:
the configured cancellation did not prevent the writer and returned 500 instead
of 200. `path-before.log` retains both stores' actual logical-path failure:
plugin after received `/write` instead of `/logical-patched`. `context-before.log`
is deliberately a passing reconciliation control, not a claimed failing baseline.
Initial review also identified lost intentional-error identity and overwritten
plugin headers; the same owner now checks both actual stages. Prior intermediate
build/setup/stack failures are not counted as behavior proof.

`source-probe.ts`, `composition.ts`, `compare.py`, provenance and raw observations
are retained here/in `raw-proof.tar.gz`. Source runs authentic published npm
bytes in a private installation, with every one of 252 Better Auth and 108 core
modules byte-verified against fresh registry tarballs after execution and link
count one. The known modified shared Bun-cache `state.mjs` was excluded entirely.
The archive contains actual native/Source cookies and physical test rows for
disposable local actors; no external credentials are involved.

## Acceptance reconciliation

| Acceptance | Existing and new evidence |
| --- | --- |
| Ordered initialization/context replacement; global and physical hooks | New composition owner; existing `core::lifecycle_dispatch` init/provider/telemetry owners. Source `context/helpers.mjs` awaits plugin init in registration order and replaces returned context properties. |
| Database create/update/delete context and callback ordering | Existing `core::database_hooks` verifies plugin-before-builder ordering, request versus direct-call absence, post-transaction provisioning and loaded delete entities. New actual two-store owner checks patched logical/physical update contexts and principal. Source `db/with-hooks.mjs` runs plugin hooks before configured application hooks; after hooks queue at the actual transaction boundary. |
| Ordinary versus API errors, cookies/headers, committed state | [PR413 receipt](../lifecycle181/README.md), PR416 OTT callback receipt (`plugins/one-time-token/custom-callback/raw-proof.tar.gz`), [PR423 admin receipt](../../../plugins/admin/closure198/README.md), [PR419 factor receipt](../../../plugins/two-factor/installed-json.md), and new both-store composition/error owner. Ordinary after failures cannot undo already committed writes. |
| Cancellation and rollback | Existing [session cancellation](../../session/create-cancellation.md), [user lifecycle](../../user/lifecycle.md) and [Axum continuation](../../integration/axum-dispatch-continuation.md) receipts distinguish actual operation veto, transaction rollback and caller versus supervised transport cancellation. New before cancellation proves no endpoint write. No whole-request transaction guarantee is invented. |
| Background observations and no-database/cache deferral | Source `context/create-context.mjs` consumes background promise errors; native `run_owned_notification` starts owned work, consumes notification errors and passes completion to the configured observer. Existing [stateless lifecycle](../../session/stateless-172/README.md), [session reads](../../session/reads.md), [session updates](../../session/updates.md) and factor OTP background receipts retain actual deferral/error/committed-state behavior. These policies were inspected and reused, not changed/replayed. |
| Trusted extensions, wrong actor, replay/expiry/concurrency | New real A/B replacement and independent SQL rows; [PR381 foundation](../../../plugins/anonymous/request-lifecycle-foundation.md), [server endpoint authority](../../server-api/server-endpoint-dispatch.md), admin strict-clock receipt and existing factor consumption/cancellation receipts retain actual foreign-owner, provenance, expiry, replay and concurrency proof. The abandoned speculative `SessionAdmissionHook` was not restored. |

The relative plugin paths above refer to the existing audits tree. These are
reconciled supported policies, not claims that every plugin's route inventory
was executed again. Incoming PR421/424/425 was inspected with a retained range
diff; PR425 cookie `AuthResult` propagation remains intact. No account/provider/
OAuth-state/factory/signing or adapter transaction policy was edited here.

## Focused validation

Using `CARGO_TARGET_DIR=/tmp/close181-target` in the development shell:

```sh
cargo test -p better-auth --test integration --features axum,seaorm,sqlx-sqlite physical_http_composition_preserves_principals_and_committed_rows -- --nocapture
cargo test -p better-auth --test integration --features axum,seaorm,sqlx-sqlite storage::lifecycle_errors -- --nocapture
cargo test -p better-auth --test integration --features axum,seaorm,sqlx-sqlite core::lifecycle_dispatch -- --nocapture
cargo test -p better-auth --test integration --features axum,seaorm,sqlx-sqlite core::database_hooks -- --nocapture
cargo clippy -p better-auth --lib --test integration --features axum,seaorm,sqlx-sqlite -- -D warnings
```

The focused owners pass 2/4/11/4 tests respectively. Both composition backends
match all 17 Source observations; the additional configured-CORS assertions are
native-specific. Only necessary incoming fixture lint blockers were repaired
inline. Formatting and `git diff --check` are targeted; no canonical/full gate
was run, as explicitly directed by the coordinator/user.
