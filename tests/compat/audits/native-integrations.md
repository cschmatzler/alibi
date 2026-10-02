# Native framework and transport boundaries

Reference: Better Auth 1.7.6. This accounts for issue #193; it does not claim
Rust implementations of every JavaScript framework package. No root or scoped
`AGENTS.md` exists in this repository. Test-audit authoring and authorization,
data-exfiltration and PII reviews apply. Fixture users and addresses are synthetic.

## Supported public interfaces

| Interface | Contract and primary executable owner |
| --- | --- |
| Axum `AxumIntegration` | Mount into an application router, including custom application state. Convert actual method, URI/origin, query, bounded body and headers; forward status, body bytes and repeated response headers. `tests/axum_integration_tests` owns real signup/session/extractor/revocation and body-limit behavior. |
| Direct `BetterAuth::handle_request` | Native `AuthRequest` / `AuthResponse` dispatch with the same admission, plugin and middleware pipeline. The caller forwards every response header entry; a map that overwrites repeated Set-Cookie loses the contract. `tests/axum_dispatch_continuation_tests` owns direct context, ordered middleware, exact connected response and native cancellation/continuation. |
| Trusted `BetterAuth::dispatch_endpoint` | Logical input/headers remain separate from an optional physical request. Installed middleware verifies authority; endpoint hooks do not substitute a fixture principal. The controlled server fixture and `tests/server-endpoints/dispatch.test.ts` own actual API-key/cookie authority, absent request context, hook order/errors, OTP state, OTT cookies/consumption/replay and cryptographic results. Plain typed plugin helpers intentionally remain separate operations. `tests/open-api/open-api.test.ts` separately owns HTTP exclusion of SERVER_ONLY registrations and trusted availability; documentation-only `scope=server` is not a transport guard. |
| Official Better Auth HTTP client | The unchanged pinned client consumes actual Axum HTTP. Shared `tests/core/dispatch.test.ts` owns origin/CSRF/method/path rejection, media types, invalid JSON, order of admission and persisted principal state. Existing plugin scenarios own signed cookies, redirect locations, response status/body/message/headers and resulting records. |

Axum buffers and validates the body before accepting a supervised dispatch.
A real TCP close drops the HTTP service future; an accepted worker retains the
request context and continues actual later writes and completed hooks even after
server/router drop. Incomplete and over-limit bodies never reach that worker.
The real socket owners are `axum_dispatch_continuation_tests` and the official
client organization creation/deletion hook scenarios. They wait for actual
server abort/drop receipts before releasing the callback and inspect real SQL
state after the observer is gone. See [the continuation audit](axum-dispatch-continuation.md).

A direct borrowed Rust future has a different ownership boundary from a
JavaScript Promise: aborting its task cancels unfinished work. The native owner
waits for a real initial write, aborts and joins the actual task, and verifies
that the committed row remains while the later write/completed hook never ran.
Its detached-observer control drops a real Tokio JoinHandle, releases the same
application callback, and verifies actual later persisted state and retained
physical request context. Its connected control checks exact status/body,
repeated cookies and plugin/middleware ordering. Hosts can retain an owned task
when disconnect continuation is required; no test-only detach API is introduced.
Runtime/process termination can cancel both direct and Axum tasks.

Framework serialization happens after native completed-response hooks and
middleware. The Axum connected owner verifies first/second before middleware,
handler, plugin after hook, then second/first after middleware, plus both emitted
middleware headers. This catches forwarding before the final cookie/header
producer without duplicating endpoint-specific callback-order owners.

## JavaScript embedding boundaries

The installed pinned `better-auth/dist/integrations/*.mjs` were inspected directly.
`node` adapts a Web handler through `better-call/node` and imports Node headers;
Next.js and SolidStart wrappers forward the actual Request. SvelteKit additionally
selects auth paths by origin/base path and bypasses builds. These wrappers are
JavaScript host bindings; no native Node, Next.js, SvelteKit, SolidStart, Actix or
Warp adapter is promised. An application using another Rust host owns its bridge
to the public direct interface.

`nextCookies`, `sveltekitCookies`, and TanStack React/Solid cookie plugins are
runtime helpers, not type-only exports: they copy completed Set-Cookie values
into framework request-scoped stores, skip HTTP router calls, and warn when a
later after hook could produce unforwarded cookies. Next.js additionally
suppresses session refresh in read-only RSC contexts. Those JS cookie-store/RSC
APIs have no native counterpart. Axum instead forwards the final wire headers;
trusted native callers receive the endpoint output headers explicitly. A host
must consume these headers after dispatch completes. This does not claim native
RSC refresh suppression or cookies() integration.

React/Vue/Svelte/Solid/Lynx reactive client adapters, `$Infer` and TypeScript
inference exports remain client embedding/type boundaries. The official client
is used unchanged for HTTP evidence; Rust APIs use native types. The nine excluded
OAuth-server/MCP/CIMD/SSO/SCIM/Stripe/i18n/Expo/Electron package boundaries remain
excluded. SeaORM/custom-store behavior and Redis have their separate owners.

## Test authoring and review

The new direct-future case protects caller cancellation after a committed write,
continued work after observer loss, and complete connected native output. A
regression that cancels owned tasks on observer drop, detaches every borrowed
call, loses request context, or returns before completed middleware fails these
observations. The existing Axum socket owner cannot reach direct Rust future
cancellation. The existing live Axum owner is extended for middleware order and
final repeated-header delivery; no duplicate fixture or production seam is added.
No production behavior repair is claimed, so these are existing-contract tests,
not assertions of a reproduced pre-fix bug. Review traces the unchanged public
dispatch and Axum conversion owners; no authorization/data-exfiltration/PII
finding or oracle change is introduced.

## Validation

On base `2e4cb47aae218024e125a500251975b361fbe7bb`, focused native ownership tests
pass (5), existing Axum integration siblings pass (36), and strict focused Clippy
passes. The actual locked Rust HTTP fixture was rebuilt from this checkout before
running unchanged Source/native scenarios: core admission, trusted endpoint calls
and organization callback/disconnect owners pass (51 scenarios, 6,014 assertions).
Magic-link redirect/expiry/replay and core error HTML owners also pass (7 scenarios,
122 assertions). Logs: `/tmp/issue193-native-final.log`, `/tmp/issue193-native.log`,
`/tmp/issue193-clippy-final.log`, `/tmp/issue193-fixture-build.log`,
`/tmp/issue193-sdk.log`, `/tmp/issue193-wire-sdk.log`.

Focused checks and final tree identifiers are recorded in the PR. Canonical
batch verification is coordinated separately: `devenv shell -- bash scripts/check.sh`
is the executable repository gate; `devenv test` itself is a no-op. No comparator,
reference package, raw-shape rule, dependency lock, route inventory or fixture
receipt is changed by this accounting work.
