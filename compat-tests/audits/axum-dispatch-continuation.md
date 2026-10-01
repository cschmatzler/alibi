# Accepted Axum dispatch continues after HTTP disconnect

The pinned Better Auth 1.7.6 organization creation/deletion handlers await their
configured callbacks and continue adapter writes after Bun receives a client
abort. Earlier probes used a propagation sleep. This owner instead sends a full
real TCP request with an actual signed cookie from public sign-in, waits for the
actual paused callback, closes the socket, waits for a real server-side abort/drop
receipt, then releases the callback through an independent request. No elapsed
sleep supplies a disconnect or completion outcome.

`src/handlers/axum.rs` previously awaited `auth.handle_request` in the Hyper-owned
HTTP service future. Closing that connection dropped the entire dispatch,
including callback waits and any later stores/session selection/response hooks.
The private lazy router supervisor now accepts an owned `AuthRequest` only after
`convert_axum_request` finishes the existing bounded body read. It owns the whole
`handle_request` future and the actual current tracing span/subscriber. The HTTP
future waits on a reply channel; dropping that receiver does not cancel the
worker. Framework request-hook context is still established by `handle_request`
inside the worker. Shared request parsing, middleware, authorization, response
conversion and repeated headers remain their existing owners.

A private actor owns/reaps a `JoinSet` and each response sender, including panic
results. Application panic produces a generic live-caller500 response and the
next request can still run. Internal diagnostics record task failure category,
not request bodies or credentials; normal Rust panic-hook behavior is unchanged.
The actor owns neither its submission sender nor the auth instance. Closing the
last router/service channel drains queued/active work, then exits. Completed work
releases the auth instance. A router constructed outside an entered runtime
starts no task. A router reused after its original runtime shuts down replaces
only a definitively closed sender under the existing mutex before submission;
accepted jobs are never retried.

## Primary owners and meaningful regressions

The existing official-client async creation and deletion scenarios are extended,
not duplicated. Their original connected requests and complete traces remain.
Private application fixtures observe Bun's actual `Request.signal` abort and
Rust's actual premature service-future `Drop`; neither observer supplies callback
delivery or CRUD results. Marker state is explicitly reset before a socket starts.
Normal source plugin after middleware/native `AuthPlugin::after_request` records
actual completed dispatch, after endpoint selection. The scenario then reads the
session once, avoiding variable traced polling. Raw disconnected requests retain
method/path/actual JSON body/marker/actual signed-cookie presence, observed zero
response bytes, actual client close and server receipt; no HTTP response is
invented for a disconnected transport. All ordinary requests, sign-in results,
release/state requests and cookies continue through the unchanged tracing fetch.

Before snapshots are read after real sign-in/selection and before socket send,
so the comparison never depends on network arrival order. Callback release and
socket disposal run in assertion cleanup. Creation proves real member/team/team
member rows and current-token selection after disconnect. Deletion proves actual
scoped organization/member/invitation removal with original callback owner and
unchanged users/retained teams/team members/sibling/foreign sessions. Its newly
signed-in token is selected before sending; forged body userId cannot change the
principal. Completion receipts and real SQL reads make hook-only detachment,
premature completion and CRUD no-ops fail.

Four native tests independently protect Rust-specific transport contracts:

* Real socket close and actual service drop, then actual Axum graceful server/router
  drop while a worker remains paused; release produces the real later write and
  after hook, then a `Weak<BetterAuth>` proves ownership is released.
* Actual201 body, both repeated Set-Cookies (queued and response), after-hook
  header, request-hook path/user-agent and current subscriber/span; application
  panic returns generic500 without its private detail and the next real request
  writes its row.
* Over-limit and incomplete real TCP bodies cannot call the application plugin;
  the same mounted route and store accept a complete control request. The body
  limit remains active before admission, including a body with no length header.
* Router construction outside an entered runtime plus a completed request on
  runtime1, runtime1 shutdown, and a second actual request/SQL write on runtime2.

The original production owner with final fixture/test scaffolding fails the two
existing SDK owners for intended missing continuation, while11 sibling scenarios
pass. The first supervisor draft also fails the new second-runtime control500
versus201 before closed-sender replacement. Setup/typing errors and the native
initial incorrect expectation of an unstripped Axum nested route are not behavior
proof. No comparator rules, skips, oracle version, inventory or dependency locks
are changed.

## Runtime/shutdown boundary

`/tmp/axum-continuation-bun-shutdown-probe.mjs` and its log exercise the actual
Bun1.4.2 used by the pinned reference fixtures, with a real server abort receipt.
`stop(false)` waits for connected requests, but resolves after an aborted socket
while its paused handler promise is still alive; releasing the gate subsequently
finishes that promise. Source server graceful shutdown therefore does not drain
all disconnected continuations. No public shutdown handle or stronger promise is
introduced. Router drop drains accepted work while the Tokio runtime remains
alive; runtime/process termination can cancel it. Arbitrary application task-local
inheritance, process survival, all framework integrations and Bun/Rust panic wire
identity are not claimed. Global trusted server-API dispatch remains a separate
boundary from this HTTP lifetime capability.

## Focused evidence

* Exact final-scaffold SDK before: `/tmp/axum-dispatch-sdk-before-final.log`.
* Earlier direct before: `/tmp/axum-dispatch-sdk-before-valid.log`,11 pass/2 intended
  failures; the earlier shebang scaffolding failure is excluded.
* Runtime reuse before: `/tmp/axum-dispatch-runtime-reuse-before.log`.
* Native transport: `/tmp/axum-dispatch-native-final.log`,4 pass.
* Existing Axum siblings: `/tmp/axum-dispatch-native-siblings-final.log`,36 pass.
* SDK final: `/tmp/axum-dispatch-sdk-final-current-tree.log`,13 scenarios/1126
  assertions pass. The earlier `sdk-final.log` reused the baseline selector
  executable from the focused build target and is excluded as a build-provenance
  setup failure; the final selector and fixtures were explicitly rebuilt from
  this checkout and run without a concurrent baseline build.
* Client/reference fixture TypeScript: `/tmp/axum-dispatch-typecheck-final.log`,
  `/tmp/axum-dispatch-reference-typecheck-final.log`.
* Workspace library/native owner/actual fixture strict Clippy:
  `/tmp/axum-dispatch-clippy-final.log`, `/tmp/axum-dispatch-native-clippy-final.log`,
  `/tmp/axum-dispatch-fixture-clippy-final.log`.

Coordinator owns independent review, full gates, inventory and publication.
