# Automatic API-key cleanup against Better Auth 1.7.6

This capability covers the published API-key module's automatic bulk expiration
cleanup, its ten-second process-wide admission window, and application background
completion registration. It builds on the existing forced-cleanup/generation
capability; atomic credential validation, quota admission, and permissions remain
awaited. Deferred deletion of an individual expired or exhausted credential is a
separate remaining capability.

## Source and public contract

Pinned `@better-auth/api-key/dist/index.mjs:2059-2079` stores `lastChecked` in module
scope, writes it before `adapter.deleteMany`, and logs/catches deletion errors.
Forced cleanup bypasses the window while updating that same timestamp. CRUD
routes start this async operation without awaiting it. Creation starts it after
validation but before the application generator, including a generator that
rejects. Middleware starts cleanup after successful quota validation whether or
not `deferUpdates` is enabled. Successful trusted verification starts it only
when `deferUpdates` is enabled. That option also registers middleware/trusted
completion with `advanced.backgroundTasks.handler`.

The idiomatic Rust contract is `BackgroundTaskCompletion`, an owned Send future
whose output is `AuthResult<()>`, and `BackgroundTaskHandler::handle(completion)`.
`AuthConfig.background_tasks` and its builder setter accept an Arc handler;
`ApiKeyConfig.defer_updates` and its builder default to false. A completion
observes already started work: ignoring or synchronously rejecting it does not
cancel the job. Applications may retain completions for their executor lifetime.
No public shutdown handle, custom clock, store pause hook, or schema is added.

The API-local launcher owns the store, framework request-hook context, and
current tracing span/subscriber. It polls the adapter future once before the
initiating route continues, then owns pending work on the current Tokio executor.
This preserves JavaScript's immediate async-function start, which is observable
at the generator callback. Dropping the JoinHandle observation does not cancel
its Tokio task. Cleanup errors are logged and resolve successfully, matching the
source's caught Promise. Runtime shutdown can cancel outstanding work; arbitrary
application task-local inheritance is not claimed. A missing executor for pending
work reports an explicit error rather than pretending the task was launched.

One mutex-protected UTC millisecond timestamp governs all API-key plugin instances
and stores in this loaded Rust module. Concurrent admission has one winner; failed
cleanup retains its timestamp. Forced cleanup awaits the real store and bypasses
that timestamp. Wall-clock behavior follows Date.now, rather than the old
per-instance monotonic Instant implementation.

At middleware background-handler registration only, ordinary internal handler
failure maps to the pinned empty 500. Explicit application Api/Upstream errors
retain their status/body, including an independently exercised APIError403.
Already consumed quota and already running cleanup remain intact in both cases.
This does not change global error mapping or other callback stages.

## Independent proofs

Fresh pinned-runtime probes wrap each real adapter's deleteMany with an
application acknowledgement gate, invoke real public/trusted APIs, and inspect
actual SQLite rows. They demonstrate immediate adapter entry before a rejecting
generator; successful HTTP return while deletion remains gated; default versus
deferred trusted verification; ignored and rejecting application handlers; caught
SQL ABORT; and cross-instance admission. No published source or clock is changed.
Probe inputs are in `/tmp/api-key-automatic-scheduler-probe.mjs`, with
`/tmp/api-key-automatic-{generation,middleware,middleware-false,verify-false,
verify-true,handler-ignore,handler-throw,storage-error}-probe.log`.

The official-client primary owners share real signups and public generation of
four actual credentials across two users. The application generator deliberately
produces the same configured credential bytes in both runtimes, so their actual
stored hash is compared literally. Private bound SQL establishes remaining=11 and
expired dates only after public creation; ownership rejection is exercised before
cleanup. Every row, timestamp, request, response, cookie/header, application receipt,
quota change, and both owners' physical sessions/accounts/users is retained.

The native fixture wraps the real SeaORM store. All operations delegate to that
store; only actual bulk deletion waits on the application's acknowledgement gate.
Receipts are emitted upon the operation's entry and actual result, not by a control
that invents expected admission. The source fixture similarly calls its original
adapter. SQL BEFORE DELETE RAISE(ABORT) proves real rollback, logged/caught completion,
retained throttle, and forced retry. Two simultaneous valid middleware requests
retain both full transports and independently check credential ownership and
consumed quota while admitting one cleanup. Observer modes cover default, await,
ignore, ordinary rejection, and genuine application 403.

Admission uses the real ten-second window. Each owner forces cleanup first and
waits until 10,020ms after its actual adapter receipt. Its optional 30,000ms
compatScenario deadline is necessary for running that real wait against both
runtimes; existing defaults and the 1.5-second date comparator remain unchanged.
Timestamp comparisons after admission cover short actual stages. Fixture reset
releases/drains real pending work and resets only application observations, never
the production module timestamp. Source-to-source six owners pass 596 assertions
(`/tmp/api-key-background-source-control-anchored.log`).

The old implementation fails before-generator entry for the intended reason
(`/tmp/api-key-background-original-generation-before.log`). Its old awaited
launcher also records `httpCompleted:false` after actual adapter entry and before
application release, then returns 200 only after release
(`/tmp/api-key-background-old-await-before.log`). The baseline fixture needs only
declarative new configuration ABI/types to compile; its old launcher/call-site
behavior is preserved. An earlier partial scaffold retained the new hot helper,
so its passing middleware control is explicitly excluded as before-fix evidence.
Early setup runs that used a server-only public remaining field, random generator
bytes, or undrained observations were fixture setup failures; corrected controls
are separately named and retained, with no comparator allowances.

## Validation and limits

Final focused proof is recorded in `/tmp/api-key-background-family-final.log`
(46 scenarios / 2182 assertions, including all six new owners) and `/tmp/api-key-background-native-final.log`
(52 native API-key siblings). Locked fixture build, client/reference TypeScript,
strict production and fixture Clippy, downstream Rustls/Axum/SeaORM compilation,
targeted formatting and diff checks are
recorded in `/tmp/api-key-background-*-final.log`. The coordinator owns independent
review, shared inventory updates, canonical gates, and publication. External
skill-specific autoreview executables are unavailable in this checkout.

The exercised profiles share the actual fixture database but use distinct auth
instances; fresh source probes additionally establish module-global admission
across independent databases. Cross-process/shared-library duplication is not a
claim of one global scheduler. Individual-row deferred expiration/exhaustion,
shutdown survival, non-Tokio asynchronous executors, arbitrary task locals,
clock reversal/extreme dates, and panic-specific source behavior remain separate
boundaries. No dependency, lockfile, schema, migration, inventory, coverage,
comparison exception, or pinned-runtime change belongs to this capability.
