# Instrumentation runtime boundary (issue #516)

The pinned `@better-auth/core@1.7.7` implementation is the source of this
boundary: `dist/instrumentation/tracer.mjs`, `api.mjs`, and `noop.mjs`; consumers
are `better-auth/dist/api/index.mjs`, `api/dispatch.mjs`, and `db/with-hooks.mjs`.
This option is distinct from the telemetry transport discussed in
`runtime-helper-telemetry-boundaries.md`.

`createWithSpan(options)` selects the no-op runner only when
`experimental.instrumentation.enabled === false`. Explicit true **and omission**
select the OpenTelemetry runner. Thus this version's instrumentation is not an
opt-in logger, as the issue describes. Logging output alone cannot prove that a
span was emitted.

The runner requests the OpenTelemetry API, tracer scope
`better-auth`, and instrumentation version `1.7.7`. It forwards route, operation,
hook, and database attributes to `startActiveSpan`. The installed `api.mjs` starts a dynamic `@opentelemetry/api` import but never
assigns its result to `openTelemetryAPI`, so its getter continues returning
`noopOpenTelemetryAPI` even after that import completes. The issue's proposed
trace/log observation therefore cannot establish actual exported spans with this
pinned loader. This source-specific limitation must be rechecked on upgrades. The no-op option invokes the original callback
without changing its value, promise, or exception.

Successful sync and async callbacks end the span and retain their original return
values. Failed callbacks record the original exception, mark ERROR, end the span,
and rethrow it. Better Auth's APIError redirects (300–399) instead set the HTTP
status attribute and mark OK, then retain the same thrown redirect. The option
does not change authentication admission, response envelopes, cookies, or stored
rows; the existing boundary owners continue to compare those contracts.

Rust observability uses the host's `tracing` subscriber and native spans/events.
It does not embed the JavaScript global OpenTelemetry provider, its attribute
constants, promise detection, or Better Auth instrumentation scope/version.
Exporter delivery, span parent propagation, provider lifetime, SDK sampling,
trace IDs, and backend formatting are application runtime integrations. They are
explicitly excluded from differential authentication-wire parity. This audit
accepts that native embedding boundary; it does not silently claim that a Rust
configuration switch or JavaScript OpenTelemetry export exists.

A differential auth profile whose only change is this flag would repeat existing
HTTP assertions without observing the integration in question. The source audit
is the requested boundary resolution for #516, as permitted by that issue; it
requires no new production seam, remote tracing service, or whole-suite run.
