# Endpoint ordinary-error header publication

Issue #181, bounded production repair against published `better-auth@1.7.6`.

The HTTP dispatcher already skipped completed hooks for `CallbackFailure` and
returned an empty 500, but then attached the request's queued response headers.
An ordinary endpoint exception in the published runtime escapes
`dispatchAuthEndpoint` before response headers are published. Explicit API errors
retain their headers and continue through matching after hooks.

The repair discards both request headers and pending cache issuance headers on
that existing ordinary-error branch. It does not alter persistence, callback
classification, or plugin registration. No shared adapter helper changed.

## Proof

`source-probe.ts` uses two genuine public plugins, `createAuthEndpoint`,
`createAuthMiddleware`, real Bun SQLite, published migrations and the internal
adapter reached through the controlled endpoint. The writer commits a user,
queues a header and two cookies, then throws an explicit API error or ordinary
exception. A second plugin records after-hook execution. Independent raw SQL
records the users after each physical HTTP handler invocation. A final success
request detects cross-request header retention.

The native regression uses the public Rust builder, HTTP dispatch and two
plugins with the existing file-backed SQLx/SeaORM fixture. Its independent side
pool checks each committed user's email directly before the header assertion.
Both adapters failed before the repair because the ordinary 500 carried all
three queued headers. Both pass afterward, preserving both committed users,
API headers/cookie multiplicity and the completed-hook ordering.

Raw observations are retained in `source.jsonl`, `native-before.jsonl` and
`native-after.jsonl`. Header order and cookie attribute order differ between the
source serializer and the explicitly queued native fixture strings; the wire
checks protect values, multiplicity and total absence after ordinary failure.
No comparison exclusions or oracle runtime were changed. `provenance.json`
records the fresh npm tarball's integrity. Installed published package files
were compared against freshly extracted tarball bytes before and after probing;
nested dependency `node_modules` is not part of the published package comparison.

Focused command (from the repository's development shell):

```sh
CARGO_TARGET_DIR=/tmp/lifecycle181-target CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --test integration --features seaorm storage::lifecycle_errors -- --nocapture
```

Run the source probe in a private directory with the pinned reference-server
package manifest and Bun dependencies. No listener or application route is added.

All 10 adjacent `core::lifecycle_dispatch` regressions pass. Targeted Rust
format checks, `git diff --check` and `cargo clippy --locked --test integration
--features seaorm -- -D warnings` pass. Two existing fixture lint blockers were
fixed inline: fixed-size hex decoding uses `as_chunks`, and the result-returning
origin-policy test documents its intentional panic-on-contract-failure assertions.
The rebase onto `556f30a7` only brought unrelated OAuth refresh changes; the
already-passing adapter regressions were not replayed for that rebase.

This proves one endpoint error/header defect. Initialization replacement, trusted
principal extensions, universal database callback composition, cancellation and
background tasks remain outside this repair. Issue #181 remains open. Actions
are disabled; no CI pass, full suite or coverage result is claimed.
