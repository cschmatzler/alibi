# Request-dependent linking trust (#178)

Published Better Auth **1.7.6** supports `account.accountLinking.trustedProviders`
as an async function of an optional Request. `context/create-context.mjs` calls
`getTrustedProviders(options)` at initialization. `auth/base.mjs` clones context
and resolves origins then providers from the HTTP request before routing.
`context/helpers.mjs::resolveRequestContext` applies the same order with dynamic
base URLs. Core types `types/init-options.d.mts` document both initialization
with undefined and real-request evaluation.

`socialProviders` is a different contract: core `types/helper.d.mts` defines
`AwaitableFunction<T> = T | (() => Awaitable<T>)`; `SocialProviders` uses that
zero-argument type. `create-context.mjs` calls and awaits each factory once at
initialization, before constructing its native provider. The executable probe
observes exactly one async GitLab factory invocation with zero arguments across
all requests. Request-dependent factory or credential selection is unsupported
by this pinned release and is not added to Rust.

The production change adds `TrustedProvidersResolver::resolve(Option<&AuthRequest>)`,
an optional Arc on AccountLinkingConfig and an AuthConfig setter. The builder
resolves None once; initialized contexts retain that value for direct calls
without a transport request. HTTP dispatch resolves the original transport
request once into a cloned config after origin resolution and before HTTP
hooks, middleware, callback state recovery or linking authority. The dynamic
list replaces the static list rather than extending it. Empty IDs are removed,
matching Source filtering. Global config and provider factories remain immutable;
no provider credentials are selected or exposed by this policy. An empty list
continues to require a verified provider email rather than bypassing linking.

Initialization errors propagate from the builder. At request resolution,
Source's handler promise rejects **before the router**, including an explicitly
thrown APIError(403); it emits no routed response or cookies. Rust maps failure
at that same stage to its empty HTTP 500 transport boundary and discards the
private cause. This is not the explicit-API-error preservation rule for callbacks
inside endpoint dispatch. The probe retains both ordinary and API error rejection
receipts; the actual Rust tests require empty bodies, no auth writes and no
static-trust fallback for both. Private callback messages are never logged by
the Rust conversion. No equality of a rejected JS promise and a routed JSON
response is claimed.

## Necessary owner-boundary proof

`tests/integration/core/dynamic_providers.rs::dynamic_provider_callbacks` runs
one grouped public-builder/dispatch contract on **actual SQLx and SeaORM** over
independently inspectable file-backed SQLite. The only new primary test owner
covers request-dependent authority missing from the previous static-list API:

- Initially allowed, callback denied: an unverified provider cannot link to a
  verified local user, and issues no new account or session.
- Initially denied, callback allowed: fresh callback policy permits linking;
  original start-time policy is not reused from recovered state.
- Different-host callbacks overlap at a barrier, with disjoint allow/deny lists.
  Only the allowed actor gets an account/session; shared initialized trust stays
  `init-only`. HTTP hooks see each request's effective list and base URL.
- Authenticated explicit linking cannot transfer another user's existing provider
  account, even when trusted. Raw SQL before/after retains owner, account ID,
  access token and scope, independently of the adapter query layer.
- Exact authorization URL endpoints/scopes/client/redirect URI, raw token forms,
  provider profiles, callback locations, state consumption and replay outcomes
  are retained. Source and both native adapters end with six users, three accounts
  and three sessions. Both error variants abort before issuance.
- Initialization failure propagates without resolving an unavailable request.
  Published static direct API without Request uses initialized trust. Published
  dynamic direct API without source or fallback rejects before trust resolution.

The local issuer returns provider responses but does not implement linking,
state validation or persistence. The actual published and native factories,
callbacks, state codecs and stores own those behaviors. No production test-only
seam is added. Existing coverage protects static factories and global origin
policies; it cannot detect a missing request-dependent linking trust API.

The **original fetched main `13f23f0f`** has no resolver API. `baseline-fixture.rs`
uses its existing static GitLab trust configuration and the same real HTTP
callback. On both actual stores the requested callback denial instead redirects
to `/done` and physically writes an account/session. `baseline.log` retains both
intended failures. This demonstrates the original API limitation, not a modified
Source oracle or a hidden mutation of production. The repaired grouped fixture
uses the new dynamic resolver and passes that callback denial plus the positive,
concurrent, ownership and failure cases. The baseline fixture is retained only
as the executable before receipt, not registered as a second ongoing test owner.

## Provenance and scope

Fresh npm tarballs `better-auth-1.7.6.tgz` and `core-1.7.6.tgz` were verified
against registry SHA-512 integrity before use. Bun supplied hardlinks despite
its copy-backend request; every package/core file was verified against its
fresh tarball and replaced with a private inode **before any mutation**. All
465 better-auth files and 350 core files were verified byte-for-byte again after
execution, with link count one and no changed Source bytes. `integrity-final.json`
retains exact hashes. The known modified `/tmp/.d774fec071c1d447-7.better-auth/dist/state.mjs`
was never used. No published package patch or excluded package was added.

The standalone `source-probe.mjs` was executed from
`/tmp/better-auth-close178-source` with its private pinned node_modules. Its
SQLite database and fresh tarballs remain in `/tmp/close178-evidence` and
`/tmp/better-auth-close178-source`; all decisive raw JSON/logs are retained here.
Reproduce by copying the probe into that private package directory and running
Bun after removing only the owned `/tmp/close178-evidence/source.sqlite`.
Native command (inside the owned checkout's existing development shell):

```
CARGO_TARGET_DIR=/tmp/close178-target CARGO_PROFILE_DEV_DEBUG=0 \
CLOSE178_EVIDENCE_DIR=/tmp/close178-evidence \
cargo test --locked --test integration --features seaorm,axum \
  dynamic_provider_callbacks -- --nocapture
```

The original #391 [dynamic-origin receipts](../dynamic-origin-178/README.md)
remain valid and are reused: allowed host/protocol/fallback/forwarded trust,
async origins, original transport hook contexts, actual SQLx/SeaORM sign-in and
magic-link challenge/ownership/consumption/replay proof. #374 already closed
all dedicated factory issues #154–#170. #420 owns advanced signing/account paths,
#421 owns OAuth proxy, and #215 owns passkey behavior; this change does not
reimplement those owners. The rebase onto `7a9d2fa3` included #419 and #420;
origin production bytes were unchanged, and only the affected callback group
was rerun because #420 changed shared OAuth handlers. No global proof replay.

This closes the supported remaining **configuration capability** in #178.
The older inventory of request-dependent social factories is corrected above.
Broader universal equivalence of every OAuth/passkey/proxy composition is not
claimed or needed under the user's targeted-only acceptance policy; those route
families keep their own receipts and authority checks. These scenarios prove the
listed dynamic-base-URL/linking combinations, not all possible deployments.
No full suite, compatibility sweep, coverage gate or mutation campaign ran.
Actions are disabled; no hosted CI result is claimed. Local self-review and
coordinator production review are recorded on the PR; no external review is
invented.
