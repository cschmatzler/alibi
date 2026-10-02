# Runtime helper and telemetry boundaries (issue #194)

Reference: the unmodified installed Better Auth **1.7.6** packages, and the
matching tag commit/archive recorded in `../upstream-source.json`. No package,
lockfile, comparison, route inventory or coverage requirement changes here.
The source experiment uses supported `betterAuth(options)`, awaits `$context`,
and invokes its real `publishTelemetry`; it never substitutes a telemetry
factory, guessed configuration object, authentication result or stored receipt.

## Telemetry is a runtime integration

`better-auth/dist/context/create-context.mjs` calls `createTelemetry(options,
{ adapter: adapter.id, database: ... })` during normal application initialization.
Both `@better-auth/telemetry/dist/index.mjs` and `node.mjs` implement these gates:

- Default telemetry is disabled. With neither `BETTER_AUTH_TELEMETRY_ENDPOINT`
  nor the separately exported factory's `customTrack`, even enabled collection
  is a no-op. Normal `betterAuth` initialization does not supply `customTrack`.
- `BETTER_AUTH_TELEMETRY=true` OR `options.telemetry.enabled` enables collection;
  explicit option false does not override environment true. Test environments
  suppress it. The standalone factory supports `skipTestCheck`, but normal
  application initialization does not supply that override.
- Enabled collection invokes configured social-provider callback factories
  while collecting their configuration, in addition to the invocation by normal
  provider initialization. This is an observable callback side effect.
- An `init` event contains actual auth configuration flags, adapter/database,
  installed plugin IDs, runtime, environment and anonymous project ID. The Node
  entry additionally reads local package metadata and OS/container information.
  These detectors and their fingerprinting are platform embedding behavior,
  rather than an authentication protocol or a safe Rust configuration dump.
- Initialization starts `track` without awaiting delivery. It occurs before
  plugin initialization completes: a later rejecting plugin still leaves an
  observed local `init` receipt. `publishTelemetry` awaits tracking. Promise
  rejections in tracking are caught and logged upstream. Debug selects logging
  instead of HTTP; its visibility also depends on the global logger level.

The committed fresh-process capture owner,
`harness/runtime-boundaries.test.ts`, executes
`reference-server/runtime-boundaries.mjs`. Its loopback receiver retains complete
JSON events; all original helper return values and resulting memory-adapter
rows are retained in the process receipt. Nine cases exercise default, explicit
disable, explicit enable, environment enable despite option false, test
suppression, missing endpoint, debug, local HTTP 500 and plugin-init rejection.
They observe one normal provider-factory call versus two with active collection,
actual initialized adapter/database/plugin metadata, shared anonymous ID across
init and application publication, no secret values in captured configuration,
and continued real helper/session operations after the HTTP failure. The
Node-conditioned telemetry collector is selected under Bun and its actual OS
metadata is retained in the receipt. Machine/package detector values remain
platform boundaries, not frozen fixtures or asserted Rust equivalents.
No remote telemetry, account, credential or paid service is needed.

Native applications opt in with
`AuthBuilder::telemetry(TelemetryConfig::new(application_sink))`, implement the
public asynchronous `TelemetrySink`, and can call `BetterAuth::publish_telemetry`
with a `TelemetryEvent`. `TelemetryConfig::default()` disables collection;
`.enabled(false)` disables an installed sink. Nothing implicitly reads telemetry
environment variables or creates an outbound transport. The host owns its sink,
transport, retention and application-event payload privacy.

After successful native plugin/config/store initialization, one awaited `init`
event contains only library version, Rust runtime label, target OS/architecture,
and ordered installed plugin names obtained from the real builder. It does not
serialize `AuthConfig`, call provider factories, read package files, identify a
project, fingerprint the machine or inspect user/session/credential data. This
bounded native metadata and awaited successful-initialization timing are explicit
native contracts, not claims of identical TypeScript detector contents or
hot-track timing. Failed config or plugin initialization emits no native event.
A sink error logs only a constant warning and does not fail initialization or
subsequent authentication; payload/error contents are not logged. Delivery is
awaited, so the application should bound its sink latency.

The native lifecycle owner exercises disabled, successful and rejecting sinks
through real `AuthBuilder::build`, preserves the entire seeded physical user,
and dispatches a real initialized plugin handler. It also rejects configuration
and plugin initialization without sink calls. Before implementation, its public
telemetry requirement failed compilation because that integration was absent.
Existing lifecycle sibling owners retain the request/hook/cookie contracts.

## Privileged test helpers have real effects

The bundled `better-auth/dist/plugins/test-utils/index.mjs` installs instance
context helpers and optional verification-create hooks; it registers no public
routes. Its `factories.mjs`, `db-helpers.mjs`, `auth-helpers.mjs`,
`cookie-builder.mjs` and `otp-sink.mjs` own these operations:

| Source operation | Observable contract / native embedding owner |
| --- | --- |
| `createUser`, `createOrganization` | Generate an object without writing storage. Rust uses application-owned typed creation values and schema/entity types; no JS factory inference API is copied. |
| `saveUser`, `deleteUser` | Trusted internal-adapter writes, hooks and user/account/session deletion. Native typed `AuthStore` operations and initialized store policies; actual user-lifecycle SDK owner retains full physical rows and foreign-state/deletion evidence. |
| `login`, `getAuthHeaders`, `getCookies` | Each creates a persisted session, with signed session-cookie transport. `login` also loads/rejects the supplied user. Native `SessionManager`, typed store and cookie utilities are privileged application APIs; ordinary SDK signin/session owners prove signed-cookie authentication, expiry/revocation and physical ownership. This is not a public bypass-login route. |
| Organization save/delete/add-member | Privileged adapter writes; deletion removes members/invitations, add defaults role to member. Native typed organization/member/invitation stores remain application-owned. Trusted endpoint dispatch additionally offers the plugin's real validated `addMember` operation; SDK member-addition and deletion owners retain authorization and physical effects. The raw test helper is not the validated endpoint. |
| `captureOTP`, `getOTP`, `clearOTPs` | Verification-create hook captures the first colon-separated part of the stored value, stripping known identifier prefixes, in an instance-local map. It can capture a transformed/hash value; it does not decrypt storage. Native tests install actual delivery callbacks/adapter after-hooks and keep their own capture map. Existing passwordless OTP and trusted-dispatch owners prove genuine issued codes, scoped rows, expiry, attempts and replay rather than accepting a fixture-supplied code. |

The new Source owner observes factory zero writes, saved user, actual login and
signed-cookie `getSession`, missing-user login rejection with every row unchanged,
three separate session rows, organization/default
member writes, actual plaintext OTP issuance, instance isolation, clearing, and
actual user/session/organization/member deletion. Those receipts establish that
the helper family cannot be dismissed as type-only. Rust does not install an
extra privileged test-utils plugin in production: tests/application embedding use
existing native public stores, lifecycle hooks, session manager, cookie helpers
and controlled fixture operations. The stronger existing differential owners are
`tests/passwordless/email-otp.test.ts`, `tests/server-endpoints/dispatch.test.ts`,
`tests/organization-extensions/member-addition.test.ts` and the user-lifecycle
owners described in [user-lifecycle.md](user-lifecycle.md) and
[server-endpoint-dispatch.md](server-endpoint-dispatch.md).

`@better-auth/test-utils` is a different package. The matching tag's
`packages/test-utils/package.json` exports `/adapter` and `/scim`.
`src/adapter/test-adapter.ts` constructs adapter instances, registers Vitest
suites, runs caller migrations in beforeAll, deletes test rows in afterAll,
refreshes adapters and invokes configured cleanup/statistics callbacks. These
are real test-harness effects when invoked, not authentication startup effects.
Native store owners (`crates/seaorm/src/store/sessions/mod.rs`), migration
owner (`crates/seaorm/src/store/migrator/mod.rs`) and
`tests/oauth_account_transaction_tests.rs` own their Rust counterparts;
TS/Vitest suite registration, JS ID generators and cleanup embedding are not
native library APIs. Custom adapter backend semantics remain #192. SCIM is an
explicitly excluded target and is not reopened here.

## Access helpers and type/tooling boundaries

`plugins/access/access.mjs` returns a runtime role with `authorize`, not just
inferred types. It rejects unknown resources, missing actions and empty action
requests; it supports resource AND/OR and per-action AND/OR. The new Source
receipt checks actual allow/deny/unknown/empty and OR branches. Native public
`AdminConfig.roles` / organization role configurations and their actual
permission endpoint/operation owners establish default whole-role authorization,
no cross-role whole-request union, foreign-principal denial and unchanged stored
state: see [admin-permission-config.md](admin-permission-config.md) and
[organization-dynamic-roles.md](organization-dynamic-roles.md).
Alternative operators/utilities and malformed legacy permission representation
are explicitly owned by #220; this boundary audit does not duplicate that API or
claim its unproved branches complete. Role-builder generic/type inference is a
TypeScript embedding boundary; the runtime authorization it feeds is not.

`plugins/additional-fields/client.mjs` merely returns client plugin ID/version
and an empty `$InferServerPlugin` marker; its schema argument has no runtime
validation/write effect. Rust derives typed schema/entity interfaces. Real
additional-field policy, validation, transformation and persistence remain the
separate implemented owners documented in [additional-fields.md](additional-fields.md).

The tag's `packages/cli/src/index.ts` is a standalone `auth` command process:
it loads dotenv, installs signal handlers and dispatches configuration-loading,
schema generation/migration, secret generation, diagnostics, initialization,
upgrade and external service commands. Loading an application TS config can
execute its initialization (including the telemetry effects above), and migrate
or create-admin commands can mutate the database. This is an explicit Node/TS
CLI embedding boundary, not a claim that tooling has no runtime effects.
Native schema generation belongs to `crates/cli`; application migrations and
privileged account creation use native schema/store interfaces. TS config
execution, JS adapter generators, package-manager installation and remote CLI
service integrations are not copied into the native authentication library.
The private `packages/release-tooling` package is version `0.0.0` in this tag.
It and changeset/publish workflows manipulate build,
version, package and release artifacts when run; they are release tooling, not
an authentication initialization hook.

Focused proof for this change is recorded in its PR. The canonical `devenv test`
gate remains unchanged and is run at the campaign batch boundary; these focused
observations are not a claim that the complete suite or coverage gate passed on
this individual issue tree.

## Focused validation record

On the candidate rebased onto `3c7cc4bb0262789a232fe822c9d8338fc773f0a8`:
Source capture passes **9 modes / 199 assertions**; the native lifecycle owner
passes **11 tests** with Axum/SeaORM enabled; strict library/lifecycle Clippy,
TypeScript, actual compatibility-fixture build, formatting and strict Rustdoc
pass. Independent architecture/privacy review found no raw configuration,
credential, sink-error or personal-data serialization in the native path.

The existing admin-permission, OTP issuance/replay/rejection/concurrency and
organization member-addition slice runs **16 pass / 1 fail / 1,768 assertions**.
The failure contains only ten `expiresAt` timestamp comparison cells in
`organization addition trusted role patches are unvalidated and before versus
after errors retain exact writes`; the candidate repeat has the same result.
A separately built detached clean-main `3c7cc4bb` runs the identical slice with
**the same 16 pass / 1 fail / 1,768 assertions and timestamp-only drift**
(`/tmp/issue194-clean-main-full-slice.log`). Clean-main isolated execution passes
1 / 396 assertions, while candidate isolated execution still reports that
timestamp comparison failure. Thus the complete matched slice demonstrates an
existing timing-sensitive failure; it remains unresolved and is not presented
as a green slice or a new telemetry regression. No timestamp tolerance, oracle,
state observation or comparison is changed. The candidate repeat and isolated
records are `/tmp/issue194-focused-sdk-repeat.log` and
`/tmp/issue194-candidate-isolated-timestamp-owner.log`.

After the serialized predecessor merged, the final candidate was rebased onto
`0121fc79e3e06f101818975861a50c8dea142c6a`. Minimal final checks pass again:
strict library/lifecycle Clippy with Axum/SeaORM, 11 native lifecycle tests,
9 Source capture modes / 199 assertions, formatting and diff checks. The
unrelated SDK slice was not repeated after this rebase.
