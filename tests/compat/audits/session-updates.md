# Configured session updates

Target: installed Better Auth 1.7.6 `api/routes/update-session.mjs`,
`db/schema.mjs`, `db/with-hooks.mjs`, `db/internal-adapter.mjs`,
`cookies/index.mjs`, and `@better-auth/core` adapter factory.

POST `/update-session` validates a JSON record before session middleware. It
updates the authenticated current token, ignores undeclared keys, and rejects an
empty allowed patch. Plugin field policies override application policies;
active organization/team and impersonation fields remain input:false. The input
policy uses JavaScript truthiness for read-only values, runs an explicitly
configured synchronous validator before a parsing transform, and does not
implicitly validate values against schema/type metadata.

FieldConfig and FieldValues are public through `better_auth::field_policy`.
FieldValues preserves raw JsValue numbers through callbacks and database binding.
Its collection operations and serialization describe real mapped values. A
separate `has_input_fields` method retains supplied keys whose parsing transform
returned undefined: upstream Object.keys is nonempty even though binding omits
that value. Callback input/output None represents JavaScript undefined, without
adding undefined to JSON values. Creation invokes a configured adapter transform
for omitted fields; update skips omitted/undefined fields unless a before hook
inserts a current value. Input-policy creation defaults are evaluated before hooks;
remaining adapter defaults are evaluated at binding and neither applies on update.
Two immutable registries preserve the source distinction: SessionFields merges
configuration then plugins for parsing/output/default preparation, whereas
SessionAdapterFields merges plugins then configuration for adapter defaults and
transforms. Declared builtin values supplied by trusted creation hooks survive
adapter defaults and reach the configured transform.

Input parsing and adapter binding are separate transform stages. A validator
wins at parsing, but an adapter transform still runs after database before hooks.
Pending callbacks use the current mutated value exactly once at binding; cached
transformed values would incorrectly discard hook mutations. Adapter None output
omits the binding. A thrown callback maps to the pinned empty HTTP500 response;
structured application errors remain explicit. Before-hook cancellation or a
missing persisted row yields FAILED_TO_GET_SESSION and clears session cookies.
Successful writes renew the signed token cookie and honor the signed
rememberMe:false browser preference.

The SeaORM implementation stages configured values on actual application entity
columns and then uses the normal insert/update lifecycle. Existing
ActiveModelBehavior before_save/after_save and explicit overrides remain active.
AuthEntity session derives generate actual column bindings and typed staging;
manual model/store defaults fail closed for nonempty unsupported fields.
TEXT numeric affinity uses the existing SQLite 3.53 formatting compatibility
implementation while preserving raw Infinity and negative zero. JSON columns use
prepared JsonMetadata, including ordinary application keys that resemble serde
private keys. No generic metadata column substitutes for application columns.

Only immutable registered policies expose custom session output fields; hidden
fields and undeclared physical columns stay off the auth wire. The trusted
AuthSession.additional_fields accessor retains all application storage fields
for hooks and session replacement. Manual application routes choosing their own
serialization are unchanged. The output projection must never replace the
persisted token used for authorization.

Evidence:

- Three real SDK scenarios / 382 assertions cover the ordinary no-fields route and two concrete
  custom-schema profiles, one with admin and organization/team policy overrides.
  They compare wire responses/cookies and persisted owner/current-token,
  same-owner second-token and foreign-user state. Controls cover invalid input,
  unsupported media, default/callback values, hidden fields, non-idempotent double
  transforms, validator precedence, raw numeric callbacks/SQLite text affinity,
  JSON, hook mutation, undefined output, callback errors, browser preferences,
  cancellation and deletion. The initial route control fails on the prior Rust
  implementation with HTTP404 versus the pinned HTTP401. A supplemental actual
  config conflict also failed before repair: pinned storage/wire contained
  adapter:configured-default-org while Rust returned null. Its configured hidden
  declaration still returns on the auth wire because the plugin output policy
  overrides configuration, as the source requires.
- The public-builder SQLite test uses a real application AuthEntity model,
  prepared JSON columns, dynamic default count, and persisted native model hooks.
  A nonnull undeclared physical-column sentinel demonstrated a pre-fix output
  leak, then passes with the registered-field projection. A trusted creation-hook
  organization value wins over a conflicting adapter default and is transformed
  before real typed storage binding.
- The manual numeric-ID application schema compiles with default methods and
  rejects an unbound configured field without changing owner, token or updatedAt.
  Existing manual schema ID/migration cases remain passing.
- Existing session SDK and native refresh/policy/lifecycle scenarios remain the
  owners of shared expiry, revocation and middleware behavior. The focused session
  SDK directory passes 16 scenarios / 696 assertions; 15 native sibling cases and
  13 API session unit cases pass. Production crates and the new custom-model
  native test pass strict Clippy; core tests compile, TS typecheck and formatting
  pass. The manual-schema file retains two pre-existing strict test-Clippy
  findings outside the production gate (an assertion-returning-Result test and an
  unused header insertion); its five runtime tests pass.

This evidence covers stateful SQLite TEXT, REAL and JSON application fields.
Secondary-storage/stateless fallback, other backend affinities and every arbitrary
application column type are not proved here. Output transforms, onUpdate adapter
callbacks, asynchronous validators, expiry-update hook branches and cookie-cache
interactions are established by the additional #223 profile evidence below. Default OpenAPI completeness remains open until this endpoint
and configured-field metadata are integrated with the generated document proof.
The 2FA disable replacement helper must preserve trusted additional_fields by
collecting current stored fields into FieldValues; the coordinator owns that
integration.

Explicitly declared builtin-shaped application fields remain visible without the
corresponding plugin; undeclared physical columns stay private. The ordinary
profile declares activeOrganizationId without organization, proves its configured
creation default and current-token update through the SDK and real SQLite state.
The regression failed before the projection repair (Rust omitted the persisted
value while pinned output returned it).

The public AuthContext::new/manual-context projection uses configured field
policies when no immutable runtime registry is installed. Its native real-model
regression failed before the repair by exposing the undeclared physical sentinel;
afterward the sentinel and returned:false fields stay hidden while declared
fields, including a builtin-shaped field without its plugin, remain visible.
Trusted AuthSession.additional_fields continues to return the raw storage data.

Independent JWT-owner review checked input/adapter policy precedence, actual
SQLite bindings, undefined/default/transform hook lifecycle, registered output
privacy and authorization through the immutable persisted token. Review findings
are resolved. The coordinator preserved replacement additional fields and
requires both custom-schema scenarios plus default validation/auth/state proof
in the shared inventory without removing earlier evidence. Final integrated gate passes: 277 SDK scenarios / 8,550 assertions, 37 harness tests /
210 assertions, two Chromium tests / 22 assertions and 78.97% source lines
(24,668 / 31,238). This proves the stateful SQLite slice rather than every storage mode.

## Remaining projection and update hook interactions (#223)

The actual `additional-cached-fields` SQLite application profile now owns
configured update response versus compact-cache and physical readback, omitted
`onUpdate` fields versus explicit updates, signed browser-session preference,
foreign/sibling preservation, and password-replacement snapshots after an update.
The additional async-validation profile invokes session validators with raw
Infinity and negative zero, rejects promises before any binding, and retains the
raw callback observations as explicit numeric sentinels.

The same physical profile runs configured updates and due expiry renewals through
mutation, veto, ordinary before-error, API before-error, after-error, output-error,
and row-deletion branches. It observes real callbacks and database rows: before
errors/veto leave the row unchanged, after/output errors retain committed writes,
and deletion clears authentication cookies. A missing row invokes the new
`SeaOrmHooks::after_update_session_missing` callback after successful before hooks;
a veto does not. Adapter transforms and `onUpdate` run even when a before hook
removed the target row. This remains stateful SQLite evidence.

The baseline cache regression returned the old `session-initial` label after a
successful configured update stored `configured-update`. Updates now publish
through the existing issuance/cache lifecycle. Ordinary database callback errors
abort completed request hooks while explicit API errors retain their response.
Password replacement also honors the actual signed browser-session preference.
Collection projections used during replacement await row callbacks concurrently
in source order, retaining physical token and owner authority throughout.

A replacement regression also exercises Source's intentionally swallowed
collection-projection rejection. A delayed sibling output transform continues
from its original physical snapshot after the rows are deleted and the HTTP
response finishes, with the actual request context retained. The initial
`try_join_all` repair failed this owner by cancelling that callback; the owned
projection worker returns the first error and leaves launched projections alive.
Success results preserve row order. The custom operator now binds rewound dates
as ISO strings, matching the application's real SQLite date columns and allowing
SQL expiry predicates to observe the intended rows.

Public list-sessions projection is separate #328; these update/replacement
owners do not establish that endpoint's configured output parity.

Final focused validation on main plus #223: 28 SDK scenarios / 2,420 assertions
(including 17 new operation owners), 19 native session/cache/policy/adapter tests,
strict production and standalone fixture Clippy, client TypeScript typecheck,
and formatting of changed Rust files pass. Full-suite/coverage gates were not
run for this focused change. Unchanged signup fixture formatting remains an
existing standalone cargo-fmt finding outside this diff.

## Public configured session listing (#328)

The public SDK list owner now runs genuine current, sibling, foreign and expired
sessions in the existing cached custom-column application. Public listing selects
physical active/unexpired rows before projecting configured adapter output,
returns successful projections in physical row order, omits hidden/undefined and
undeclared columns, and leaves every persisted session unchanged. A foreign
caller's list remains scoped to its own physical user.

Two baseline failures establish the repair: a live rejecting output transform
returned Native HTTP200 versus Source HTTP500; an expired rejecting row incorrectly
ran Native's output callback whereas Source excluded it before projection. Active
record selection reuses the existing collection projection worker; all-row
replacement callers keep their existing selection behavior. The route catches
projection errors into an empty HTTP500 while completed request hooks still run.
Two already-started delayed row callbacks finish after that response with their
actual captured `/list-sessions` context. Successful output and physical/cache
credentials are compared through the SDK, full HTTP traces and SQLite state.

A separate observed scheduling question remains: with one immediately completing
normal row alongside rejecting and delayed rows, Native and Source placed the
normal row's remaining output-field observations differently relative to the
completed HTTP500 hook. The controlled rejection owner uses two genuinely delayed
callbacks to establish continuation without forcing microtask ordering through
arbitrary sleeps in production. That fast-row interleaving is not repaired here.

Final focused verification: 23 SDK scenarios / 568 assertions, including the
existing replacement rejection owner, and 13 native session-management tests
pass. Strict production and standalone-fixture Clippy, client TypeScript
checking, changed Rust formatting and `git diff --check` pass. A sibling session
directory run passed 75 cases and exposed the empty500 content-type difference;
the final focused run verifies that repaired transport detail. No full repository
or coverage gate was run for this issue.
