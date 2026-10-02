# OpenAPI/reference parity investigation (Better Auth 1.7.6)

The generator/reference defaults and configuration branches are implemented and
proved with strict whole-document differential profiles on equivalent, explicitly
core-configured instances. That ordinary fixture document includes the real
`/update-session` endpoint and all implemented core annotations.
The earlier temporary `/update-session` disabledPaths branch has been removed.
Source-backed annotation tables cover selected plugin declarations; untested
configuration branches remain explicit below rather than a full-parity claim.

## Runtime contract and implementation

Pinned sources: `better-auth/dist/plugins/open-api/{index,generator}.mjs`,
`@better-auth/core/dist/db/get-tables.mjs`, and each owning endpoint/plugin schema.
The runtime serves `/open-api/generate-schema` and `/reference` by default;
`path`, `theme`, `nonce`, and `disableDefaultReference` are application options.
The generated document is OpenAPI 3.1.1 with upstream info, security schemes,
security, server base URL, model schemas, tags and operations. The OpenAPI plugin
excludes its own endpoints from the document. Disabled paths and server-only
annotations are omitted. The reference page embeds the complete generated
schema and the pinned MIT-licensed upstream brand asset, with the nonce on its
two executable scripts. Disabling the reference produces an empty 404 response
that retains the application/json header; schema generation remains public.

The production builder obtains actual routes from registered plugins and collects
rich endpoint/model annotations after all plugin initialization. It stores an
immutable registry in context extensions and on the auth instance. `AuthRoute`
fields and dispatch ABI are preserved. Custom plugins provide the typed
`openapi_metadata` hook, including parameters, request body, responses, explicit
operation IDs, tags, descriptions, and server-only policy. Operation ID collision
resolution uses method suffixes and numeric suffixes. Path parameters are added
only when a corresponding path parameter was not already supplied.

The chosen `AuthSchema::openapi_models` supplies its core accessor-backed wire
projection and may declare additional field policies. Registered plugin models
are merged by logical field name; optional SQL columns do not activate plugins.
Model fields preserve type/format/array/nullable/default constraints, input and
returned policies. `returned:false` fields remain documented but are excluded
from required lists; `input:false` adds readOnly. Dynamic defaults are omitted.
Documentation metadata does not itself install storage behavior. Session config
field policies also drive the implemented input/output/storage lifecycle, whose
actual application columns must be declared independently. Callback defaults
remain omitted from metadata and are never evaluated during document generation.


The author-time `port-openapi-annotations.ts` reads pinned factory endpoint
declarations, Zod annotations and model fields. It ports only the installed
generator's parameter/body conversion helpers, with their SHA256 recorded in
the Rust source headers; it never invokes endpoint handlers, the complete
generator, or captures an oracle document. The resulting endpoint/model tables
are ordinary compiled Rust metadata. Runtime documents still derive from actual
Rust plugin registration, chosen schema, config and overlays; production has no
TypeScript dependency. Plugin user inputs are merged only into the source's
sign-up/update-user request schemas, with source core keys retaining precedence.
Chosen-schema model field overrides apply after registered plugin model fields,
matching the upstream table policy. Documentation does not install those input
or storage behaviors.

## Minimal builder and core-module boundary

`AuthBuilder::new` installs the implemented core modules during build, before
initialization and metadata collection. Explicit core plugins retain their
configuration; defaults are appended after application plugins so their dispatch
priority is preserved. The implicit email/password module disables both
credential authentication and username support. Change-email and deletion are
registered but their handlers retain the pinned disabled-feature guards.
No social provider is installed by the implicit OAuth module.

The `openapi-minimal` profile omits upstream email/password and user options and
installs only OpenAPI on the Rust builder. Its complete runtime document and
reference frame match the pinned minimal instance. Actual requests prove null
unauthenticated session lookup, disabled credential signup/signin, protected
session-list/change/deletion rejection, and authenticated disabled change/delete
outcomes. An explicitly configured instance issues the session used for those
last checks; the minimal instance preserves that user's email and session.

The registry retains all actual registrations. `SERVER_ONLY` metadata excludes a
route from both the document and HTTP resolution, while trusted dispatch remains
available. The custom profile proves that distinction through the real upstream
API and native `BetterAuth::dispatch_endpoint` behind a controlled fixture
interface. Upstream `scope: server` hiding retains HTTP and document visibility;
disabled paths independently return 404 and disappear from docs. Transport
middleware and physical on-request hooks still precede HTTP resolution.

## Focused proof and test ownership

Fourteen official SDK/raw HTTP scenarios compare complete ordinary and configured
documents, every model field/required list, security and endpoint metadata. The
reference profiles compare embedded JSON with the same complete document and
compare the remaining HTML frame verbatim. Fixture origins use the existing
narrow URL comparison. No comparator exceptions, field exclusions, or generated
oracle captures were added.

Profiles cover minimal initialization, last-login database enabled/disabled metadata, default options, configured path/theme/nonce and disabled `/error`,
disabled reference, JWT Jwks, username inputs, chosen custom user schema policies,
custom entity models and enum/array/date user-field policies, and combined admin/organization/two-factor/API-key/passkey/device/JWT/phone/SIWE/
multiple-session registrations. Teams/dynamic-role flags and configured API-key
rate defaults are compared in whole documents. Optional bundled columns alone
do not activate models. All profiles include the real `/update-session` endpoint;
its SDK persistence proof is owned by [session updates](session-updates.md).

The custom profile declares its application fields and a plugin-owned Document
model explicitly. Complete documents prove enum types, nullable described bodies,
query descriptions, dynamic-default omission, literal defaults, private/read-only
policies, path parameters for idiomatic Rust `{id}` routes, and duplicate
operation IDs. Undeclared optional storage columns remain absent from the model.
The last-login database option now publishes its actual initialization flag to
the generator; its default profile does not advertise that field.

Two actual application session-schema profiles use real TEXT/REAL/JSON columns.
Their documents derive from config field types and explicit required/input/returned
policies, literal defaults, and callback-default omission. The config-over-plugin
table metadata precedence is source-distinct from plugin-over-config runtime
input/output policies: a configured required, returned:false organization field
is documented with its raw config default and excluded from required, while
session SDK proof confirms its adapter-transformed persisted value is returned
and its plugin read-only input policy rejects writes. A before-fix actual SDK run failed both custom-schema profiles because Rust
omitted the configured label field; pinned declarations already exposed it.
The public native generator
also proves that a stateful creation-default callback is not invoked by docs.

The native application extension test owns the Rust-specific metadata contract:
chosen application schema metadata and custom plugin definitions reach the HTTP
schema and embedded builder, actual route dispatch keeps working, equivalent
path/query parameter names remain independent, duplicate operation IDs receive
a method suffix, rich nullable/union/array body schemas survive, and hidden/read
only policies do not accidentally become required fields. The independent actual
route snapshot retains documentation-disabled/server-only and OpenAPI-own routes.
The native Rust-only `/__test/openapi.json` embedding endpoint is included in that
snapshot and is exercised through the public handler. It is explicitly marked
as a native extension: the default pinned-equivalent document omits it, while
`include_native_extensions` and the embedded builder's corresponding method
include it. Both choices retain actual registration and have native HTTP proof. Inventory consumers must use registration independently of
OpenAPI documentation exclusions. The SDK scenarios own
built-in schema and HTML behavior; native tests do not duplicate those flows.

Focused #191 results: 63 SDK OpenAPI/user-management scenarios / 2,640
assertions; 12 native user-management lifecycle checks; six native application
metadata/builder surface checks; strict API/core/root production Clippy and client
TypeScript check. The original production code fails the final owner fixtures
for missing minimal routes, configured last-login metadata and enum inputs.
Root batch validation owns the integrated canonical `devenv test` gate.

## Remaining work

- New plugin configuration branches require their own runtime evidence; source
  tables alone do not establish them. Implemented last-login, organization
  teams/dynamic-role and API-key rate-default model branches have complete
  runtime document comparisons.
- OAuth's existing Rust route template uses `{provider}` while pinned source uses
  `:id`; an explicit canonical document-path annotation preserves the route ABI.
  An independent actual handler probe confirmed that upstream HTTP disabledPaths
  matches the requested literal path, while its generator filters declared
  endpoint templates: `/items/:id` omitted from docs still serves `/items/value`,
  and disabling `/items/value` returns 404 before the handler. Rust's existing
  literal dispatch policy matches upstream; no dispatch correction is required.
- Additional application schemas must explicitly supply documentation fields;
  their explicit `AuthSchema::openapi_models` declarations are the public
  application interface; arbitrary stored extra columns are not inferred. Session fields now have explicit policy integration and proof;
  custom enum schemas and the implemented model configuration branches now have
  complete runtime document evidence. Deriving arbitrary private columns remains
  deliberately unsupported.

## Integrated review and canonical validation

The coordinator registered the actual OpenAPI plugin in the native inventory
fixture and changed route enumeration to the public registered-route snapshot,
independent of documentation filters. Only the exact GET native embedding route
is outside the pinned upstream HTTP inventory. A meaningful retained native
contract exposed lost custom Rust plugin operation identifiers; the metadata
fallback is repaired while the source `/ok` operationId omission is preserved.
Independent SIWE-owner review of both repairs is clear.

The final canonical gate passed on 2026-10-01: 327 SDK scenarios / 11,256
assertions, 39 harness tests / 243 assertions, two Chromium tests / 22 assertions,
all native/optional-feature/Rustls/Redis/TypeScript/documentation checks, and
79.95% source lines (26,998 / 33,768). The capability report has 143 routes,
five unimplemented identities and zero implemented routes without success
evidence. This is bounded document/reference parity, not full runtime parity.
