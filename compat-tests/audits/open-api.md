# OpenAPI/reference parity investigation (Better Auth 1.7.6)

This family is **in progress**, not full parity. The first generator/configuration
slice is implemented and proved with strict whole-document differential profiles.
The ordinary default document still differs: `/update-session` is not implemented,
while the implemented core families now have source-backed endpoint annotations.
Checked-in source-backed annotation tables cover the pinned declarations of the selected plugin families. No default-complete scenario is claimed or silently filtered.

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
Documentation metadata does not install input parsing, output projection, or
custom-field persistence. Applications must declare the policies they implement.


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

## Focused proof and test ownership

Nine official SDK/raw HTTP scenarios compare the complete configured document,
including all implemented core sign-in/social/session/password/email/account/user operations, every model field/required list,
security and endpoint metadata. They compare embedded reference JSON with that
same complete document and compare the entire remaining HTML frame verbatim.
Fixture origins use the existing narrowly scoped URL comparison. There are no
new comparator exceptions, field exclusions, or oracle document captures.

The profiles explicitly disable only the pending `/update-session` endpoint in both real runtimes:
this is the supported application configuration under test. They exercise default
OpenAPI options, configured path/theme/nonce plus disabled `/error`, disabled
reference, an actual registered JWT plugin's Jwks model, username inputs, a chosen custom
schema with returned/input policy, and combined admin/organization/two-factor/
API-key/passkey/device/JWT registrations. Organization team and dynamic-role
flags and API-key configured rate defaults are compared in whole documents.
Optional bundled columns do not register plugin models. The default-document gap remains independently
listed above. The strict default-complete scenario must be added when its core
prerequisite and remaining annotations land.

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

Focused result for this core/configuration slice: 9 SDK scenarios / 396 assertions, one native
application extension test, API/core/root production strict Clippy and client TS
check pass. Existing core embedded builder checks are retained. Full gates,
shared inventory/lock finalization, and publication belong to the coordinator.

## Remaining work

- Configuration branches of plugin models beyond the combined profiles require
  their own evidence. Source tables alone do not establish those branches; for
  example a future last-login-method plugin must publish its database flag.
- `/update-session` core prerequisite, followed by strict ordinary default whole
  document evidence; it cannot be replaced by disabling that route silently.
- OAuth's existing Rust route template uses `{provider}` while pinned source uses
  `:id`; an explicit canonical document-path annotation preserves the route ABI.
  An independent actual handler probe confirmed that upstream HTTP disabledPaths
  matches the requested literal path, while its generator filters declared
  endpoint templates: `/items/:id` omitted from docs still serves `/items/value`,
  and disabling `/items/value` returns 404 before the handler. Rust's existing
  literal dispatch policy matches upstream; no dispatch correction is required.
- Additional application schemas must explicitly supply documentation fields;
  derive convenience is not yet installed, and arbitrary stored extra columns
  are not inferred. Dynamic default presence and arbitrary custom enum input
  policy need explicit field-policy integration and proof.
