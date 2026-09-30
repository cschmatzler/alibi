# Organization input validation: Better Auth 1.7.6

This bounded slice ports the create/update organization input schemas, JSON media/error handling, validation before authentication/policy evaluation, and validation of the public trusted Rust creation helper. It does not claim complete organization adapter or lifecycle parity.

## Source and implementation contract

The pinned declarations are `better-auth/dist/plugins/organization/routes/crud-org.mjs`: `createOrganizationBodySchema`, `updateOrganizationBodySchema`, `createOrganization`, and `updateOrganization`. `better-call/dist/utils.mjs::getBody`, `router.mjs`, and `context.mjs::createInternalContext` establish body decoding before endpoint validation/middleware. The installed Zod English locale supplies ordered errors, including nonfinite Number type names. Actual unchanged Bun runtime probes confirmed the contract before production edits.

Creation validates name and slug as nonempty strings, then nullish string logo, optional record metadata, and optional boolean keep-current selection, in declaration order. The coercible public `userId` field never supplies authentication authority. Update validates the required data object and its declared name/slug/logo/metadata fields before the optional string organization selector. Optional name/slug accept omission but reject null and empty strings. Neither slug declaration has a maximum length of 100. Unknown input fields retain the existing stripped DTO contract.

Metadata must be a JSON object at the input boundary. Null, arrays, strings, numbers, and booleans are rejected before callbacks, limits, authentication, or storage writes. A private `JsValue` decoder preserves an overflowing numeric token until validation: raw `1e400` produces the upstream `received Infinity` error instead of an invented null or parse failure. Accepted record values then use the existing JSON conversion/storage contract; nested arrays and null values remain allowed, and an explicit empty record is retained.

The allowed-media check precedes JSON parsing and retains the original header in 415 responses. JSON syntax errors use `BAD_REQUEST` / `Invalid JSON in request body`. Case-insensitive `APPLICATION/JSON; charset=utf-8` is accepted. Ordered endpoint validation precedes session lookup. A schema-valid update without a session returns 401 with `{ "message": "User not found" }` and no error code, while malformed guest input receives the schema error first. The existing creation guest response and persisted-session ownership checks remain unchanged.

`OrganizationPlugin::create_organization_for_user` validates its typed request before resolving the selected persisted user. Its public return type remains `AuthResult`; ordered validation errors use the shared `AuthError::Api` contract with status 400 and code `VALIDATION_ERROR`. The helper remains a trusted server API, not a registered HTTP authority selector. Only the private compatibility fixture exposes it, matching the actual upstream server API without request/session headers.

## Observable proof and primary test ownership

Four official-client differential scenarios in `tests/organization-extensions/input-validation.test.ts` own this boundary:

- Record-only metadata rejection on create and update at an already-reached asynchronous limit, with raw overflowing Number controls, unchanged policy receipts, and persisted organization/member/session/orphan observations. A valid nested record and `{}` retry establish successful response and exact stored JSON text.
- Ordered malformed guest input before authentication, rejected authenticated empty/null updates, malformed JSON, the schema-valid guest response, and a successful persisted name/slug retry preserving metadata and session selections.
- Unsupported text/form media with a deliberately invalid JSON body, proving 415 precedes parsing, callbacks, and writes; uppercase JSON retry and a slug longer than 100 establish successful state transitions.
- Trusted helper validation before missing-user lookup, record rejection for actual typed metadata values, and a corrected trusted call under a static public-creation denial, with real membership ownership, stored metadata, and unchanged sessions.

State observations query real SQLite organization/member/session records and unowned organization rows. `includeMetadata=true` explicitly adds a raw SQL metadata column to the existing private state projection for this slice. The established creation-policy projection remains unchanged. This avoids pretending the two adapters store absent metadata identically: upstream absent metadata is SQL NULL, while the bundled Rust JSON model stores JSON text `"null"`. The new persistence controls intentionally create actual records with metadata and compare their raw text; no comparator exception or response normalization was added.

All four scenarios fail against the prior parser/helper with the canonical metadata repairs and shared error type retained. The failures are specifically metadata reaching a limit check instead of validation, the old JSON missing-field response instead of ordered schema errors, JSON parse 400 instead of media 415, and user lookup 401 instead of trusted input validation 400. Existing stronger creation-policy ownership/configuration tests remain separate and run unchanged as siblings. Final focused validation passed ten SDK scenarios / 590 assertions (four new / 288, six existing / 302), 32 organization API tests, two native SQLite creation/metadata tests, strict library and compatibility-fixture Clippy, client TypeScript, the bounded reference-fixture TypeScript check, both Rust format checks, and diff validation. A broader API all-target Clippy attempt remains blocked by existing integration-test unwrap/panic lint failures; no such test policy was weakened.

## Remaining adapter and configuration boundaries

Actual pinned runtime probing found three separate mutation/storage branches outside this input repair: clearing an existing logo with explicit null, an empty update object reaching the Bun adapter's empty-update error, and a blank organization selector falling back to the active organization. Their current Rust adapter/request representation differs. This change accepts their schema-valid inputs but does not invent adapter errors, add a null patch seam, or alter selector dispatch. Those branches require their own persistence evidence and implementation contracts.

Configured organization additional fields, lifecycle hooks, custom model/adapter policies, and uncommon composite media strings or distinctions between absent and transport-level empty body streams remain outside the focused proof. The existing fixed/adaptive creation count pagination boundary is recorded in `organization-creation.md`. Canonical absent/empty/populated metadata response and getter fixes are prerequisites, owned by the coordinator; this slice preserves them.

Coordinator independent review inspected the source declarations, Better Call
decoding, ordered parser, public typed helper, actual callback receipts and SQL
observations, plus all four intended before-fix failures. The bounded contract
is clear. Inventory requirements append actual successful retries, schema/media
rejection, guest update authorization and persisted state without inventing a
public route for the trusted helper. Integrated canonical validation is pending.
