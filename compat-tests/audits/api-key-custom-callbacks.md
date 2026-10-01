# API-key application callbacks

Pinned reference: `@better-auth/api-key` 1.7.6, installed `dist/index.mjs`
(`validateApiKey`, server-only `verifyApiKey`, `getApiKeyFromConfig`,
`findApiKeyAndConfig`, and the matcher/handler before hook). The standalone
1.7.6 official API-key client drives HTTP authentication and protected CRUD.
The local reference fixture configures the actual unchanged plugin.

## Implemented contract

`ApiKeyConfig` and its builder accept optional immutable application getter and
async validator implementations. `ApiKeyCallbackContext` exposes the actual
optional request, immutable authentication configuration, typed application
extensions, and selected configuration ID. Callback captures are omitted from
configuration Debug output. These are public production APIs; the fixture does
not supply authentication results, key lookup results, or quota decisions.

A custom getter replaces that configuration's configured headers. None and the
empty string leave normal cookie authentication in control. Only configurations
that enable API-key sessions are scanned, in registration order. A matching
getter runs twice, as in the upstream matcher and handler; the validator runs
once after minimum UTF-16 key length validation and before persisted lookup,
ownership/configuration checks, or usage consumption. Rejection returns the
upstream 403 INVALID_API_KEY. A successful lookup uses the existing request-local
virtual session, owner lookup, and atomic usage store operation. It creates no
persisted session or replacement cookie.

Server-only explicit verification resolves its requested configuration and runs
its validator before hash/lookup. Rejection preserves the upstream unusual
KEY_NOT_FOUND error whose `message` is an INVALID_API_KEY code/message object.
Implicit verification first loads the actual key and resolves its persisted
issuing configuration. Only that configuration's validator runs; an unknown
implicit key runs no validator. Rejection uses KEY_NOT_FOUND with its ordinary
string message. Disabled-key, expiration, permissions, quota and rate-limit
processing retain their existing order after validation. The existing
`verify_api_key` supports no-request callers; `verify_api_key_with_request`
provides the caller's actual request to the same verification operation.

## Meaningful proof

`tests/api-key/api-key-hooks.test.ts` owns two end-to-end contracts, without
mirrored native HTTP tests:

- The getter ignores fallback headers and empty application credentials. An
  attacker cookie remains the attacker for those cases. Denied predicates,
  insufficient key length and wrong issuing configuration preserve actual key
  rows and session counts. Accepted application credentials authenticate the
  real key owner and allow their protected key read; the same foreign cookie
  alone cannot read it. The original cookie principal remains intact on the
  next request. All callbacks, full client responses, plaintext created key and
  virtual-session token observations, exact two-getter/one-validator ordering,
  and persisted remaining/counters/owners are retained and compared.
- Explicit/implicit validation preserves the different source rejection shapes,
  unknown-key ordering, disabled-key precedence, configuration isolation, and
  real successful quota consumption. Denied calls preserve stored rows; an
  unrelated configuration is not governed by the hook configuration's policy.

One additional native test owns the distinct Rust interface boundary: a trusted
programmatic caller without an HTTP request consults its typed context policy,
rejects without consuming quota, and accepts after the application updates that
policy. It also verifies callback-captured policy secrets are absent from Debug.
The persisted row is read through the actual store.

Before proof used unchanged production at base
`4ce3e86d89bf18f8ed69148787ae233a5b12ffea`. The branch-local fixture omitted
callbacks, which the old public configuration could not represent, and invoked
the old server-only verifier. The two new official-client scenarios failed for
intended capability gaps: the fallback header selected the key owner rather
than retaining the cookie principal; a predicate-denied explicit verifier
returned valid:true and consumed remaining 10 to 9. This is a configuration
capability baseline, not a claim that the old API promised custom callbacks.

Logs:

- `/tmp/api-key-hook-baseline-sdk.log`: two intended baseline failures.
- `/tmp/api-key-hook-oracle-final.log`: genuine TS-to-TS, 2 scenarios / 444 assertions.
- `/tmp/api-key-hook-sdk-final.log`: TS-to-Rust API-key family, 37 scenarios / 920 assertions.
- `/tmp/api-key-hook-native-final.log`: 46 native API-key tests pass.
- `/tmp/api-key-hook-typecheck-final.log`: official-client TypeScript check passes.
- `/tmp/api-key-hook-clippy-final.log`: API library Clippy with warnings denied passes.
- `/tmp/api-key-hook-fixture-build-final.log`: actual Rust fixture build passes.
- `/tmp/api-key-hook-fixture-clippy-final.log`: Rust fixture Clippy with warnings denied.

No comparator exemptions, token substitution, store/schema changes, global
inventory edits, dependency changes, or full compatibility gate were made.

## Explicit limits and follow-ups

The typed getter returns Option<String> and the validator returns bool. Arbitrary
JavaScript non-string getter return types, getter throws, rejected validator
promises, Rust panics, and a non-idempotent getter that loses its key between
matcher and handler have no universal exception parity claim in this slice.

Rust's direct server-only verification methods perform verification, not a
full `auth.api` middleware dispatch. Upstream can run its generic before hooks
around a virtual server-only path, including an additional API-key-session
lookup/consumption when that programmatic call supplies custom key credentials.
The differential server-only calls in this slice pass ordinary request policy
headers without custom key credentials; this middleware variant remains an
explicit gap. The application getter's event recorder intentionally records
HTTP authentication lookups or present custom credentials, rather than adding
side effects to source programmatic calls without credentials.

Secondary storage, cache/fallback/deferred writes, custom key generation,
dynamic default permission callbacks, custom schema and unrelated configuration
families were not expanded. Existing atomic usage and owner/configuration
checks are reused unchanged. The coordinator owns shared inventory, integration,
canonical full gates and publication.

Coordinator independent review checked the installed matcher/handler and trusted
verifier ordering, callback error shape, owner/config isolation and actual quota
assertions. The bounded contract is clear. Shared inventory now requires the
customized HTTP principal success/rejection/authorization and state evidence,
retaining every earlier requirement. Trusted server-only verifier proof remains
private rather than inventing a public authentication route. Final canonical
validation is pending.
