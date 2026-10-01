# API-key application issuance and forced cleanup

This bounded capability follows installed Better Auth 1.7.6
@better-auth/api-key/dist/index.mjs creation (729–858), update (1524), forced
cleanup (863), normalization (2325), and delete helper (2060). It depends on the
separate getter/validator capability c530332, typed session cancellation 1655472,
intentional public Api error 56299c2, and comparator correction 61ef0c2. Local
prerequisite cherry commits are not additional capability changes.

Immutable per-configuration Arc callbacks expose only source-relevant inputs:
ApiKeyGenerator receives length and effective prefix and owns its full returned
key; ApiKeyDefaultPermissions receives the resolved reference and existing
read-only ApiKeyCallbackContext. HTTP creation supplies the actual request;
trusted programmatic creation supplies no request. Debug reveals callback
presence without exposing captured application state. Zero key_length resolves
to 64 in builder, with_config and configuration, matching source's ||64 before
both generation and authentication use the effective configuration.

Generation precedes hash/start derivation, then dynamic defaults run even when
explicit server permissions override their result. Callback failure prevents
key persistence. Source APIError equivalents (domain 4xx, Upstream, Api including
public 500) retain their public status/code/message over HTTP; internal errors
produce source's empty 500. Trusted create_key retains its typed AuthResult.
Ordinary full-scalar UTF16 substring behavior selects stored start from the
returned full secret. The generator does not receive fabricated request context
or automatically prepend a prefix to its return value.

ApiKeyPermissions uses ordered IndexMap for static/dynamic/explicit creation and
updates. The existing JS JSON writer sorts numeric object keys and retains
ordinary insertion order. ApiKeyView uses the existing safe JSON parser so a
singleton literal $serde_json::private::RawValue resource remains ordinary data.
No arbitrary_precision/private marker exemption is introduced.

Trusted delete_all_expired_api_keys bypasses the existing ten-second throttle
and awaits deletion across all owners/configurations of non-null expired rows.
Adapter deletion failures are logged, success:true/error:null is retained, and
an immediate forced retry is allowed. There is no new public HTTP endpoint.

Three official-client scenarios own the real configured lifecycle:

- Actual custom keys authenticate the persisted owner while foreign cookies and
  rows retain their owners; denied permissions consume no quota, accepted
  authentication consumes exactly one remaining use. Exact stored hashes,
  Unicode full key/start, configured prefix independent of that key, static and
  dynamic permissions, issuing configuration, explicit overrides and private
  resource names are retained and read back from real SQLite/public get/update.
- Client authority fields and anonymous creation reject before callbacks.
  Generator/default failures retain order, create no key, and allow a valid
  retry. Deliberate Api 500 remains public. A failed default callback prevents
  persistence even with an explicit server permission override.
- Forced cleanup deletes two expired owners/configurations, preserves live and
  unlimited rows and quotas, invalidates actual get/verify, then deletes another
  expired key within ten seconds. The unsupported public path is actually 404.

The primary native cleanup test owns a distinct backend failure unavailable to
those SDK flows: a real installed SQLite delete-rejection trigger leaves every
field of the expired key and user unchanged while the forced method succeeds;
dropping the trigger and retrying immediately removes only that key. The actual
pinned SQLite trigger oracle agrees in
/tmp/api-key-generation-cleanup-error-oracle.log. Existing native tests retain
all earlier creation, verification and owner boundaries; no primitive mirror,
mock persistence, test-only production flag or helper export is added.

Before evidence and scope:

- /tmp/api-key-generation-baseline-sdk.log runs the actual pre-capability
  production owner at 9b1eb60 with equivalent supported prefix/length/config/rate
  settings and new fixture controls only. It cannot express the new application
  callbacks or forced cleanup; callback implementations/registrations and the
  nonexistent cleanup controller are omitted rather than fabricated. Three
  intended failures show the built-in random key, accepted generation despite
  application rejection, and absent trusted cleanup (404). These prove missing
  capabilities, not regressions in previously supported configuration.
- /tmp/api-key-generation-length-zero-before.log proves a distinct actual
  partially implemented callback configuration defect: source normalizes zero
  to callback length 64 while Rust passed 0 (other two cases pass).
- /tmp/api-key-generation-private-wire-{source,before,after}.log retains complete
  official-client creation/get traces using the ordinary default configuration,
  without new callbacks. Source and repaired Rust retain the literal resource;
  the old wire parser returns null in both real creation/read responses.
- /tmp/api-key-generation-prefix-sdk-before.log proves the separate old
  comparator rejects an otherwise successful official-client TS→TS Unicode key
  only for its impossible mandatory configured-prefix relationship. The frozen
  comparator prerequisite preserves all complete key/storage observations.

Explicit unresolved boundaries: source automatic deletion STARTS before the
application generator without awaiting it. A fresh-process real SQLite probe
seeds an expired row and the failing generator still observes that row
(/tmp/api-key-generation-automatic-order-oracle.log). Rust's preexisting
post-insert awaited automatic cleanup is deliberately unchanged: AuthContext
has no production background-task contract to represent the source invocation.
This capability does not close automatic cleanup trigger/error/timing parity,
source's module-global throttle versus Rust's per-plugin throttle, or arbitrary
backend/captured-callback scheduling. Forced cleanup above is explicitly awaited
and proved independently. There is no sleep/yield workaround or fabricated
callback snapshot. A centrally coordinated background-task contract is a future
prerequisite for automatic cleanup parity.

Also unproved: splitting a UTF16 surrogate (actual Bun SQLite replaces a lone
surrogate differently from Rust String; /tmp/api-key-generation-oracle-split.log),
invalid JavaScript generator/callback return types, rejected Promise/panic
representation, other zero/nonfinite option normalization, full trusted endpoint
context/body access beyond the typed context, organization-reference callback
profiles, custom store/schema/cache/secondary-storage adapters, and generic
server API middleware dispatch. Existing public validation ordering gaps are
not claimed closed. Ordered permission constructors now use the public alias;
this is an intentional typed API change approved for the integration.

Validation logs are /tmp/api-key-generation-sdk-final.log (40 API-key SDK cases,
1,586 assertions),
/tmp/api-key-generation-oracle-final.log (three TS→TS scenarios, 666 assertions),
/tmp/api-key-generation-native-final.log (52 native cases, existing family plus one
backend-failure case), /tmp/api-key-generation-clippy-final.log,
/tmp/api-key-generation-fixture-clippy-final.log,
/tmp/api-key-generation-typecheck-final.log, and
/tmp/api-key-generation-build-final.log. The coordinator owns inventory,
additive evidence, locks, canonical gates and publication. Only an existing
indexmap dependency is activated in the API manifest; no lock is committed.
