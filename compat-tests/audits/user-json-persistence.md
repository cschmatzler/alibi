# Safe user JSON metadata persistence

This follow-up to JSON Number semantics closes the bundled user metadata SQLx
boundary. Actual public native store creation with a literal private RawValue
key inserted the row but failed while decoding metadata. The same failure was
reproduced in an application-owned AuthEntity model before the repair; both
logs are retained. These are runtime failures, not source-shape assertions.

## Public model contract

JsonMetadata is now reusable through better_auth::seaorm::JsonMetadata and
better_auth_seaorm::JsonMetadata. It retains From/Into<serde_json::Value>,
read-only Deref<Value>, transparent serde serialization and the same JSON column
type. Its existing organization entity path remains an alias. SQLx reads use
ordinary JsValue map decoding; SQLite writes bind JavaScript JSON text; other
backends retain JSON binding. The bundled user model uses this type. A custom
AuthEntity model opts into safe decoding by declaring metadata: JsonMetadata.
Existing Value fields remain source-compatible, including their ordinary SQLx
Value decoder; a caller requiring arbitrary marker-key support uses the public
wrapper. No schema or migration changes occur.

SeaOrmUserModel adds prepare_json_metadata with a default no-op for manual
implementations. AuthEntity generates preparation only for a present metadata
field, and create/update field conversion uses Into so existing Value schemas
remain compatible. The store invokes preparation after application hooks and
immediately before its existing atomic insert/update. Set metadata is normalized;
Unchanged fields remain unchanged. The typed helper uses safe TypeId/Any
specialization for JsonMetadata and ordinary From/Into conversion for Value.
No unsafe, type-name matching, extra SQL operation or interpolation is added.

This is a finite native Value/storage contract. It does not replace every native
CreateUser/UpdateUser callback field with JsValue or claim that Value can carry
raw infinity. The shared raw parser and explicit JsValue callback interfaces
remain the source of JavaScript nonfinite input semantics.

## Meaningful owner tests

Two native integrations use actual SQLite and public builders/stores:

- Bundled user create, lookup, partial update and metadata replacement retain
  both literal marker families, owner identity and tiny-value binary bits.
  Native imprecise u64 ingress and hook-produced u64 values are rounded by the
  production store, and direct SQL text stores 1e20 as 100000000000000000000,
  negative zero as 0 and numeric-looking IDs unchanged. Hook mutation happens
  before preparation. A name-only update retains the persisted metadata.
- A custom derived model with an extra tenant field exercises the public model
  type and generated backend preparation. Creation/read/update retain marker
  keys, correctly rounded numbers and exact SQL text; the unrelated extra field
  stays null and serde metadata remains an object rather than quoted JSON.
  This feature test uses seaorm2, the feature exposing the public derive module.

Both initial tests failed before production changes with a SQLx metadata decode
error. They protect separate bundled-adapter and custom-model/derive contracts;
there is no fixture normalization, copied receipt or test-only production seam.
Existing Value custom models and manual numeric-ID implementations still compile
and their real persistence/signup/signin tests pass.

Focused checks: two new tests; two existing derived-model tests; four database
hook tests; four legacy custom-schema tests; all four JSON Number integrations;
production workspace Clippy with seaorm2; formatting/diff checks. Independent
review and the canonical full gate are owned by the coordinator. Dependency
versions, lockfiles, comparators, inventories and coverage settings are unchanged.
