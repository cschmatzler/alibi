# JavaScript JSON numbers and SQLite persistence

The reference is published Better Auth 1.7.6 with the pinned Bun adapter. This
prerequisite implements JavaScript Number parsing, JSON output, arbitrary
metadata and explicit numeric-to-text adapter bindings. It never enables
serde_json arbitrary_precision, changes dependency versions or patches packages.

## Production interfaces

`utils::json::JsValue` carries all numbers as f64, including infinity and signed
zero. Its bounded RFC8259 decoder validates structures and uses the existing
serde string decoder for escape/UTF8 validation. Numeric conversion uses Rust's
correctly rounded f64 parser; duplicate keys retain the last value and original
position. Malformed numbers, trailing tokens, invalid escapes and excessive
nesting are rejected. Exact root Value is constructed recursively without
Value::deserialize; safe Any.downcast requires a static owned DTO bound.

Typed arbitrary Value/map fields use documented safe deserializer adapters;
JsValue fields need no adapter. Repository request metadata, OAuth additional
data/state, administrative data, passkey response and view extensions use them.
Caller-defined nested Value fields must opt into the adapter or use JsValue.
Generic serde cannot specialize arbitrary caller fields automatically.

Magic-link callbacks receive Option<JsValue>, preserving actual f64 values.
API-key create/update metadata uses JsValue so schema validation sees infinity
before storage maps it to null. Conversion to finite Value preserves finite
bits, maps nonfinite values to null, and converts negative zero to zero.
Standard serde serialization promises the same parsed numeric value; the shared
writer emits exact JavaScript numeric text at actual byte/string sinks.
AuthResponse, JWT signed JSON and API-key stored metadata use that writer.
Existing preserve_order retains ordinary property order; canonical array-index
keys sort numerically first. Numeric-looking IDs/config/provider strings stay
literal. Same-version serde_json float_roundtrip prevents SQLx finite readback
from changing binary values; it introduces no reserved map-key protocol.

Organization metadata uses scoped JsonMetadata. Manual Deserialize reads maps
through JsValue, avoiding the private RawValue classifier transitively enabled
by SQLx. SQLite input binds the shared writer's JSON text on the existing atomic
ActiveModel insert/update; non-SQLite input retains JSON binding. Readback is
JSON and public Serialize emits the underlying value, not a quoted JSON string.
Conversion from/to Value is documented. Column/schema/migrations are unchanged.
A RawValue serializer-only experiment failed: SeaORM reparses it into Value
before binding, losing spelling and interpreting literal markers. No raw SQL
interpolation or extra writes were added.

UserStore::coerce_user_text_number preserves INTEGER versus REAL bindings and
PluginStore forwards it. The store returns the database's actual CAST text and
propagates its errors, so REAL formatting follows the installed SQLite version,
as it does for the TypeScript adapter. NaN is rejected. The phone consumer selects INTEGER inside Bun's
signed Int52 range, excluding negative zero, and REAL otherwise. Other backends
retain their own CAST results; custom stores must implement the capability.

## Regression ownership and measured evidence

Raw 1e400 delivery/API-key requests failed on ae4aa46 with 400 instead of 200.
Independent review blocked the first implementation: its precision feature
interpreted literal private Number objects as numbers/invalid JSON. Actual
HTTP failures and the rejected frozen commit remain evidence. The repair never
filters or renames markers; Number and RawValue keys now survive real delivery,
API-key readback and organization SQL persistence/readback.

Four public-builder/real SQLite native integrations protect distinct contracts:

1. Callback infinity, signed zero and integer rounding survive until emission;
   finite conversion preserves .625 bits and arbitrary marker keys stay literal.
2. Actual API-key/organization SQL text and owner identity agree; foreign API-key
   updates fail. Native organization ingress supplies an unrounded u64 directly
   to the production store. Create/update persist 1e20 as 100000000000000000000.
   Create/lookup/name-only update preserve tiny-number bits 31511b97697f234c.
3. Actual phone text affinity distinguishes numeric binding types, finite edge
   values/subnormals, negative zero and both infinities. Unique collisions insert
   no extra users; trusted context and store facade agree.
4. Malformed JSON/escapes and excessive nesting create no notification,
   verification record or session cookie.

Before the bind repair, 1e20 persisted as 1e+20. Before float_roundtrip, tiny JSON
readback produced 31511b97697f234d. Those meaningful failures are logged separately.
These SQL/binary checks detect failures parsed SDK comparison cannot observe.
Five dual-server SDK scenarios cover raw literals, paired surrogate escapes,
duplicate keys, both private marker families, delivery/magic-link consumption,
API-key create/get/update/verify plus denied foreign ownership, organization
create/update/readback, and invalid JSON without delivery/session creation.
Every observation remains in the unchanged comparator.

JWT owner repairs protect actual signed bytes and JOSE verification, native
header rounding, arbitrary marker claims, finite registered dates, truthy
non-string claim rejection and lazy key persistence on rejected signing.
Two new native cases and one SDK scenario extend managed JWT coverage.

A pinned Better Auth phone signup probe confirms raw 1e400/-1e400 stores Inf/-Inf;
1e309/-1e309 duplicate signups fail 422 without users. JSON.parse rounding,
negative zero/infinity and JSON.stringify null/zero are independently confirmed.
Scenarios assert only values whose text is identical across SQLite versions;
17-significant-digit REAL text depends on the engine (3.52+), not the library.

Tests cover separate callback, wire, signed-byte, persistence and adapter risks;
no wrapper/export exists only for a test. Expected SQL/claim text and binary
values are independently specified. No exemptions/skips/inventory/coverage
changes occur. Focused proofs: 4 native integrations; 155 core and 301 API library
tests; 5 numeric SDK scenarios / 290 assertions; 20 native managed JWT tests and 9
JWT SDK scenarios / 530 assertions; TypeScript; production workspace Clippy;
formatting/diff checks. Coordinator owns the canonical full gate and inventory.

## Explicit separate contracts

Pinned get-full-organization returns raw metadata text while Rust returns parsed
JSON; the coordinator tracks that response gap. This slice exercises the
source-confirmed parsed create/update readback contract. Bundled/custom user
entity Json<Value> storage has a preexisting marker hazard requiring a separate
persistence follow-up; this commit does not alter user model traits/macros or
claim custom-schema/user-metadata parity complete.

JavaScript accepts unpaired UTF16 surrogate escapes; Rust String and the existing
serde decoder reject them. Paired escapes are covered. This preexisting string
representation gap and bounded excessive-nesting policy are explicit limits.
Non-SQLite adapter/model behavior needs its own runtime evidence; not every
embedding interface is declared audited.

The code-execution review traced raw request bytes through the bounded JSON
decoder into typed DTOs and parameter-bound SQLite writes. It found no eval,
shell, template, dynamic-loading or executable-deserialization sink.

Independent review also reproduced raw team userId coercion selecting the
`null` owner for 1e400. The repaired String coercion reads JsValue before finite
conversion. A fifth dual-server scenario seeds real Infinity/-Infinity/array
coercion owners and separate null owners with the existing fixture, then adds
and removes actual team members and inspects persisted ownership/counters.
Both private marker objects retain ordinary object String coercion. The before
SDK run selected userId null instead of Infinity; after repair 5 scenarios and
290 assertions pass. 32 organization native tests and production API Clippy pass.
Custom raw JWT callback claim production remains a separate JWT owner slice.

Custom `jwt.sign` callbacks bypass upstream JOSE setter validation and can receive
nonfinite claims. The current Rust remote-signer map cannot preserve those raw
values; that callback branch remains a separate JWT interface capability.
Local managed-key signing is the scope of the numeric signing proof.

The final integrated canonical gate passes after SIWE integration: 244 SDK
scenarios / 6,190 assertions, 37 harness tests / 210 assertions, two Chromium
tests / 22 assertions, default/optional configurations, Rustls/Redis builds,
TypeScript, documentation and 78.67% source line coverage (22,900 / 29,109).
Independent findings are resolved within this numeric and storage scope.
