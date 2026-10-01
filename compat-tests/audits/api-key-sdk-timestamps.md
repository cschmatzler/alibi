# API-key timestamp projection against Better Auth 1.7.6

This prerequisite repairs two production wire paths found by the canonical
501-scenario gate: virtual API-key sessions and API-key date projections. The
failures were real timestamp corruption in the published client, not host clock
jumps, slow cleanup or a reason to expand comparator tolerance.

Pinned `better-auth/dist/client/parser.mjs:18-31` accepts one through seven
fractional digits, then passes the entire parsed fraction as the millisecond
argument to Date.UTC. Chrono automatic RFC3339 formatting sometimes emits six
digits when nanoseconds end in zeros. Nine-digit fractions remain strings in that
client, making the visible date corruption intermittent. The unchanged published
parser independently reproduces the exact reported failed values
(`/tmp/api-key-timestamp-published-parser-proof.log`):

- 03:17:00.489730Z becomes 03:25:09.730Z, shifting 489241 ms.
- 03:27:04.290730Z becomes 03:31:54.730Z, shifting 290440 ms.
- 03:18:31.016562+00:00 becomes 03:18:47.562Z, shifting 16546 ms.

Live fresh Bun Date, host/Python realtime, direct clock_gettime syscall and VDSO
readers agreed across all twenty CPU affinities; relevant processes had no time
namespace offsets. More decisively, actual stored fractional-date controls below
reproduce the corruption without any wall-clock adjustment.

Source API-key values are Date objects and JSON emits UTC milliseconds. Pinned
`@better-auth/api-key/dist/index.mjs:813-820` creates Date fields; the adapter date
projection supplies Date values on reads. Its virtual session at 2426-2436 also
creates Date fields and uses the original API-key expiry or source getDate.
Rust virtual /get-session had inserted raw chrono DateTimes into json! instead
of using its already-correct SessionView serializer. ApiKeyView::From copied
native API-key date strings without the source's Date.toJSON projection.

The repair reuses the actual SessionView serializer for the virtual-session body.
This produces precisely the same eight source session fields: id, token, userId,
userAgent, ipAddress, createdAt, updatedAt and expiresAt. Optional builtin extension
fields are absent and the map is empty for this constructed virtual session. The
real pipeline, owner lookup, expiry units and request metadata remain unchanged.
ApiKeyView::From projects the five valid RFC3339 date accessors to UTC millisecond
strings: createdAt, updatedAt, lastRequest, lastRefillAt and expiresAt. Optional
nulls stay null. Native ApiKey accessors, stores, chrono values and actual database
bytes retain full precision; SeaORM conversion helpers are not globally changed.
The private helper preserves prior invalid-native-string behavior rather than
inventing a new adapter validation contract. Such invalid/custom date strings
remain a separate boundary, as do directly constructed application wire DTOs.

One primary official-client owner now protects both distinct wire paths using
actual SQLite data. A private existing background-fixture action selects a real
known key, validates date inputs and stages five precise values with parameterized
SQL in both runtimes. One value includes a nonzero timezone offset. A raw-date
observation reads physical stored values rather than fabricating expected data.
The source adapter and auth runtime are unmodified. The owner checks full raw get,
SDK get/list, actual trusted verification, SDK virtual session and raw virtual
session payloads, including all timestamp fields and the exact source session
keys. Every SDK date must be a real Date with the correct instant; raw responses
must have source UTC millisecond precision. Guest authority is not manufactured,
foreign get is denied, the complete foreign key row remains unchanged and owned
immutable physical date bytes remain precise after verification. No fields,
response bodies, cookies, hashes or transport are suppressed.

The initial unchanged source-self owner passes 1 scenario / 90 assertions
(`/tmp/api-key-sdk-timestamps-source-self.log`). Identical staged data against the
unchanged native implementation fails deterministically for all five SDK dates
(`/tmp/api-key-sdk-timestamps-before.log`, 0/1, 58 assertions), for example
00:00:00.016562 becoming 00:00:16.562. A separate fresh-runtime probe exercises
only the old virtual session path with an actual stored six-digit expiry,
retaining complete raw and published-decoded payloads
(`/tmp/api-key-virtual-timestamp-before-probe.log`): source emits
2099-10-01T00:04:00.456Z, while native emits .456789Z and its SDK decodes
00:11:36.789Z, shifting 456333 ms. Thus both production paths have meaningful
independent before evidence. The repaired primary owner passes 1/90
(`/tmp/api-key-sdk-timestamps-sdk-final.log`). The existing cleanup owners retain
all their functional assertions and exact observations.

The focused complete API-key, JWT, session and actual OpenAPI owners pass
93 SDK scenarios / 5080 assertions (`/tmp/api-key-sdk-timestamps-family-final.log`),
including both formerly failing automatic/default and deferred/exhausted cleanup
owners. All 334 API and 156 core library tests pass
(`/tmp/api-key-sdk-timestamps-native-final.log`). Strict core/API library and
actual fixture all-target Clippy, TypeScript, fixture build and both format checks
pass in `api-key-sdk-timestamps-{clippy-final,fixture-clippy-final,types-final,
final-build,format-final,fixture-format-final}.log`. The original full gate tree
and its logs remain frozen. Temporary independent before-probe processes were
stopped after evidence capture; focused final servers remain available for review.

This is an output projection repair, not a client parser patch, host-clock change,
generic adapter precision rewrite or timestamp suppression. Native/store dates
and their SQL precision remain intact. No comparator, tolerance, mock clock,
skip, schema, migration, dependency, lock or inventory change is made. The
coordinator owns independent review, canonical gates and publication; external
test-audit autoreview is unavailable. No production test-only seam is introduced.
