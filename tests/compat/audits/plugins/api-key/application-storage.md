# Application-owned API-key storage

Issue [#203](https://github.com/cschmatzler/better-auth-rs/issues/203) adds the
published Better Auth 1.7.6 secondary-storage, customStorage and
fallbackToDatabase configuration family. The default remains database storage.
`ApiKeyStorage` exposes the real application get/set/delete boundary with an
optional TTL; custom storage takes precedence over the configured secondary
cache. Permanent keys and reference lists use no expiry. Expiring key indexes
use Source's positive, floored remaining seconds.

## Production contract

Secondary-only keys have actual hash, ID and owner/organization reference
indexes. Reference-list read/modify/write operations serialize within one
process, matching the pinned Source lock. Cross-process atomic admission is
not promised. Quota and rate admission merge the validated snapshot's usage
fields into the current application row. Concurrent requests observing the same
snapshot can both succeed. Awaited writes return the merged row; deferred
secondary-only writes return the validated usage snapshot and expose background
completion through the configured application handler.

Database fallback keeps real database rows and guarded database admission.
Cache misses load the current row. Successful usage always refreshes from the
actual database result; secondary cache failures cannot roll back already
committed database usage. Exhaustion retains refill-capable keys; actual expiry
and permanent exhaustion retire the applicable indexes and database row.

The independent storage actions in Source Promise.all initiate together, reject
on a failure and allow other initiated IO to continue. Owned native tasks retain
this lifetime after the caller receives the error. Completion-order error
propagation preserves input order on success even with more than thirty storage
groups. List ID reads and fallback cache loading use Source's concurrency bound
of ten. A selected config reads only its own backend; all-config listing starts
each distinct backend, deduplicates in group order and filters the actual
reference owner and configured user/organization type before pagination.
Sorting runs inside each backend before group concatenation. Database fallback
orders rows before publishing cache indexes and the reference list; an absent
sort preserves the backend's original order. The SQLite database branch compares
stored JSON text for metadata, while cached metadata follows Source's null-first
JavaScript primitive coercion. Permissions compare their actual serialized JSON
strings. Cache string comparisons preserve UTF-16 ordering.

Cache rows retain full Source JSON metadata values, including null, and the
secondary-only absent permissions field. Native database models store metadata
as JSON text. The existing native storage journey explicitly projects that
text to the actual JSON value before comparing complete rows; it does not omit
metadata. Get/list ordinary application failures expose the observed empty HTTP
500 response while typed API errors retain their own status and body.
Documented legacy double-encoded metadata is parsed once more for API views,
including Source's date revival; the actual stored string remains in receipts.

## Independent primary evidence

`client-tests/tests/plugins/api-key/application-storage.test.ts` owns 49 official
client/trusted-application scenarios. Six profiles independently cover shared
secondary, custom, fallback, custom fallback, deferred and deferred fallback
storage. A seventh installs thirty-two distinct application stores to exercise
large-group failure propagation. Fixtures are separate Map implementations and
record actual stored strings, lookup keys, deadlines and SQL rows. Their
controls implement application IO failure/barriers and direct test data changes;
they do not implement admission, cache indexing or usage merging.

The complete observations retain signups, issued plaintext, every index value,
lookup, actual writer deadline, all database columns, actual SQLite start bytes
and type, full HTTP transports and foreign user state. The owners exercise
missing and lazily expired cache entries, current-row reload, positive refill,
quota exhaustion, actual expiry, selected/all-config list ordering and paging,
wrong user/organization/config and permission denial, misindexed foreign IDs,
partial set/delete/ref-list failures, retries and same-snapshot concurrency.
Held-ID and held-first-group barriers demonstrate errors returning before
remaining initiated IO finishes, then retain the actual partial and settled
state. A twelve-key list holds the first ten actual ID reads, checks the ten
pending application calls and preserves original result order after release.
The group-failure owner also holds the isolated backend's actual reference write
after its hash/ID writes finish, observes the caller's error and pending IO,
then releases it and checks completed publication. It does not infer completion
from a momentarily idle IO counter.

The sorting owners retain actual group order, pagination, stored-key sorting,
null/object/array metadata, raw permission strings, cache versus database order,
both sorted reference-list receipts and unspecified-sort insertion order. A
sixty-four-key owner issues supported heterogeneous metadata through the actual
API, crossing the small-list sort path while retaining stable order and every
row. Actual legacy metadata is installed through the owned storage boundary;
get/list return the Source-parsed object while full raw receipts stay unchanged.
An admitted object with an own non-callable toString produces Source's observed
ordinary 500 and preserves storage.

The actual Source-only control passes **49 / 5,280 assertions** in
`/tmp/issue203-final-49-source.log`. Strict fixture Clippy and the native API-key
selection pass **55 tests**, including its application-storage authority/usage
journey and an organization integration owner, in
`/tmp/issue203-final-safe-sort-build-native.log`.

Before-fix fixture binaries are preserved independently. Restoring the
checkpoint's actual storage owner/callers yields **8 intended failures and one
deferred-secondary success** in nine focused SDK owners:
`/tmp/issue203-pre-concurrency.log`. Awaited partial writes wait for held IO, and
a failed first list group suppresses independent fallback cache writes. The
separate bounded-ID owner fails on the sequential checkpoint in
`/tmp/issue203-pre-bounded.log`. Replacing only completion collection with the
earlier try_join_all fails the thirty-two-store held-first/later-error owner in
`/tmp/issue203-ordered-mutation.log`; the later error waits behind the held
earlier result. The corresponding locked build logs and actual binaries remain
under `/tmp/issue203-{pre-concurrency,ordered-results}-server`.

Before sorting correction, the actual Source/native group receipts differ in
`/tmp/issue203-group-sort-complete-{source,rust}.json` and four intended group
order/reference refill failures remain in `/tmp/issue203-before-group-and-ref.log`.
The metadata and permissions omissions separately fail at their intended order
assertions in `/tmp/issue203-before-raw-sort.log` and
`/tmp/issue203-permissions-before.log`; complete legitimate issued rows and every
sort response remain in `/tmp/issue203-raw-sort-complete-{source,rust}.json`.
Before the legacy projection fix, native get returns the encoded string at
metadata while Source returns its object in `/tmp/issue203-legacy-before.log`.

Trusted Source creation also admits boxed String and Number objects, which its
serializer turns into primitive stored metadata. The coordinator's independent
actual Source/official SDK artifact is `/tmp/better-auth-source-boxed-metadata.json`;
a mixed sixty-four-key actual Source issuance/SDK artifact is
`/tmp/issue203-source-boxed-mixed-metadata.json`. No fixture mutation produces
these Source rows. Their relational comparator can be cyclic. Cached metadata now uses fallible
binary insertion, natural run normalization, Powersort and galloping merge,
matching the installed Bun/JavaScriptCore ordering rather than slice sorting's
total-order assumption. While ECMAScript permits engine differences for cyclic
comparators, this compatibility owner preserves the pinned runtime's ordering,
parsed metadata and unchanged indexes.

The native public HTTP owner
`source_boxed_metadata_rows_list_successfully_without_mutating_storage` loads
the actual Source storage shapes through the owned application boundary and
checks both sort directions, all IDs/metadata, full hash/ID/reference values
and empty SQL authority. It fails with the prior sort panic and HTTP 500 in
`/tmp/issue203-boxed-native-before-final.log`. The original exploratory cyclic
probe remains separately in `/tmp/issue203-mixed-numeric-owner.test.ts` and
`/tmp/issue203-mixed-raw-sort.log`. Supported large API-issued arrays/objects/null
also pass the Source control and differential in
`/tmp/issue203-49-supported-{source,sort}.log`.

## Comparator provenance

The comparator recognizes actual application hash/ID receipt envelopes and
independently binds every row to its observed plaintext issuance. Its stored
hash must equal the real SHA-256 base64url derivative (or the observed configured
plaintext), its ID/hash lookup must address that exact stored row, its starting
characters must be the actual issued credential prefix, and its owner,
configuration and configured prefix must match the issuance. Stored metadata
remains application data and compares literally. Finite writer deadlines are
retained in comparison; SDK owners additionally assert Source's bounded TTL
window for each index. Controlled deliberate cache expiry remains observable.

`client-tests/harness/api-key-application-storage.test.ts` creates two actual
pinned Source instances with real migrated SQLite, random issued credentials
and independent application stores. Its controls preserve authentic foreign
credentials/owners, valid shortened prefixes and literal metadata. They require
the intended mutation path and reason, including independently rejecting
matching invalid receipts on both sides. No generic key/hash alias, raw-row
omission or broad comparison exception is introduced. The sibling SQLite
receipt controls pass alongside these controls in
`/tmp/issue203-provenance-harness.log`.

The earlier checkpoint's full API-key SDK family passes **114 / 11,214 assertions** in
`/tmp/issue203-final-family.log`, retaining the existing automatic-cleanup,
organization, callback, SQLite-byte, phased-usage and session owners.

## Integration status

The complete focused storage differential passes **49 / 5,280 assertions** in
`/tmp/issue203-final-49-safe-diff.log` after the safe cyclic-metadata merge
correction. All **87 harness
tests / 2,342 assertions** pass in `/tmp/issue203-replacement-harness.log`.
Strict production Clippy and locked fixture compilation pass in
`/tmp/issue203-final-safe-sort-build-native.log`; client typing and the new Source
fixture's isolated strict typing pass. A supplemental full-reference strict
check exposes inherited errors across other fixtures and is not claimed as a
passing repository check. Format/lint and diff checks retain their ordinary
requirements.

The draft publishes focused checkpoints before the complete gate. The original
17af7fe2 gate was explicitly stopped after independent review reproduced group
sorting drift; its log is `/tmp/issue203-complete-gate-17af7fe2.log`. No complete
success is claimed for that head. The corrected checkpoint rebases onto main
f48d546e before freezing the replacement canonical gate. Independent review and
the canonical complete gate are
required before readiness. Existing
capability obligations, the pinned oracle, all harness negative controls and
the 75% source line coverage floor remain unchanged. Counts above identify
their actual runs and do not claim complete repository parity.


## Resumed review on current main

The branch incorporates main `74309f36`, including managed secrets and the
independently established JWT request-window repairs. The existing six lifecycle
owners now exercise successful official SDK deletion in each profile's selected
backend and its isolated configuration. Before deletion, listing publishes the
actual reference index. After deletion, full receipts prove hash/ID removal,
reference removal or correct surviving IDs, database-row removal for fallback,
unchanged unrelated stores/rows and a missing SDK get without resurrection.
Source's fallback deletion invalidates the complete owner reference list;
secondary-only deletion retains the other referenced IDs. Every issuance,
mutation, response, transport and full before/after receipt remains observable.

The authoring gate is satisfied by extending the existing primary public SDK
owner: forgetting hash/ID/reference cleanup or selecting the wrong backend is a
credible regression; expiry and partial-failure cases do not prove successful
SDK deletion. No additional production seam was needed. An isolated actual
native mutation omits only hash deletion while retaining ID/reference/database
cleanup. All six lifecycle owners fail at the retained hash after the SDK has
returned success in `/tmp/pr350-resumed-deletion-control.log`; its separate
build and binary remain under `/tmp/pr350-deletion-control-target`.

Independent unchanged Source trusted creation proves the serialized boxed
metadata values `3`, `"10"`, `"2"` in `/tmp/parity-sort-source-3.json`, retaining
complete issuance, stored strings and official SDK transports. The existing
large metadata owner now consumes those real Source storage shapes through
owned application IO, checks all six three-value permutations in both
directions, preserves its original 64 supported API-issued rows and adds a
257-row deterministic mixed-value phase crossing native run merging/galloping.
Complete ordered responses and unchanged storage stay in the differential;
metadata is never omitted or aliased. Before repair, the actual SDK owner fails
at Source order `[boxed-0, boxed-1, boxed-2]` versus native
`[boxed-2, boxed-0, boxed-1]` in `/tmp/pr350-resumed-boxed-before.log`.

The private production metadata-sort owner now follows JavaScriptCore's
comparison orientation and actual ordering strategy; coercion and invalid
ranges return errors. Its source/license attribution is retained. Supplemental
JS models match installed Bun for 10,000 deterministic mixtures of lengths
3–72 and another 10,000 of lengths 3–402 in
`/tmp/pr350-jsc-{probe,large-probe}.mjs`; these supplement the real native SDK
proof and do not replace it.

After the final repair, the actual Source-only control and strict native
storage differential each pass **49 / 7,900 assertions**, in
`/tmp/pr350-resumed-final-{source,diff}.log`. Strict API and fixture Clippy,
locked fixture compilation and **77 native API-key selections** pass in
`/tmp/pr350-resumed-{sort-clippy,sort-final-native}.log`. Client format, lint,
typing and **90 harness controls / 2,395 assertions** pass in
`/tmp/pr350-resumed-final-harness.log`.

The replacement canonical gate is run only after freezing and publishing this
reviewed checkpoint, with its exact head in `/tmp/pr350-resumed-frozen-head.txt`
and full output in `/tmp/pr350-resumed-canonical.log`. The PR body records its
actual outcome; the focused passes above do not claim a complete gate. The
pinned oracle, negative controls, complete observations, capability obligations
and 75% production line coverage floor remain unchanged.

## Independent multi-session retirement comparator repair

The frozen `260627a7` replacement gate's managed parent was interrupted during
handoff. Its surviving SDK child reached its actual terminal result: **1,692
passes, one failure / 124,928 assertions**. All 49 storage scenarios passed. The
sole failure was the existing multiple-session browser-account-limit owner,
where two authentic logout tombstones were paired by header position rather
than corresponding previously signed cookie names. Documentation and coverage
did not run under that interrupted canonical parent, so this is not a complete
gate pass. The full original output remains `/tmp/pr350-resumed-canonical.log`.

Unchanged pinned Source sign-out verifies the presented multi-session cookies
concurrently and publishes each retirement from its completing verification.
The actual Source-self SDK repeat reproduces the same two credential-name
failures in `/tmp/pr350-multi-source-repeat-2.log`. The strongest existing
Source rotation harness owner now captures two genuine Source-issued signed
credentials, their actual logout request and raw response, every real stored
owner/foreign user/account/session column, and unchanged foreign state. A
naturally reordered independent capture pair is retained completely in
`/tmp/pr350-multi-source-natural-reordering.json`: retirement issuance indices
are `[0, 2]` versus `[2, 0]`. The exact frozen pre-repair comparator fails these
same complete observations at the intended cookie-name checks, and the repaired
comparator returns no differences, in
`/tmp/pr350-multi-natural-before-after.log`; the executable probe remains
`/tmp/pr350-multi-before-probe/probe.ts`.

Only a complete unique set of empty `Max-Age=0` multi-session cookies on a
successful public POST sign-out can align by previously observed signed name
pairs. Prior issuance must prove the credential HMAC, owner identity mapping,
exact name suffix and original scope; right-side correspondence is bijective.
Every actual header byte/attribute and complete cookie-scope observation still
compares. Live, mixed, malformed, unknown and duplicate arrays retain positional
comparison and denials. Same-name/scope duplicates and retirement scopes that
differ from observed issuance are independently rejected.

The authoring gate extends the existing primary real-Source owner: concurrent
valid retirement completion is the credible regression, the old one-cookie
rotation owner could not expose it, and no production seam was added. All
original 15 negative controls remain. Thirteen additional semantic controls
exercise changed names, signer corruption, live expiry, Expires/HttpOnly/path,
missing scope, count, duplicates, authentic foreign live input and unrelated
cookies, including matching duplicates/wrong scopes on both sides. They require
the precise intended cookie comparison reason rather than an unrelated failure.
The extended owner passes **106 assertions**. All **90 harness controls / 2,468
assertions**, format/lint/typing and both actual Source-only and native SDK
multiple-session families **3 / 212** pass in
`/tmp/pr350-multi-{harness-controls,full-harness,sdk-source,sdk-native}.log`.

The next frozen canonical gate uses a detached session with redirected stdin and
an atomic task-specific exit marker so its parent survives handoff. Its exact
head, full log and terminal exit status are recorded separately; no complete
pass is claimed until documentation and the fresh unchanged 75% production
coverage floor finish successfully.
