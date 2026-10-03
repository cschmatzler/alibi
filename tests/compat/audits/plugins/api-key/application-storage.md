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

Cache rows retain full Source JSON metadata values, including null, and the
secondary-only absent permissions field. Native database models store metadata
as JSON text. The existing native storage journey explicitly projects that
text to the actual JSON value before comparing complete rows; it does not omit
metadata. Get/list ordinary application failures expose the observed empty HTTP
500 response while typed API errors retain their own status and body.

## Independent primary evidence

`client-tests/tests/plugins/api-key/application-storage.test.ts` owns 47 official
client/trusted-verification scenarios. Six profiles independently cover shared
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

The actual Source-only control passes **47 / 4,742 assertions** in
`/tmp/issue203-47-self.log`. The existing complete native API-key family passes
**53 tests**, including its application-storage authority/usage journey, in
`/tmp/issue203-final-focused-native.log`.

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

The full API-key SDK family passes **114 / 11,214 assertions** in
`/tmp/issue203-final-family.log`, retaining the existing automatic-cleanup,
organization, callback, SQLite-byte, phased-usage and session owners.

## Integration status

The complete focused storage differential passes **47 / 4,742 assertions** in
`/tmp/issue203-final-47-diff.log`. All **87 harness tests / 2,342 assertions**
pass in `/tmp/issue203-final-harness.log`. Strict production and fixture Clippy,
locked fixture compilation and all 53 native owners pass in
`/tmp/issue203-final-strict-focused.log`; client typing and the new Source
fixture's isolated strict typing pass. A supplemental full-reference strict
check exposes inherited errors across other fixtures and is not claimed as a
passing repository check. Format/lint and diff checks retain their ordinary
requirements.

The draft is publishing this focused checkpoint before rebasing onto the
coordinator's main. Independent review and the canonical complete gate are
required before readiness. Existing
capability obligations, the pinned oracle, all harness negative controls and
the 75% source line coverage floor remain unchanged. Counts above identify
their actual runs and do not claim complete repository parity.
