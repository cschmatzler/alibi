# Successful database API-key usage and refill evidence

This bounded evidence capability follows automatic cleanup c8bee0bf, non-mutating
exhaustion ab00b5c2 and individual deferred deletion312b3aec. It changes no
production policy, public configuration, store contract, schema or dependency.

Published @better-auth/api-key1.7.6 claimUsageInDatabase always awaits the real
quota/refill guarded increment, rate-limit write and final updatedAt update.
Successful database quota is never deferred by deferUpdates. That option changes
successful cleanup observation; successful deferred merge writes belong only to
secondary-storage-only mode. No secondary backend is enabled in this capability.

Actual pinned runtime probes /tmp/api-key-successful-usage-probe.mjs use migrated
SQLite, real users and public key generation. The final original adapter.update
is application-gated after genuine prior writes. Default and deferred modes both
remain pending at that receipt. A due refill of3 already stores remaining2,
lastRefillAt and lastRequest, and registration of successful background completion
occurs only after the final update is released. Complete raw observations remain
in /tmp/api-key-successful-usage-{deferred-refill,default-refill,deferred-plain,
deferred-veto}-probe.log. No runtime clock is changed.

Two official-client primary owners cover existing default and deferred database
profiles. Real owner/foreign signups and generated keys establish authority. A
bound private application SQL action places only the owner key at an overdue
refill; its configured interval is60seconds, and subsequent calls cannot refill
within the short real lifecycle. Foreign public lookup and trusted permission
checks reject before consumption. The application observes/gates the actual
quota increment or existing consume operation, rather than returning a synthetic
result. Pending verification cannot finish before release; observed physical
rows and both users' complete state remain unchanged. Source's increment receipt
covers the quota phase, while Rust's receipt covers the existing combined consume
operation; this is deliberately not a claim of identical internal write phases.

After genuine release, trusted verification returns remaining2 and actual stored
refill/request/update dates. A real official-client API-key session belongs to the
issuing owner and consumes to1; another trusted verification consumes to0 without
refilling. The next usage denial retains the zero row because its refill amount
is nonnull. Every returned key field, signed-cookie transport, full observed
physical ID/key/config/quota/request/refill/rate/date fields and owner/foreign
states remain in comparison. Foreign observed key fields remain byte-for-byte
unchanged. These two profiles disable rate limiting: requestCount stays0 and the
existing lastRequest behavior is retained. Enabled rate-limit lifecycle has its
existing independent primary owner; a new combined configured refill/rate branch
is not claimed here.

Both independent pending verification and gate-release transports are retained
through the existing recordTransport interface after completion, in explicit
pending/release order. No response, date, header, cookie or array field is removed.
Other existing fixture owners do not opt into usage observations and retain their
receipts/state shape. The new optional usage state projection adds actual refill
and rate fields only for these owners. Reset restores that application flag and
drains actual pending operations through the existing fixture lifecycle.

The existing public-store independent-connection owner gains a distinct overdue
refill phase. Eight actual concurrent calls against two separate SQLite
connections accept exactly3 and reject5, replenish once, preserve the original
key/ID/owner and complete foreign serialized row, and retain remaining0. This
covers atomic refill independently of the sequential HTTP lifecycle; it does not
assert unstable concurrent network completion order. Actual pinned eight-call
same-snapshot probe /tmp/api-key-due-refill-race-probe.log independently confirms
one refill, three valid outcomes, five denials and retained zero row.

Source self-control initially rejected a null foreign remaining field because
the new observer schema incorrectly required a number. The schema was corrected
to retain null rather than supplying a quota or weakening a production guard;
/tmp/api-key-successful-source.log remains a setup failure. Source-to-Source final
2/180 passes /tmp/api-key-successful-source-fixed.log. Actual Source-to-Rust
2/180 passes /tmp/api-key-successful-usage-sdk-final.log.
The complete focused API-key family passes55 owners/2852 assertions in
/tmp/api-key-successful-usage-family.log. Both native concurrency owners pass
/tmp/api-key-successful-usage-native-corrected.log; the first command selected the
file name instead of its module and ran zero tests, so it is not counted as proof.
Locked fixture build, strict fixture Clippy, client/reference TypeScript and
edition-specific formatting/diff checks pass. The generic Source adapter wrapper
initially inferred Promise<unknown>; its final explicit generic signature retains
the actual adapter's Promise<T|null> contract without a cast or suppression.

## Confirmed separate boundaries

A failure at Source's final updatedAt write retains earlier quota/refill/rate
writes and returns rejection without successful cleanup. Rust's combined consume
transaction rolls them back together. A real SQL ABORT trigger installed only at
the genuine final-update gate confirms earlier writes remain in
/tmp/api-key-successful-usage-final-sql-veto-probe.log. The actual final-veto probe confirms this
phase boundary; no test masks or claims it fixed here. A subsequent separate
contract proposal must retain guarded quota/refill and rate-limit concurrency
while exposing the required phases and final current-row reread.

Under simultaneous due-refill calls, Source's final update rereads the current
row: the actual eight-call probe returned remaining0 for all three successes.
Rust returns its individual committed snapshots. Arbitrary concurrent returned
row projection parity remains open. This capability does not serialize an SDK
race and then claim that gap closed, discard responses, normalize quota fields,
or change the comparator. Secondary storage/fallback/deferred merges, unusual
installed dates and nonfinite storage fields remain separate capabilities.

Coordinator owns inventory, full gates, independent review and publication.
Test-audit authoring checks were applied; external autoreview tools are unavailable.
No full gate was run or claimed; all runners stopped only their own fixture
children. Source, logs and failed setup observations are preserved.
