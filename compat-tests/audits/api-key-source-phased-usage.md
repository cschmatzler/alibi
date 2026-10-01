# Database API-key usage write phases

This capability follows successful database evidence 4b831494, individual deletion
312b3aec, non-mutating exhaustion ab00b5c2 and automatic cleanup c8bee0bf.
It implements the separately observed database write phases in published
@better-auth/api-key 1.7.6. It does not change the secondary-storage path.

## Source and public contract

The published `claimUsageInDatabase` first awaits `consumeRemaining`, then
`consumeRateLimit`, then an adapter update containing only `updatedAt`.
`consumeRemaining` uses the originally validated row to decide whether refill is
due. Its refill compares the observed lastRefillAt, and a loser falls through to
a guarded remaining > 0 decrement. Rate claims independently guard window start,
reset and increment; a loser reloads the row and reevaluates. Final update returns
the current row. Successful quota and rate writes survive a later storage error.

The new `ApiKeyStore::consume_api_key_usage_from_snapshot(&ApiKey, bool)` accepts
the genuine validated database snapshot. Its default returns an explicit error;
custom stores cannot silently substitute the old combined transactional method.
PluginStore forwards this operation, and the bundled adapter implements it with
independent guarded UPDATE RETURNING operations. Existing
`consume_api_key_usage(id, bool)` remains unchanged for native consumers.
SQLite and PostgreSQL are permitted; other backends fail before any write.
Only SQLite is exercised here. API validation continues to perform configuration,
enabled/expiry, permission and initial exhaustion checks before consumption.
SQL IDs and values are bound, and the operation never uses a request-provided
owner or changes the stored key hash, owner or configuration.

Actual pinned probes use real users, migrated SQLite and public key generation.
An application wrapper installs a SQL ABORT trigger at the genuine rate or final
adapter operation and calls the original operation. Logs
`/tmp/api-key-successful-rate-sql-veto-probe.log` and
`/tmp/api-key-successful-final-rate-sql-veto-probe.log` show retained refill/quota
writes after a rate failure and retained quota/rate writes after a final failure.
The original updatedAt remains unchanged in both cases. Ordinary rate-limit
denial already burns an admitted quota in the previous implementation; it is not
claimed as a new correction.

## Meaningful owner evidence

Four official-client primary owners exercise default and deferUpdates=true
profiles, each with a real rate or final SQL veto. Real owner/foreign signups and
generated keys establish authentication and authority. Foreign public lookup
and permission rejection cannot consume the target. Trusted verification and
official API-key session middleware then expose the genuine failure; prior
quota/refill/rate writes persist, updatedAt does not advance, and successful
background registration does not occur. Removing the actual trigger permits a
real retry; the subsequent exhausted request retains the refill-capable row.
Original cookie sessions, both users' complete observed state and foreign
physical key fields remain unchanged. Every observed key/date/transport field is
retained, without comparator changes.

A fifth owner installs a real AFTER-rate SQL trigger that changes the target's
name and quota before the final update. Actual verification must return those
current values with the original key owner and matching persisted dates. This
tests current-row reread without relying on an arbitrary concurrent completion
distribution. The fixture trigger operates only on its controlled target; phase
selection chooses fixed SQL predicates, with no user text interpolated into SQL.
It does not replace adapter results or production behavior.

The same four SQL-veto owners fail against an actual fixture binary built with
the original API verification consumer calling the old combined operation:
`/tmp/api-key-source-usage-sdk-meaningful-before.log` has 4 intended failures.
Rate failure incorrectly restores quota to zero; the old combined write never
reaches the distinct final-only veto and incorrectly reports success. The binary
is preserved at `/tmp/api-key-source-usage-original-owner-server`; its compilation
log identifies this isolated tree. The current-row HTTP owner was added later
and is not claimed in that four-owner before run.

Native public-store proofs add distinct coverage unreachable through sequential
HTTP: two independent connections admit exactly three of eight simultaneous
same-snapshot due-refill calls, and an eight-connection pool admits only the
guarded quota/rate budget under 32 simultaneous calls. Losers preserve rows and
the complete foreign serialized key. Existing combined-operation race phases
remain alongside these new-operation phases. Three real SQLite public-store
tests independently prove full persisted rows after rate/final veto and final
current-row reread. Original-operation intended failures are preserved in
`/tmp/api-key-source-usage-native-meaningful-before.log` and
`/tmp/api-key-source-usage-current-read-native-before.log`.

## Fixture provenance and validation

The native application refill control now binds a real DateTime through its
existing database driver rather than copying a Source ISO lexical representation.
SQLite stores its canonical driver text, which the genuine observed-date CAS
also binds. The epoch assertion retains the actual date in comparison and checks
its parsed instant. The old fixture text caused five after-run admission failures
in `/tmp/api-key-source-usage-sdk-current.log`; that setup failure is retained.
No global date parser, database normalizer or clock is changed. The existing
expiration control is unchanged.

Focused new SDK owners pass 5/392 in
`/tmp/api-key-source-usage-sdk-typed.log`. Full SeaORM library passes 53 tests in
`/tmp/api-key-source-usage-seaorm-native-final.log`; the API api_key filter passes
53 tests in `/tmp/api-key-source-usage-api-native-final.log` (including its
matching organization authority test). Strict core/API/SeaORM production and
fixture Clippy, locked fixture build and client/reference TypeScript pass in
`/tmp/api-key-source-usage-{production-clippy,fixture-clippy,final-fixture-build,
client-typecheck,reference-typecheck}.log`. Complete focused API-key family
passes 60 owners/3248 assertions in `/tmp/api-key-source-usage-family-final.log`.
Pinned Source self-control passes 5/392 in
`/tmp/api-key-source-usage-source-final.log`. The downstream feature consumer
passes `rustls,axum,seaorm2,redis-cache` without default features in
`/tmp/api-key-source-usage-consumer-rustls.log`; edition formatting and diff checks
pass. No full canonical gate was run.

Initial compile/typecheck/filter setup failures and the initial Source token
classification setup failure are retained, not counted as behavior evidence.
All focused runners use their own ports and stop only their own fixture children.
The test-audit authoring gate is applied: each owner has a distinct public
failure/lifecycle contract; native concurrency protects independent connection
semantics; no test-only production seam is introduced. Authorization and SQL
binding were reviewed with the authz/data-exfil skills.

## Limits

Arbitrary simultaneous HTTP return distributions are not promised: the new
operation observes the current row at its actual final write, and the test keeps
all observed returns without forcing scheduler parity. Secondary storage,
fallback cache writes, unusual installed date lexical aliases, malformed stored
dates, nonfinite stored numeric fields, extreme Date/Chrono bounds, custom store
implementations and arbitrary application storage hooks remain separate
capabilities. No schema, lockfile, inventory, comparator or tolerance changes
are made. Coordinator owns independent review, canonical gates and publication.
