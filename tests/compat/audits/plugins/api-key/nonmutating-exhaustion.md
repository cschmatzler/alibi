# Atomic API-key exhaustion preserves the credential

This storage prerequisite supports separate API policy for awaited/deferred
individual deletion. Pinned @better-auth/api-key1.7.6 validateApiKey deletes only
an initially read `remaining === 0 && refillAmount === null` snapshot, after its
permission check. Its consumeRemaining guarded decrement rejects a positive
snapshot that loses the final quota without deleting the row. Physical deletion
inside Rust consume_api_key_usage conflated these distinct stages.

The public ConsumeApiKeyResult::UsageExhausted contract now documents a
non-mutating rejection. SeaORM removes only its zero/no-refill physical DELETE;
its immediate SQLite transaction, row lock, atomic quota/refill/rate-limit logic,
and other fields are preserved. Plugin-owned deletion policy follows separately.
No method signature, default success, schema, migration or lock change is needed.

The actual pinned public-route race in
`/tmp/api-key-individual-quota-race-probe.mjs` gates real adapter findOne after
both initial reads observe remaining1. Its two real authentication requests
produce one200 owner session and one429, no individual-delete call, and an actual
retained row with remaining0. Full output is preserved in
`/tmp/api-key-individual-quota-race-probe.log`.

The native owner uses two independent SQLite Database connections, each with a
one-connection pool, against one installed migrated file. Two atomic consumers
race for its final quota; one succeeds and one exhausts. The persisted full row
must equal the genuine successful result, another denial preserves it exactly,
a foreign owner's entire row remains unchanged, and an application refill can
reuse the same credential/owner. This distinct storage contract protects custom
consumers and SQL concurrency beyond API callback/transport scenarios.

Before the fix, the test fails `quota loser must retain the credential`
(`/tmp/api-key-individual-storage-before.log`). The repaired owner and existing
fractional 32-request concurrency sibling pass2 tests
(`/tmp/api-key-individual-storage-final.log`). Strict core/SeaORM checks and
formatting are recorded in `/tmp/api-key-individual-storage-*.log`. No full-gate
claim: coordinator owns shared inventory, integration, independent review and
publication. External test-audit autoreview commands are unavailable.
