# Enforce every recorded capability requirement

The actual inventory gate reads `evidence`, including arrays of required scenario
names. Later coordinator updates mistakenly put 751 additional category entries
under `requiredEvidence`. Zod silently stripped that unknown field, so those
entries were documentation rather than enforced requirements. The earlier
passing gates remain valid for their implemented checks, but did not enforce
those additional entries.

All 751 entries are moved, without deletion or category changes, into the
existing enforced `evidence` field. Each category preserves the ordered union
of its original requirements and additions. Route flags and the pinned version
are unchanged. This is a deliberate migration, not regeneration from results.

The real gate subprocess regression writes an unknown requirement field whose
scenario has no evidence. Before the fix the subprocess incorrectly succeeds;
the preserved failure is `/tmp/capability-unknown-requirements-before.log`.
Inventory, route records and category objects now reject unknown fields.
Ordinary checking and regeneration both reject the unknown field and leave the
inventory file unchanged. Existing missing-scenario, duplicate-route, route
removal and regeneration-preservation controls remain.

The focused complete harness passes 42 tests / 344 assertions in
`/tmp/capability-unknown-requirements-harness-final.log`. Comparing all additions
with the failed 501-scenario run finds seven missing category observations:
four belong to its two real timestamp failures; three older declarations require
genuine success or authorization flows that their original scenarios did not
exercise. Those scenarios are being extended with actual successful retries
and a guest creation rejection, retaining their original failures and full
persisted-state checks. No declared requirement is removed to obtain green.
The canonical gate and independent migration review are pending.
