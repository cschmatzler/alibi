# Match the actual state-reader date projection

Integration of the successful-usage owners with the production wire repair
exposed a private fixture mismatch. Source's existing default state reader maps
all five date fields through `new Date(value).toISOString()`. Native's reader
returned physical SQL strings. Comparing a successful key's returned UTC
millisecond dates with the default persisted-state projection therefore failed.
The frozen 512-scenario gate retains the two real failures in
`/tmp/next-priority-fixed-canonical.log`: 510 passed / 30,260 assertions; browser,
documentation and coverage were not reached. It is not a passing gate.

A deterministic focused regression stages the original five six-fraction dates
and a nonzero offset through real parameterized SQL. It first checks the complete
physical owned row, then requires the complete default row with Source's five
known UTC millisecond projections. The unchanged native fixture fails precisely
those five fields in `/tmp/api-key-default-state-projection-complete-before.log`.
The Source control passes in `/tmp/api-key-default-state-source-control-final.log`.

Native's default projection now matches that existing Source reader, after the
optional usage fields are added. Null dates and every other field survive.
`rawDates=true` bypasses projection entirely; existing exact raw stored fractions,
offsets and foreign-row preservation checks remain. No production store, schema,
comparator, tolerance, field exception or oracle behavior changes.

The timestamp owner invokes the existing trusted forced-cleanup operation before
creating keys. This establishes an actual completed throttle admission in both
runtimes rather than depending on process history. Its result and transport are
retained. The initial Source-self receipt mismatch is preserved in
`/tmp/api-key-default-state-source-control.log`; the corrected control retains all
background observations and does not alter the runtime clock or throttle.

All eight connected timestamp, successful-usage and phased-failure owners pass
8 / 674 in `/tmp/api-key-default-state-complete-connected-final.log`, with isolated
Source 42344 and Native 42343. An initial mixed-fixture setup run is preserved in
`/tmp/api-key-default-state-connected-final.log`; its seven missing-action failures
are setup errors, while the timestamp owner passed. Independent organization-owner
review is clear for the exact bounded projection and lossless physical checks.
TypeScript and the locked fixture build pass. Strict fixture checks and the full
canonical gate are pending.
