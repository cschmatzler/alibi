# Compatibility runtime investigation

The architecture PR (#465) was merged before this investigation. The measured
serial SQLx SDK run exercised 2,851 scenarios in 191 files and took 2,593.68
seconds (43m 14s). It passed 2,849 scenarios; its two failures concerned session
clock comparison after username sign-in.

## Where the time goes

The old orchestrator starts one TypeScript/Rust server pair and one Bun process.
Every scenario uses `test.serial`, executes its complete TypeScript sequence,
and then repeats the sequence against Rust. The suite consists of HTTP flows,
cryptographic proofs, physical persistence observations, and rejection/replay
checks; a scenario can make many requests rather than one assertion.

The complete gate runs this SDK suite for SQLx and SeaORM, adds Chromium and four
fresh process-environment configurations, and repeats selected SDK directories
with LLVM coverage instrumentation. An hour for that gate includes multiple
runs, not just one list of 2,851 scenarios.

Twelve real signup requests per server, measured locally using the existing
fixtures and production-mode configuration, had median end-to-end latencies of
58.19 ms for TypeScript and 119.50 ms for Rust. The Rust fixture already optimizes
`scrypt`, `salsa20`, `rsa`, and `num-bigint-dig` at opt-level 3. Disabling password
hashing or reducing its parameters would invalidate the compatibility contract.

Some waits are protocol behavior. API-key cleanup scenarios wait for the real
module-global ten-second throttle separately on each runtime. The longest
CAPTCHA scenario in the serial run took 47.5 seconds across its verifier deadline
and application-callback checks. These costs previously blocked the entire
remaining suite.

## Changes

- Discover scenario files and balance them by source size among independent
  fixture pairs. Each worker retains serial file/scenario execution and owns
  separate databases, callback state, and process-global throttles.
- Default to at most four workers, capped by available CPU parallelism.
  `BETTER_AUTH_COMPAT_JOBS=1` restores serial execution; an explicit 1–16 value
  controls the fixture budget. Browser and process-environment checks retain
  their existing process isolation.
- Build the Rust fixture once before starting workers. Join every worker even
  when another fails, ensuring every fixture shuts down and LLVM counters flush.
- Reset full-suite evidence once and validate the merged receipts after all
  workers complete. Partial runs still cannot manufacture full-suite evidence.
- Print failed Bun diagnostics once rather than duplicating the complete output
  inside the orchestrator panic.
- Recognize username sign-in as a session issuer. For the default fixture's narrow
  physical observer, validate the seven-day expiry against its exact signed
  issuance window. Rows with creation clocks retain their observed-lifetime
  comparison. Timestamp tolerances are unchanged.

## Validation and timings

All 106 comparator/gate harness tests pass, including a real upstream username
sign-in regression that fails on the old comparator under delayed requests.
Its negative controls reject incorrect lifetimes, foreign owners/tokens, invalid
signatures, foreign issuers, and missing/tampered physical observation receipts.
Strict Clippy, Rust formatting, TypeScript formatting/lint/type checking pass.

With warm builds and no other fixture suites running, the same 22 scenarios
across signup, signin, signout, and origin-contract files passed in:

| Workers | Orchestrator elapsed |
| --- | ---: |
| 1 | 29.61 s |
| 4 | 23.30 s |

The four-worker sample is bounded by one 17.31-second origin-contract file.
This small sample does not establish the full-suite speedup. Full SQLx and
SeaORM SDK/browser/environment validation is running separately and will be
recorded here when complete. The combined production coverage floor has not
been rerun for this investigation yet.
