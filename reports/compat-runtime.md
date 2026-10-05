# Compatibility runtime investigation

On the development host (Intel Core Ultra 7 265K, 20 logical CPUs, 30.7 GiB RAM),
`time bash scripts/compat.sh` now passes in **3m 32.26s**, with warm Rust builds
and the pinned Bun dependencies installed. This is the complete compatibility
matrix: SQLx and SeaORM, Chromium, fresh process environments, comparator
negative controls, and both adapters' independent evidence gates.

| Scope | Elapsed | Result |
| --- | ---: | --- |
| Historical serial SQLx SDK, 2,851 scenarios | 43m 13.68s | Two username clock failures |
| Initial four-worker SQLx SDK, same 2,851 scenarios | 11m 19.98s | Passed |
| Final SQLx SDK plus four environment configurations | 2m 25.90s | Passed |
| Final SeaORM SDK plus four environment configurations | 2m 27.12s | Passed |
| Final complete compatibility script | 3m 32.26s | Passed |

The full compatibility script executed 5,702 SDK cases in 402 file invocations,
20 browser cases, 16 environment cases, and 110 comparator/gate harness cases.
Both adapters independently passed the 143-route inventory and required
scenario/oracle receipts. Six previously declared evidence gaps remain explicit;
passing the gate does not claim coverage of those missing evidence categories.

## Why the old run was slow

One fixture pair executed every scenario serially, including the TypeScript
sequence followed by the Rust sequence. Each scenario can contain many HTTP
requests, expensive password hashes, public cryptographic proofs, storage
observations, and rejection/replay tables. The old repository gate then repeated the
SDK suite for the other adapter and selected directories with LLVM coverage.

The Rust fixture already optimized scrypt, salsa20, RSA and num-bigint-dig at
level 3. The remaining HTTP/router code was unoptimized. Its enormous combined
profile router was also passed directly to `axum::serve`, which calls
`clone().with_state(())` for each new connection. That rebuilt the complete route
tables repeatedly. A local probe of 100 fresh health connections took 7.765s
before resolving the router once with `into_make_service()`, and 0.018s after.
This probe isolates connection setup; the full-matrix timings establish the
end-to-end improvement.

Real protocol waits also held up the serial run. API-key cleanup checks retain
the actual ten-second module-global throttle on each runtime. CAPTCHA retains
its actual verifier, callback, and body deadlines. Hash parameters and all of
these waits are unchanged.

## Scheduling and host resources

Workers take the next file from a shared queue. Committed measured file costs
prioritize long work, and newly discovered files fall back to source size.
Independent CAPTCHA and API-key cleanup behaviors now have separate files and
shared setup helpers. All 2,851 SDK cases remain; none are filtered or retried.
Each pair owns its database, callback state, and process-global throttles, with
serial file/scenario execution inside the pair.

The default reserves two CPUs and 4 GiB of available RAM, budgets 1.5 GiB per
pair, and caps the total at 16 pairs. Linux cgroup memory availability can reduce
that budget. Unmeasured hosts default to at most four pairs. On this host the
complete run selected 14 pairs, split seven per adapter. Explicit
`BETTER_AUTH_COMPAT_JOBS=1` restores serial operation; 1–32 overrides are supported.

During the complete run, two-second sampling measured at least **9.00 GiB of
available memory**, with combined fixture/client resident memory peaking at
**18.40 GiB**. These are sampled host measurements, not a hard memory limit or a
claim that other workloads cannot change available resources during a run.
The fixture now uses one Tokio event loop, preserving actual concurrent requests
and blocking cryptography, rather than creating one runtime worker per host CPU
for every fixture process. Its complete production code is optimized at level 2,
with the existing level-3 cryptographic dependencies retained.

Both adapter executables are compiled before testing and copied separately.
The coverage pass also runs the complete SDK suite in one shared pool rather
than rebuilding pools for seven selected directories. This broadens executed
owners while preserving the native matrix and the 75% production line floor.
Workers never overwrite each other's executable or evidence. Every worker is
joined before failures propagate, so fixtures shut down and LLVM counters flush.
The runner prints actual per-file times and fixture exit states on failure.

## Trust and scheduling defects found during validation

- Port allocations remain unique within a runner, use separate adapter ranges,
  and avoid the normal outbound ephemeral-port range. Harness listeners finish
  closing before their assigned port is handed to a child.
- Concurrent traces retain request invocation order and every complete response.
  One race owner compares the entire set of equivalent admission responses;
  the identity of the winning identical request is not a promised contract.
- Physical session/JWT clocks are bound to actual request windows, immutable
  application observations, exact key material and valid public signatures.
  Rejected key-creation callbacks use their actual failed request and immutable
  event receipt. Real Source captures with forced clock offsets fail the old
  comparison and pass the new one; negative controls reject tampering. Global
  timestamp tolerances are unchanged.
- The TypeScript orphan-account fixture now restores the previous SQLite
  foreign-key setting. Previously it enabled cascades for later organization
  owners, making their results depend on file order.
- Duplicate capability records are merged by retaining the union of required
  scenarios. Stale names follow their existing split owners. Actual configured
  OAuth proxy error redirects count as denials only when bound to a preceding
  successful grant in the same profile and its exact application destination.
  Unknown/unbound redirects do not acquire denial evidence.
- The inventory preflight fails before expensive tests. The real CLI owner proves
  that missing requirements, duplicate routes, invalid schema, and missing
  evidence from one adapter still fail even when the other adapter passes.

## Complete repository gate

The final `time bash scripts/check.sh` passed in **11m 14.19s**, including
formatting, strict Clippy, both Rustls feature builds, both 1,077-test native
matrices, the fixture's two tests, doctests, the complete dual-adapter
compatibility matrix, warning-free rustdoc, and LLVM coverage. Instrumented
native execution passed another 1,077 tests, followed by the complete SQLx SDK
and its four fresh environment configurations. Production line coverage was
**53,574 / 59,918 = 89.412197%**, above the unchanged 75% floor.

The 3m32s standalone measurement above includes warm fixture builds, harness
checks, both adapters, browsers, environment checks, and evidence gates. The
11m14s repository measurement also includes compiler checks, native builds,
documentation, and instrumented builds/execution. They are different scopes.

A repeat exposed Bun's default ten-second idle socket timeout cutting off the
intentional eleven-second CAPTCHA response body. The final fixture transport
uses a sixty-second idle timeout; the auth verifier's real timeout, delayed body,
and all existing admission/state assertions remain unchanged. The final full
gate and instrumented SDK pass include this fix. Failed investigations and
fixture crashes were not counted as passing measurements or retried silently.
