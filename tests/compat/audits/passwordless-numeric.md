# Passwordless numeric configuration

Reference: installed `better-auth@1.7.6` email-otp, phone-number and magic-link
modules and their types, `@better-auth/utils/random`, and the shared internal
adapter. The reference, raw response shapes, comparers and coverage requirements
remain unchanged.

Native OTP lengths and attempt budgets are `f64`. All three plugin lifetimes
are `f64` seconds. Existing callers migrate `Duration::seconds(n)` to `n.0`
seconds and integer length/budget literals to floating-point literals. Checked
`num_traits::ToPrimitive` conversions preserve numeric comparisons and compute
expiry by truncating the complete `Date.now() + seconds * 1000` millisecond
value, rather than rounding the configured duration independently.

## Established branches

Both OTP plugins reject zero, negative and negative-infinity built-in lengths
with the actual empty 500 response, before delivery. Safely terminating positive
fractional lengths round up. NaN generates an empty credential, which is
persisted, delivered and consumed through the real endpoint. Phone's object
spread overrides the apparent `||` defaults with explicit options; zero and NaN
are consequently preserved for both length and lifetime.

Email attempts use `allowedAttempts || 3`: zero and NaN fall back to three.
Phone uses `allowedAttempts ?? 3`: zero and negatives reject unused proofs,
while NaN and positive infinity never exhaust an integer counter. Fractional
budgets compare against the actual integer counter: 1.5 permits two wrong
attempts, then rejects and removes the proof. Negative infinity rejects both
plugins' unused proofs. Bounded probes issue four wrong attempts for unbounded
budgets and then consume a genuine fresh delivery.

Email and phone zero lifetimes persist the issuance millisecond; negative
lifetimes persist past deadlines. NaN and either infinity fail before delivery.
Magic-link zero/NaN select 300 seconds, negative lifetimes are expired, and either
infinity fails. Its deprecated attempt option is ignored by Source: tokens are
always single-use, and no native configurable magic-link attempt policy is added.

Invalid email lifetime persistence enters Source's resolver retry, removes an
existing logical proof, then fails again. Native distinguishes this failure from
prior generator/storage callback failures. Trusted direct creation, change-email
issuance and reusable-expiry update retain their separate ordering. The tests
first deliver a real predecessor and then prove which failed reissuance removes
it; retained phone/magic-link/generation-failure predecessors still authenticate.

Each numeric SDK row reads complete actual delivery and verification receipts,
asserts the stored secret representation, counter and deadline, and exercises
wrong-recipient/token controls, exhaustion, fresh generation, authentication,
owned user/session state and replay. Unbounded-budget rotation appends another
live row; consumption selects the newest generation and clears the identifier.
Random secrets are asserted against their actual persisted values locally;
differential observations retain complete endpoint results, persisted user and
session state, row counts, counters, credential lengths and original deadlines.
The existing primary owners retain browser-preference, reuse/codec, concurrent
consumption, credential replacement, cleanup and authorization controls.

## Exact expiry equality

Source checks `expiresAt < new Date()` on lookup and consumption; its global
cleanup uses the same strict millisecond cutoff. An external diagnostic froze
only process realtime at `2026-10-02T14:06:40.500500Z` while preserving monotonic
clocks. Source Date and native issued deadlines were `.500Z`. Source consumed
real zero-lifetime email and phone codes, while native cleanup deleted them and
returned `INVALID_OTP`. SeaORM cleanup now truncates its cutoff to milliseconds;
the existing memory store retains equal-millisecond deadlines too. Typed SQL
lookup operators and unrelated expiry policies are unchanged.

The diagnostic uses real delivered credentials, existing controlled physical
expiry updates for magic-link, complete stored receipts and owned persisted
sessions. It covers equality, one-millisecond-earlier expiry, wrong recipient or
unissued token, removal and replay. The clock shim and runner are external
reproduction artifacts, not repository hooks or production clock injection.

## Excluded probes and native safety

Positive lengths below 0.5 allocate a zero-byte random buffer and cannot advance
Source's loop. Positive infinity and huge lengths are allocation-unsafe; these
runtime probes are excluded. Native rejects them without allocation or looping.
The built-in generator permits `[0.5, 32768.5)`: Source allocates
`floor(length * 2)` bytes, and Web Crypto rejects buffers above 65,536 bytes.
This bound preserves safely terminating Source generation rather than allowing
unbounded work. The upper resource boundary is derived from the installed
implementation and API limit, not exercised with giant random allocations.
Application-provided email generators keep ownership of their returned code.
Date values outside JavaScript's TimeClip or the native physical date range fail
through the checked native representation.

## Focused evidence

- Exact representable zero-length regression: Source empty 500 versus native
  issuance 200 before repair, `/tmp/issue208-baseline-sdk.log`.
- Actual predecessor-proof regression: Source deletes the email proof on invalid
  lifetime retry; native retained it before the stage repair,
  `/tmp/issue208-partial-regression-before.log`.
- Exact equality before repair: `/tmp/issue208-equality-before.log`; full owned
  Source state plus native failure: `/tmp/issue208-equality-regression-before.log`.
- Equality, one-millisecond expiry, foreign proof and replay controls pass in
  both runtimes: `/tmp/issue208-equality-after.log`.
- Final focused results and exact equality controls are recorded in the PR.

The repository-wide canonical gate is run by the coordinating batch. This issue
uses focused native, SDK, fixture, TypeScript, formatting and strict package
checks and does not claim a fresh whole-workspace gate on this branch.
