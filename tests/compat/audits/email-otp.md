# Email OTP capability

Owner: upstream_audit. Reference: published `better-auth@1.7.6`; the oracle
remains pinned. The capability branch descends from the core email-verification,
nullable plugin-fields/defaults and shared storage prerequisites, and activates no magic-link or
phone-number authentication.

## Included behavior

All nine public OTP endpoints issue, validate or consume operation- and
mailbox-scoped proofs. Successful sign-in creates a verified account or proves
the existing account, revokes access accrued before mailbox ownership, and
issues a persisted session with a signed cookie. Password reset updates or
creates the credential and inherits configured password/reset callbacks and
session revocation. Email changes belong to the requesting session's user and
can require current-mailbox proof.

The two trusted server operations create and retrieve codes through the
initialized context. They have no public authentication route. The local
fixture exposes them through a controlled test-only server interface and
asserts the resulting verification rows.

Default codes contain six digits, expire after 300 seconds, rotate on resend,
and allow three attempts. Plain, SHA-256 hashed, XChaCha encrypted and custom
codec storage are supported. Reusable plain/encrypted proofs retain their code
and attempts while renewing expiry. Hash-only storage rejects retrieval and
rotates because it cannot recover the original secret.

Consumption is atomic. Expired, exhausted, wrong-user, wrong-mailbox,
wrong-operation and replayed proofs cannot create sessions or change accounts.
Cancellation by a verification update hook terminates without an unbounded
retry. Reads snapshot the newest row before the configured global expiry
cleanup; disabling cleanup preserves unrelated expired rows.

## First-caller shared prerequisites

- The OTP verification-email override trait is implemented by this production
  plugin. Signup persists its proof through the active transaction, and an
  explicitly configured core sender retains precedence.
- Initialized password-management settings supply reset callbacks and policy.
- `VerificationConfig.disable_cleanup` configures the existing hook-aware
  storage cleanup primitive. Raw lookup semantics remain unchanged.
- Neutral helpers supply scoped verification reads, additional username
  validation, real session issuance, signed remember-me cookies and cleanup of
  access accrued before mailbox ownership.
- The neutral token codec and direct XChaCha dependency implement the pinned
  encrypted representation. No JWT-plugin implementation is included.

## Evidence

The isolated branch passes 20 native OTP tests. They cover expiry, scoped
attempts, successful and rejected lifecycle transitions, concurrency,
non-consuming checks, hook cancellation, credential replacement and session
revocation, current/new-email ownership, encrypted upstream vectors and
notification failure after proof issuance. An absent username schema ignores
malformed additional username inputs and persists no username fields; the
SQLite and official-client regressions both fail before the parsing repair.

The final focused official-client run passes all 21 SDK scenarios with 750
assertions, including three inherited email-verification configuration scenarios.
The initial five raw null-versus-false failures were repaired by the shared
nullable storage and per-auth plugin defaults prerequisite. The trusted state
inspector uses the optional persisted getter. No normalization or comparison
exception was introduced.

The absent-username official-client regression passes with 44 assertions after
repair. Client TypeScript checking and the excluded fixture build pass. A
focused transport regression exposed duplicate binary/JSON content types in
the trusted server fixture's error projection; replacing the auto-added header
with the actual JSON header repairs it without changing authentication behavior.

Independent review resolved the hook-cancellation loop and global expired-row
cleanup findings. The complete canonical gate passed on
`4f5d7318cd925d8852054bff6aecb086ff15bb98`: 163 strict SDK scenarios (1,408
assertions), 23 harness tests, two Chromium tests, default/optional native
configurations, Clippy, Rustls/Redis builds, TypeScript and documentation.
Source coverage was 77.47% (17,828/23,014 lines). The native route inventory
fixture registers the actual OTP plugin; strict inventory equality is retained.
The nine OTP inventory entries are activated deliberately with successful flow,
rejection, applicable authorization and real state-transition evidence; all
other committed requirements are preserved.

A later bounded repair treats a signed empty `dont_remember` cookie as false,
while nonempty values including the string `false` retain upstream truthiness.
The existing SQLite sign-in/replay contract now tests absent, empty, `false` and
`true` preferences with default seven-day and configured 90-second TTLs and a
configured cookie name. It independently checks persisted full-length expiry,
signed-cookie identity, HTTP-only/path attributes and preference-cookie reissue.
The pre-fix native and official-client runs fail at the wrong empty-preference
Max-Age after the pinned runtime passes all four cases. This repair passes all 20 native OTP tests, 21 SDK scenarios (750 assertions),
TypeScript, fixture build, production Clippy and a bounded independent review.
The complete magic-link descendant gate then passes on
`25544d9341d60e22fd3fdc8a03158c9fba05fd93`, inheriting this repair: 171 strict
SDK scenarios (1,720 assertions), 23 harness tests, two Chromium tests and
77.59% source coverage (18,043/23,254 lines), with every canonical native,
feature, lint, browser and documentation check retained.

## Passwordless username input stages

Passwordless creation parses registered username and display-username input
before username validation and collision lookup. The create hook derives its
display fallback from that parsed candidate; adapter transforms remain a
separate storage stage. This matches pinned `parseUserInput` rather than
lowercasing the final display value. Both callers supply a fresh candidate;
trusted identity-policy mutations occur afterward and retain physical binding
authority.

The existing OTP signup owner reproduces the former `Mixed.Owner` fallback
failure and covers collision proof consumption, failed-proof replay, foreign
signup retry, and unchanged original-owner state. It also exercises twelve
configured username profiles through real OTP deliveries and the custom
post-normalization profile through real phone creation. Callback transcripts
and counts preserve endpoint, validation, create-hook, and adapter stages.
Readonly input, Unicode lengths, normalization preservation, display validators,
disabled display output, and immutable policy remain covered.

The shared fixture database is inspected through a profile registering both
username columns, independently of the signup profile's public projection.
A display-disabled Source adapter read omits that physical column; it is not
used as a complete storage receipt. Public signup and session output still use
the configured profile. This repair does not expand passwordless request parsing
to arbitrary application additional fields.

## Remaining audited boundaries

Plugin-specific default rate limits, versioned secret envelopes, schema
renaming and additional-field validators/transforms, actual callback request
and context exposure, and dynamic URL/origin configuration remain explicit
broader audit boundaries. This capability's evidence does not establish them.
