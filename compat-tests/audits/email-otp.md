# Email OTP capability

Owner: upstream_audit. Reference: published `better-auth@1.7.6`; the oracle
remains pinned. The capability branch descends from the core email-verification
prerequisite and shared storage foundation, and activates no magic-link or
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

The first official-client isolated run passes 14 of 19 SDK scenarios,
including the three inherited email-verification configuration scenarios.
Five configuration scenarios expose a real shared persistence deviation:
upstream stores null `twoFactorEnabled` when its plugin is absent, while the
bundled Rust entity currently stores false. The difference remains visible;
no normalization or comparison exception was introduced. The shared nullable
storage and plugin-default prerequisite is coordinated centrally before the
capability can pass its canonical gate.

The additional absent-username official-client regression passes with 44
assertions after repair. Production Clippy for core/API, client TypeScript
checking and the excluded fixture build pass.

Independent review resolved the hook-cancellation loop and global expired-row
cleanup findings. Canonical coverage, browser checks, optional builds and
inventory updates remain serialized coordinator responsibilities.

## Remaining audited boundaries

Plugin-specific default rate limits, versioned secret envelopes, schema
renaming and additional-field validators/transforms, actual callback request
and context exposure, and dynamic URL/origin configuration remain explicit
broader audit boundaries. This capability's evidence does not establish them.
