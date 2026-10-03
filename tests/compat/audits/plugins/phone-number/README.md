# Phone number authentication

The behavioral reference is the installed better-auth@1.7.6 phone-number
plugin: index.mjs, routes.mjs and client.mjs. Five public POST routes now support
phone password sign-in, OTP delivery, verification and password reset. Typed
consume_otp remains server-only and neither creates a user nor issues a session.
The default challenge has six digits, a 300-second lifetime and three attempts.
Rust integrations use async sender, validator, verifier and verification-hook
traits, plus a temporary signup identity provider.

## Ownership and lifecycle

Local challenge consumption uses the store's atomic consume operation. Wrong
codes preserve expiry and advance the attempt counter; expiry and exhaustion
remove the challenge. A successful proof cannot be replayed or consumed twice
by overlapping requests. A configured external verifier owns its expiry and
replay policy; acceptance removes any local verification rows. Verification
consumes proof before authenticated update ownership checks or signup input
guards, matching the pinned runtime's observable ordering.

Authenticated phone replacement retains the requester and existing session and
rejects an occupied number. Direct nonnull update-user phone input is forbidden.
An explicit null clears the number and verification flag through an instance
local update transform, including trusted context/store facades. Email signup
accepts the phone field only when the plugin is enabled and rejects truthy
client-supplied verification claims. Disabled username fields are removed from
the raw JsValue object without rewriting the remaining numbers.

Numeric signup inputs use the preceding JSON/SQLite capability: JavaScript f64
rounding precedes Bun's integer/real binding selection and actual SQLite TEXT
conversion. Negative zero, Int52 boundaries, subnormal values and overflow retain
their binding semantics. Inf/-Inf are stored and participate in phone uniqueness;
they are not treated as null or malformed JSON. Numeric-looking IDs and provider
configuration literals do not undergo this coercion.

Password sign-in checks required phone verification before credential validation,
issues a one-day session for rememberMe:false, and participates in two-factor
challenges and signed trusted-device ownership/rotation. Password reset consumes
proof before password-policy validation, creates or updates only the owner's
credential account, invokes the configured reset callback and honors session
revocation. Missing-user reset issuance retains the upstream verification row.
Sender failures follow the pinned blocking/nonblocking notification boundaries.
Verification callbacks observe the persisted verified owner before session
issuance; callback rejection prevents issuance.

## Primary evidence and distinct native contracts

Eleven official-client dual-runtime scenarios exercise real configured SMS
delivery callbacks and inspect persisted users, credentials, sessions and proof
rows. Four isolated profiles cover default no-signup behavior, signup, required
verification and an external verifier/validator. The scenarios cover schema
errors, spoofing, finite and overflowing raw numbers, uniqueness collisions,
proof budgets/expiry/replay, account ownership, server-only consumption, null
updates, rememberMe cookies, two-factor trust, reset policy ordering and external
provider binding. Successful repeated verification checks the real configured
callback's owner records. Fixtures deliver codes; production decides validity,
consumption, identity, authentication and persistence.

Twelve plugin-native tests additionally reach notification failures, callback
rejection ordering, concurrent consumption, imported attempt counter spellings
and a valid trust cookie belonging to another owner. Three SQLite integrations
exercise instance-local transforms through both trusted store facades, bundled
signup field registration and actual adapter number coercion. These native
contracts do not depend on a fixture implementing the asserted transition.

Before implementation the pinned TS verification flow completed while the Rust
fixture returned 404 at send-otp: /tmp/phone-v2-baseline.log. After refresh onto
the repaired numeric and user metadata prerequisites, final focused evidence is:

- /tmp/phone-v2-final-api.log: 313 API native tests, including all twelve phone
  tests and existing shared parser/session consumers.
- /tmp/phone-v2-final-integration.log: three SQLite phone integrations.
- /tmp/phone-v2-final-sdk.log: eleven SDK scenarios, 1058 assertions.
- /tmp/phone-v2-final-typecheck.log and /tmp/phone-v2-final-clippy.log:
  client TypeScript and production workspace Clippy with seaorm.

Independent coordinator review traced ownership, proof consumption, credential
writes, callback ordering and trusted-device checks against the pinned source.
The integrated canonical gate passes: 255 SDK scenarios / 7,248 assertions,
37 harness tests / 210 assertions, two Chromium tests / 22 assertions and
79.00% source lines (23,531 / 29,787). Log: /tmp/phone-selected-canonical.log.
All five routes require explicit configuration, rejection, ownership and
persisted-state evidence in capabilities.json. The inventory enables the phone
plugin independently; the baseline wire fixture retains its matching TypeScript
configuration. This slice
does not change comparators, skip tests, relax coverage, update dependency
versions or change database schemas. Local fixtures disable rate limiting to
exercise lifecycle cases; this evidence does not claim production SMS transport
or a distinct phone rate-limit policy. Applications supply their real delivery
provider and, when configured, external verifier policy.

## Raw numeric configuration

The [passwordless numeric audit](../email-otp/passwordless-numeric.md) records native `f64`
configuration, real delivery/persistence/consumption evidence, plugin-specific
zero/NaN policies, checked millisecond expiry and excluded unsafe probes.
