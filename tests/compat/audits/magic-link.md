# Magic-link capability

Owner: upstream_audit. The published `better-auth@1.7.6` magic-link runtime
remains the oracle. This branch adds only magic-link production code,
configuration fixtures, official-client evidence and documentation on the
email-OTP stack's already shared authentication/token helpers. It activates
no phone-number, JWT or session-plugin capabilities.

## Included behavior

`POST /sign-in/magic-link` persists a mailbox/name-bound proof before delivery.
The sender receives the actual token, URL and caller metadata. Default tokens
contain 32 letters and expire after five minutes. Plain, SHA-256/base64url and
custom hashing compose with application-owned token generation.

`GET /magic-link/verify` authorizes all three callback origins before consuming
its proof. It loads or creates the actual mailbox owner, promotes an unverified
mailbox by revoking its unproven accounts and sessions, and persists a new
session with a signed cookie. Missing, expired and reused proofs cannot create
sessions. Consumption is atomic, including when two callers share a token.
Disabled signup still issues/delivers the proof but consumes unknown-user
links without creating a user. Existing users can authenticate.

Responses retain callback URL query/fragment semantics. New users use the
new-user callback; failures use the error callback. Omitting callbackURL
returns the actual token, user and session. Delivery errors propagate after
issuance and leave the persisted proof available.

## Evidence and dependencies

Eight real SQLite native tests pass, covering persistence, delivery metadata,
callback authorization before consumption, one-use sessions, expiry, disabled
signup, account promotion/revocation, custom generation/storage, concurrent
consumption, strict body validation and delivery-error retention.

All seven default and configuration SDK scenarios pass against both actual
fixtures with 176 assertions.
The new-user lifecycle scenario fails on the pre-feature fixture at the
expected missing route before repair. The initial two hashed/disabled signup
configuration failures exposed a real raw-persistence difference: upstream
stores null twoFactorEnabled when its plugin is absent, while the earlier Rust
bundled entity stored false. The integrated nullable/plugin-default prerequisite
repairs storage and per-auth creation defaults; the trusted state inspector
preserves the actual optional value. No comparison exception was added.

The official SDK is used for issuance and JSON consumption; actual delivered
URLs exercise redirect flows. Assertions inspect real users, accounts,
sessions and verification rows. TypeScript checking and the excluded Rust
fixture build, focused production Clippy and formatting pass. The two magic-link
inventory entries require the actual successful flow, malformed-input rejection,
applicable callback authorization and persisted state evidence. All other
committed requirements remain unchanged.

The complete canonical gate passes on
`25544d9341d60e22fd3fdc8a03158c9fba05fd93`: 171 strict official-client scenarios
(1,720 assertions), 23 harness tests, two Chromium tests, default/optional native
configurations, strict Clippy, Rustls/Redis builds, TypeScript, browser and
documentation checks. Source line coverage is 77.59% (18,043/23,254). This final
descendant run also validates the inherited signed-empty preference repair from
OTP PR #10. Subsequent audit-only commits leave production and test inputs
identical to that canonical-gated tree.

## Explicit audit boundaries

Plugin-specific default rate limits, renamed/custom schema fields and
additional-field transforms, actual sender/generator request-context exposure,
versioned secret envelopes and dynamic base URL/origin configuration remain
explicit broader audit gaps. This bounded change does not claim complete
Better Auth parity.

## Raw numeric configuration

The [passwordless numeric audit](passwordless-numeric.md) records native `f64`
configuration, real delivery/persistence/consumption evidence, plugin-specific
zero/NaN policies, checked millisecond expiry and excluded unsafe probes.
