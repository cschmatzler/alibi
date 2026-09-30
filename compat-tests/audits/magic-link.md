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

Five default-configuration SDK scenarios pass against both actual fixtures.
The new-user lifecycle scenario fails on the pre-feature fixture at the
expected missing route before repair. Two additional hashed/disabled signup
configuration scenarios currently expose the shared raw-persistence difference:
upstream stores null twoFactorEnabled when its plugin is absent; the earlier
Rust bundled entity stores false. This difference remains compared and blocks
the gate until the nullable/plugin-default prerequisite is integrated.

The official SDK is used for issuance and JSON consumption; actual delivered
URLs exercise redirect flows. Assertions inspect real users, accounts,
sessions and verification rows. TypeScript checking and the excluded Rust
fixture build pass. Full canonical validation and measured coverage remain
serialized with the coordinator after dependency integration.

## Explicit audit boundaries

Plugin-specific default rate limits, renamed/custom schema fields and
additional-field transforms, actual sender/generator request-context exposure,
versioned secret envelopes and dynamic base URL/origin configuration remain
explicit broader audit gaps. This bounded change does not claim complete
Better Auth parity.
