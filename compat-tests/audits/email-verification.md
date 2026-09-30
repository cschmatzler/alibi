# Core email-verification parity

Owner: upstream_audit. Reference: published `better-auth@1.7.6` and the matching source tag; the oracle remains pinned.

The passwordless plugins depend on the core verification contract. This change corrects that contract before introducing those plugins.

## Included production changes

- Verification challenges use the pinned HS256 JWT header and payload: lowercased mailbox, optional `updateTo`, request type, and exact NumericDate lifetime. Verification checks signatures, supported algorithm, expiry, and future `nbf` without adding a leeway or mandatory claims the pinned runtime does not require.
- Verification replies preserve configured session behavior, authenticated change-email ownership, persisted user changes, hook ordering, and callback URL query/fragment semantics. The legacy updateTo flow reuses/issues a real session, sets its cookie, and issues its follow-up token with the pinned default 3,600-second lifetime.
- Email/password signup respects required verification, issues the configured verification message inside registration, and avoids creating a session when verification is required. Email and username sign-in block unverified users and honor the configured delivery callback. Failed signup/signin/change-email notification callbacks are logged while direct send-verification-email failures propagate, preserving the pinned distinction.
- Explicitly disabled username support omits its registered schema, signup hooks, and both username endpoints; minimal email-verification profiles ignore unregistered additional username inputs.
- The send-verification-email schema rejects malformed addresses and explicitly null optional strings. Authenticated delivery compares normalized mailboxes, while missing, verified, unverified, and delivery-error outcomes retain the unauthenticated 500 ms timing floor. Redirect middleware preserves TypeScript truthiness, body/query precedence, and its earlier non-string-field rejection.
- Shared prerequisites are limited to typed initialized plugin settings, preservation of an initialized email provider, strict string/email body parsing and the awaited notification policy, and signed/URI-encoded session cookies. Default authentication accepts only signed cookies, selects the first duplicate, rejects bare Bearer/unsigned/foreign signatures, and ignores unrelated Authorization headers. Existing happy-path native inputs now supply actual signed cookies.

## Exact shared prerequisites

`ContextExtensions`, its initialization transfer, and `EmailVerificationConfig`/`EmailPasswordConfig` registration are needed by core signup and sign-in. `authentication_helpers` contains only `String`/`Email` schemas, practical email validation, body/error parsing, and the awaited/logged notification policy used by this route. Cookie HMAC helpers and token extraction implement the reference session cookie contract. The `percent-encoding`, `hmac`, and `sha2` direct dependencies already exist in the workspace dependency graph.

The email-OTP override trait, transactional verification writes, configured expired-verification cleanup, passwordless session response helper, XChaCha encryption, anonymous authentication, phone authentication, and session renewal changes belong to their first calling capability slices. They are intentionally absent from this branch.

The fixture user-state seam reads actual persisted users, credential/account ownership, session identity and expiry, and factor records. It is outside the public authentication router and is used to assert that rejected schemas neither send messages nor mutate state.

## Evidence and validation

- Forty-six native email-verification tests pass, including externally signed proofs, invalid signature/algorithm/NumericDate rejection, date-free proofs, persisted verification changes, callback redirects, automatic sign-in, before/after hooks, and anonymous/authenticated legacy updateTo state/lifetime checks.
- After rebasing onto storage foundation 20865c8, the isolated owner tests pass: 150 core tests, 228 API unit tests, 18 account/OAuth integration tests, and public AuthBuilder/SQLite email-verification integration tests. Production Clippy for core/API, TypeScript checking and the excluded fixture build pass.
- Main checkout native regressions confirm disabled username signup persists only core fields and credentials, case-varied authenticated mailboxes match while foreign mailboxes are rejected, and all four unauthenticated outcomes take at least 500 ms without creating sessions or changing users. Each defect was demonstrated before its production repair.
- The redirect middleware regression fails before the repair because it silently accepts a truthy non-string callback; all nine middleware cases pass after repair.
- The six existing/default SDK scenarios pass. Three new configuration scenarios cover required verification, suppressed signup notification, and failed notification callbacks with full persisted credential/session state and actual emitted JWT proofs. Their initial strict run exposed missing common timestamp and disabled-plugin projection dependencies: 6 pass / 3 fail. These are pending production integration; no comparison exception was added.
- Shared source coverage, browser checks, optional-feature builds, inventory evidence, and canonical validation remain the coordinator's serialized gate responsibility. No final coverage or full-parity claim is made here.

## Remaining integration boundaries

This slice is rebased onto shared storage foundation 20865c8. The canonical wire timestamp serializer is a separate common prerequisite: official client values must remain real `Date` instances, including microsecond/nanosecond database timestamps. The OTP callback override is added with the OTP capability, where a real production plugin implements it. The minimal-core profiles also expose seven unconditional username/admin/two-factor user fields when those plugins are absent; this projection dependency remains explicit until repaired in production.

The broader audit still records versioned secret envelopes, configurable schema mappings, delivery callback request/context exposure, and additional global middleware/configuration boundaries. Passing these tests does not establish those unimplemented boundaries.
