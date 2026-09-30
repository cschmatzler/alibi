# Core email-verification parity

Owner: upstream_audit. Reference: published `better-auth@1.7.6` and the matching source tag; the oracle remains pinned.

The passwordless plugins depend on the core verification contract. This change corrects that contract before introducing those plugins.

## Included production changes

- Verification challenges use the pinned HS256 JWT header and payload: lowercased mailbox, optional `updateTo`, request type, and exact NumericDate lifetime. Verification checks signatures, supported algorithm, expiry, and future `nbf` without adding a leeway or mandatory claims the pinned runtime does not require.
- Verification replies preserve configured session behavior, authenticated change-email ownership, persisted user changes, hook ordering, and callback URL query/fragment semantics.
- Email/password signup respects required verification, issues the configured verification message inside registration, and avoids creating a session when verification is required. Email and username sign-in block unverified users and honor the configured delivery callback.
- The send-verification-email schema rejects malformed addresses and explicitly null optional strings. Redirect middleware preserves TypeScript truthiness, body/query precedence, and its earlier non-string-field rejection.
- Shared prerequisites are limited to typed initialized plugin settings, preservation of an initialized email provider, strict string/email body parsing, and signed/URI-encoded session cookies. Cookie consumers validate signatures; existing test inputs now supply actual signed cookies.

## Exact shared prerequisites

`ContextExtensions`, its initialization transfer, and `EmailVerificationConfig`/`EmailPasswordConfig` registration are needed by core signup and sign-in. `authentication_helpers` contains only `String`/`Email` schemas, practical email validation, and body/error parsing used by this route. Cookie HMAC helpers and token extraction implement the reference session cookie contract. The `percent-encoding`, `hmac`, and `sha2` direct dependencies already exist in the workspace dependency graph.

The email-OTP override trait, transactional verification writes, configured expired-verification cleanup, passwordless session response helper, XChaCha encryption, anonymous authentication, phone authentication, and session renewal changes belong to their first calling capability slices. They are intentionally absent from this branch.

The fixture user-state seam reads actual persisted users, credential/account ownership, session identity and expiry, and factor records. It is outside the public authentication router and is used to assert that rejected schemas neither send messages nor mutate state.

## Evidence and validation

- Forty-five native email-verification tests passed before final branch extraction, including externally signed proofs, invalid signature/algorithm/NumericDate rejection, date-free proofs, persisted verification changes, callback redirects, automatic sign-in, and before/after hooks.
- The isolated owner tests passed: 148 core tests, 227 API unit tests, and 18 account/OAuth integration tests. These counts will be rechecked after the storage prerequisite is rebased.
- The redirect middleware regression fails before the repair because it silently accepts a truthy non-string callback; all nine middleware cases pass after repair.
- The SDK schema scenario compares full rejection responses, delivery absence, and before/after persisted state, then confirms successful delivery through the official client. Configuration scenarios and integrated SDK/gate evidence are pending.
- Shared source coverage, browser checks, optional-feature builds, inventory evidence, and canonical validation remain the coordinator's serialized gate responsibility. No final coverage or full-parity claim is made here.

## Remaining integration boundaries

This slice is rebased onto the shared storage foundation before review. The canonical wire timestamp serializer is a separate common prerequisite: official client values must remain real `Date` instances, including microsecond/nanosecond database timestamps. The OTP callback override is added with the OTP capability, where a real production plugin implements it.

The broader audit still records versioned secret envelopes, configurable schema mappings, delivery callback request/context exposure, and additional global middleware/configuration boundaries. Passing these tests does not establish those unimplemented boundaries.
