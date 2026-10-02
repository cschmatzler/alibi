# TOTP configuration and server generation

Reference: published Better Auth 1.7.6, including
`plugins/two-factor/index.mjs`, `plugins/two-factor/totp/index.mjs` and
`@better-auth/utils/otp.mjs`. This slice owns TOTP issuer, integer period/digit
settings, disabled methods and the server-only `generateTOTP` capability.

## Production contract

`TwoFactorPlugin::generate_totp` accepts application-owned UTF-8 secrets; no
public HTTP endpoint exposes it. The pinned HMAC implementation accepts short
nonempty and Unicode keys, so the Rust dependency's stronger key-length policy
cannot reject them. The production constructor validates the upstream 1–8
digit constraint and rejects empty keys before its unchecked library constructor.
Period and digits use upstream truthy defaults for zero during generation and
verification. The existing typed period is an unsigned integer; fractional and
negative JavaScript configuration values remain outside this slice.

Enrollment uses its request issuer, then the outer plugin issuer, then app name.
Retrieving an authenticator URI instead uses the TOTP provider issuer or app
name. Empty issuer strings fall back. URI labels use encodeURIComponent
semantics, query fields use URLSearchParams semantics, and default digits and
period remain explicit. Enrollment forwards a configured zero period into its
URI, while the authenticator URI and actual codes use the provider default 30.

Disabled TOTP rejects enrollment after password authentication, and rejects
generation/URI retrieval/verification before factor state access. Error bodies
match each pinned owner, including the distinct enrollment message. URI lookup
loads and decrypts the factor before password validation, so a missing factor
reports TOTP_NOT_ENABLED even with an incorrect password.

## Regression ownership

Four SDK scenarios exercise actual public clients and the real server-only
method through equivalent private fixture adapters. Three configured profiles
and a disabled profile supply only equivalent plugin settings. No fixture
generates a fake code or writes the asserted state.

The generator table independently computes WebCrypto HMAC-SHA1 codes for short,
Unicode and longer secrets with default, 8-digit/45-second and zero-default
settings. It asserts the returned code before redacting its dynamic value for
the ordinary comparator. A public-path request remains 404 and an empty key
fails. The URI lifecycle table checks both configured and zero settings, real
enrollment and challenge completion, wrong-code owner state preservation,
persisted session token ownership, and distinct enrollment/provider issuers.
The disabled-method case proves errors leave the actual owner state untouched.
The default-profile case checks exact reserved-character URI bytes without a
new fixture profile.

Before the production repair, that existing-profile reserved issuer case
returned Rust 500 while the pinned runtime enrolled successfully
(`/tmp/two-factor-totp-owner-before.log`). Before adding the actual capability,
the new configured fixture requests also failed with Rust 404
(`/tmp/two-factor-totp-before.log`). These are separate owner and missing-feature
failures; the tests do not use comparator exemptions. Existing enrollment,
OTP, trust-device and backup-code scenarios remain covered. Their duplicated
WebCrypto TOTP implementations were consolidated into one independent test
helper; no production export exists solely for testing.

## Focused checks and remaining scope

Both pinned runtimes pass 12 SDK scenarios / 204 assertions
(`/tmp/two-factor-totp-sdk-final.log`). Nine existing native two-factor tests,
client TypeScript, production workspace Clippy with seaorm2, Rust formatting
and diff checks pass. The coordinator owns the full canonical gates and shared
inventory. No schema, migration, lockfile or comparator changes occur here.

Factor verification flags, existing-record enrollment reuse, account/challenge
lockout, passwordless enrollment, OTP/backup storage modes and trust-cookie
policy remain separate capability work. This slice does not claim those
branches or arbitrary JavaScript configuration numbers are complete.

Independent SIWE-owner review traced the pinned HMAC/URI/config source and
security boundaries and found the bounded contract clear. The reviewed integrated
`devenv shell -- ./scripts/check.sh` passed: 274 SDK scenarios / 8,168 assertions,
37 harness tests / 210 assertions, two Chromium tests / 22 assertions, and
78.97% source lines (24,009 / 30,402). Log:
`/tmp/totp-configuration-reviewed-canonical.log`. Existing requirements remain
with explicit configured/disabled lifecycle evidence; no comparator or policy
was weakened.
