# Two-factor disable schema ordering

The published Better Auth 1.7.6 handler declares a required password when the
outer allowPasswordless option is false and an optional password when true.
Explicit null is invalid in either schema. The actual BetterCall HTTP runtime
validates that body before the authoritative-session middleware. A standalone
real-handler probe records both configurations and all null/missing/valid guest
outcomes in `/tmp/two-factor-disable-body-order-oracle.log`.

The production change moves the existing dynamic parser immediately before
`require_authoritative_session` in the disable route. It retains the exact
parser, requiredness, authoritative-cookie restriction, error conversion,
password policy and every subsequent user/factor/trust/session operation.
Malformed guests now receive the source's 400 VALIDATION_ERROR. A valid body
still receives 401 UNAUTHORIZED without an authoritative cookie; omitted
password is a schema error under the default configuration and reaches that
401 check under the passwordless configuration.

The regression extends two existing official-client owners with one shared
three-input guest table. The default disable success case already has a real
enrolled factor, a stored trusted-device record and an active organization.
It asserts that guest, wrong-password and foreign-password rejection leave the
complete actual user/account/session state and trust row unchanged before a
successful signed-owner disable rotates the token, preserves organization,
removes factor/trust records and denies the old signed-cookie replay. The
passwordless social owner checks the same null/missing/valid guest contracts
with the outer flag enabled, preserves its complete stored state, then performs
its already-owned successful passwordless disable. The separate existing
API-key emulation and bare-bearer case remains intact and passes: a real API key
can read its virtual session but cannot disable a factor, while the signed
owner succeeds. No fabricated fixture response, extra profile, comparator
exception or duplicated enrollment setup supplies this evidence.

Before the route reorder, those two owner cases fail specifically on Rust 401
UNAUTHORIZED instead of source 400 VALIDATION_ERROR after their real factor
setup (`/tmp/two-factor-disable-validation-sdk-before.log`). Both source runs
complete before the Rust failures. Afterward all 33 two-factor SDK scenarios /
1,266 assertions pass (`/tmp/two-factor-disable-validation-sdk-final.log`), as do
12 existing native two-factor tests
(`/tmp/two-factor-disable-validation-native-final.log`), TypeScript and
workspace library Clippy (`/tmp/two-factor-disable-validation-typecheck-final.log`
and `/tmp/two-factor-disable-validation-clippy-final.log`). Formatting and diff
checks pass. A duplicate native parser-order test would be weaker than these
actual middleware/HTTP cases and was not added.

This five-file capability is based on the coordinator's frozen integrated
passwordless 5cbcdc5 prerequisite. It adds no shared core contracts, fixture
behavior, schema, migration, registration, lockfile, coverage or inventory
changes. The coordinator owns independent review and canonical full gates.
Its future merge with OTP must retain that slice's enable-method schema and
body-before-authoritative ordering. Global before-request hooks, including
API-key quota/invalid-key handling, retain their own existing ordering and are
not newly claimed by this route-local correction.

## Integrated validation

Forward integration with configured OTP retains the enable method schema and inherited password policy. Independent review is clear. The complete canonical gate passed: 316 SDK scenarios / 10,762 assertions, 39 harness tests / 243 assertions, two Chromium tests / 22 assertions, and 79.38% source coverage (25,562 / 32,203). Log: `/tmp/two-factor-disable-validation-reviewed-canonical.log`. PR #47; all earlier required evidence remains.
