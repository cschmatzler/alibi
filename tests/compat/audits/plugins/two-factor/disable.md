# Two-factor disable success and authoritative ownership

Reference: published `better-auth@1.7.6`, `plugins/two-factor/index.mjs`
`disableTwoFactor`, `api/routes/session.mjs` sensitive-session middleware, and
`cookies/index.mjs` session-cookie issuance. This selected capability changes
only disable and the shared session-issuance helper it calls.

The endpoint now requires the existing authoritative persisted signed-cookie
session. API-key virtual sessions and bare bearer tokens cannot authorize it;
password verification still belongs to that cookie's user. User enablement is
updated before factor deletion, matching upstream's observable write order.
A replacement session carries the current server-controlled organization,
team and impersonation fields through atomic `CreateSession`, retains IP/user
agent, and retires the old token. The original session helper delegates with
no overrides and retains its admin-ban behavior. The replacement cookie
inherits a signed nonempty `dont_remember` preference. Trust deletion removes
all rows with the signed cookie's identifier and propagates storage errors,
instead of deleting one arbitrary match and swallowing its result.

The primary official-client lifecycle performs actual enrollment/TOTP,
second-factor SMS-free OTP delivery/verification, persisted trusted-device
creation, organization selection and successful disable. Guest, wrong-password
and foreign-user attempts preserve the owner's real factor, session rows and
trust record. Success clears the factor/trust records, rotates the sole stored
session without losing active organization, prevents old-token replay from
mutating state, and permits a later password-only sign-in. Browser preference
and cookie attributes are compared by the unchanged harness.
A separate credential-boundary scenario first proves that a real API key
establishes a virtual session, then proves it cannot disable a factor even with
the correct password; a bare bearer token is also rejected. Normal cookie
ownership can still complete disable.

A native SQLite route test has a distinct risk: configured team/impersonation
fields and duplicate persisted trust identifiers are inaccessible in the
shared SDK profile. It initializes the actual admin/organization/team plugins,
stores those extensions and two matching trust rows, calls the real disable
handler through a signed cookie, and reads the resulting users/sessions/factor
and trust state. It needs no test-only production seam.

Before: `/tmp/two-factor-disable-before.log` has eight SDK scenarios passing,
two failing because successful rotation loses active organization and API-key
emulation receives 200 instead of upstream 401. The configured native route
fails with missing organization in `/tmp/two-factor-disable-native-before.log`.
After: ten focused native tests pass (`/tmp/two-factor-disable-native-final.log`)
and all ten SDK scenarios / 112 assertions pass against both runtimes
(`/tmp/two-factor-disable-sdk-final.log`). TypeScript, workspace library Clippy
with `seaorm`, formatting and diff checks pass. Independent coordinator review is clear. The integrated canonical gate passes:
259 SDK scenarios / 7,374 assertions, 37 harness tests / 210 assertions,
two Chromium tests / 22 assertions and 79.21% source lines
(23,646 / 29,853). Log: /tmp/two-factor-disable-selected-canonical.log.
Both lifecycle and API-key authority scenarios are explicitly required by the
inventory, including persisted retirement evidence.

Merge-forward contract: once the separately owned `CreateSession.additional_fields`
and `AuthSession::additional_fields` land, replacement issuance must also carry
the trusted stored custom fields as `FieldValues`/`JsValue`; this baseline has
no such model API. Broader configurable passwordless management, disabled
methods, custom OTP/backups, cross-challenge lockout and renamed schema fields
remain separate capabilities. No schema, lockfile or inventory was changed.
