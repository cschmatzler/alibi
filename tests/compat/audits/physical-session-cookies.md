# Physical session token and preference cookies

Issue #301 is a separate production prerequisite for #205. It does not close
the broader cookie policy issue #177. Discovery used actual main
`bb4142faa155e60b745184401c531b2db9dfd34d` and installed Better Auth 1.7.6.
No root or scoped AGENTS.md exists. The test-audit authoring gate applies;
OpenClaw/Crabbox/autoreview helpers are unavailable in this environment, so
actual repository gates and independent parent review provide the proof.

## Contract and actual regression

The physical producer used cookie::Cookie formatting, synthesized Expires from
Max-Age, forced Secure for SameSite=None, and ignored the already public
advanced cookie name/attribute configuration. The authenticated reader used
the legacy name, even when the public configuration declared a different token
name. These are observable complete response headers and restoration behavior.
The two existing #205 ordinary/cached signed organization owners independently
exposed three signup header suffix differences each; their complete captures
remain `/tmp/issue205-signup-header-controls.json`, SHA256
`6d01e50dbcb66f9c613f8649fb7163b4adda4d85ccf072ca4b3fad45f0e8e2ba`.

The new primary table drives seven actual installed HTTP/official SDK profiles:
defaults, declared custom token/preference names and attributes, Secure,
SameSite=None with explicitly false Secure, a 60-second durable lifetime, and
two arbitrary exact legacy token names (`customsession` and `some.alias`).
Source uses its real advanced configuration; Native uses the existing public
CookieAttributes/CookieOverride fields. Neither fixture implements cookie
rendering, signs a credential, supplies a callback receipt, or changes Source.

Each owner checks real signup, browser restoration, a deliberately corrupted
issued HMAC, rememberMe=false token plus signed preference, rememberMe=true
rotation, restoration of each new token, and logout with actual clear headers.
Bound SQLite reads retain every declared core user, account and session column;
owner and foreign physical rows protect deletion/rotation scope. The actual
SQLite scrypt bytes are retained, with salt/key encoding metadata and published
password verification accepting the genuine password and rejecting a foreign
password. These profiles do not declare extra user/account schema fields.

Full cookie bytes are represented losslessly by literal prefix/name, the actual
encoded credential, and literal complete attribute suffix. Concatenation must
equal the raw header. Each live credential independently passes canonical URI
encoding, base64 length and real HMAC-SHA256 verification, and its plaintext
must equal the actual SDK session token or preference literal true. Existing
token identity reconciliation compares independently random real credentials;
no comparer, allowlist, timestamp rule, package or global parser changes here.
Every attribute, order, clear value and cookie name remains literal.

The pre-fix owner completed every Source lifecycle and failed 0/5, 1,322
assertions: `/tmp/issue301-before-owner4.log`. Default and short failed seven
exact suffix paths (signup, durable signin, both transient cookies and three
clear cookies); custom attributes failed the actual token name, Secure failed
the actual flag, and SameSite=None failed its actual policy. The original
production had not been edited during these measurements.

## Bounded production change and caller audit

Physical shared helpers render already encoded values in Source's order:
Max-Age, Domain, Path, HttpOnly, Secure, SameSite. They emit no synthetic Expires.
Legacy session settings remain defaults, then configured cross-subdomain,
default attributes and logical per-cookie attributes apply. Token publication
explicitly replaces Max-Age, including with absence for a browser session;
preference publication preserves a declared 121-second per-cookie lifetime.
Clearing preserves the configured name and attributes with Max-Age=0. Explicit
__Host-/__Secure- names retain Source's serializer restrictions. Initialization
gives authentication the same configured token name; direct public token/clear
helpers also resolve that name. The old explicit legacy cookie name/prefix
behavior remains when no advanced name or prefix is configured. The initial
direct-helper follow-up regressed arbitrary legacy names; the bounded correction
returns the exact legacy name specifically for the token family after genuine
advanced name/prefix selection. Related preference/cache naming retains its
existing fallback policy.

All production callers were read: email/password signup/signin, session refresh,
email verification, authentication helpers, anonymous, admin impersonation,
passkey, SIWE, one-tap, one-time-token, MultiSession, two-factor, organization
invitation/session renewal, OAuth proof cookies, root/core issuance and shared
session deletion. Signed helper callers already pass encoded values; rendering
must not encode them a second time. The integer helper API remains unchanged.
The existing password-change native owner now requires the actual configured
Max-Age and absence of synthesized Expires, replacing its obsolete expectation.

The separate compact cache renderer/runtime and its authenticated successful
read memo, publication observation, chunk cleanup and transient-MFA retirement
are unchanged. OAuth and user-management have legacy local related-name helpers;
this issue does not claim all configured names for those cookie families.
Two-factor's floating Max-Age owner appends its own validated age; its broader
attribute order/configuration is not established by these five physical owners.

## Recorded proof and explicit limits

The first repaired program passes 5/5, 1,710 assertions:
`/tmp/issue301-after-owner5.log`. Its optional workspace/fixture strict Clippy,
TypeScript and affected password-change native owner passed:
`/tmp/issue301-strict6.log`. After the direct-helper name follow-up, the same
five owners pass unchanged in `/tmp/issue301-final-owner7.log`; final optional
workspace/fixture strict Clippy, TypeScript and both formatting checks pass in
`/tmp/issue301-final-strict9.log`.

Independent actual Source/native SDK probes retain ten complete lifecycles,
70 literal raw Set-Cookie headers, combined headers, full requests/responses,
real restored sessions and physical SQLite rows in
`/tmp/issue301-raw-cookie-captures.json`, SHA256
`5d956ac8e5f0dc454c66d1fca317afa4bb88910530e6a59d075ca51b12d34f10`.
The probe verifies every live HMAC and each actual restored SDK token:
`/tmp/issue301-raw-captures8.log`. No raw cookie bytes are removed.

Setup failures are retained separately: initial TS expected-argument typing,
an import accidentally preceding the Source shebang, and tough-cookie's actual
absent Max-Age representation being null (before-owner1/2/3 logs). The raw
probe's first attempt omitted the genuine Origin header after signup and hit
the actual CSRF guard; owner7 retains that failed diagnostic attempt after its
successful five owners. Raw attempt8 supplies the real origin, as the SDK
scenario's existing transport does. None is presented as a product before.

Broader #177 remains open: HTTPS/environment factory secure-prefix inference,
partitioned/priority/Expires options absent from the current typed config,
400-day validation through currently infallible helpers, deployment/browser
constraints, general configured compact/cache/chunk/account/OAuth/2FA policy,
and every cross-subdomain default-domain inference branch. SameSite=None here
proves Source's emitted insecure header and actual standards CookieJar behavior;
it does not claim that every browser accepts that configuration. Advanced
cookie-prefix selection is traced production behavior, rather than a separate
measured profile in this owner. The capability owner reran 5/5, 1,710 assertions with actual evidence capture
(`/tmp/issue301-capability-owner10.log`); all 5,297 parent capability cells
remain and 35 observed success/state cells are added. The historical 4ba61831 full canonical terminated with exit 100: default 793,
optional 845, fixture 2, harness 76 (1,126 assertions), Axum 36, endpoint 3 and
inventory 2 passed. Full SDK was 1,430/1,431 with 93,564 assertions; the only
failure was the known #174 expired-reset/OTP `observation.observations.0.proof.length`
(`/tmp/issue301-canonical-4ba61831.log`). Independent strict Rustdoc/browser
passed (two actual Chromium tests, 22 assertions; wrapper 1/1) in
`/tmp/issue301-docs-browser-4ba61831.log`. Actual fresh clean coverage, with
MBX_DISABLE=1 inside devenv and all five SDK wrappers, passed the unchanged 75%
floor at 32,050/41,491 (77.245668%); 214 LCOV paths had zero duplicates
(`/tmp/issue301-clean-coverage-4ba61831.log`). These are historical program
results, not proof of the later legacy-name correction.

The extended unchanged-program before captures retain the review finding:
`/tmp/issue301-legacy-before11.log` is 5 pass/2 fail (2,128 assertions), with
genuine Native SDK restoration null for both legacy names after Source
completed every lifecycle. The clearer producer-boundary run in
`/tmp/issue301-legacy-before12.log` is 5 pass/2 fail (2,126 assertions): both
Native token names were literally `better-auth.session_token`, rather than
`customsession` or `some.alias`. The exact reader still expected each configured
legacy name. With only the token-family fallback corrected, the same seven
SDK owners pass 7/7 (2,450 assertions) in `/tmp/issue301-legacy-after13.log`.
The foreign actor now also restores its own real token in every profile; owner
and foreign reads and physical rows remain separate. Fourteen observed cells
are appended for the two legacy owners, preserving all existing parent cells.
Final composed-program proof is pending; no final green claim yet.


## Composed legacy repair checkpoint

Candidate 9d66dff3 is based on actual merged CAPTCHA main afb5184f. Its additive
ledger preserves all 5,433 actual parent cells plus 49 observed cookie cells
(5,482 total). The composed seven SDK owners pass 7/7 (2,450 assertions), with
actual capability capture enabled: `/tmp/issue301-composed-cookie-owner14.log`.
Independent full raw captures retain 14 Source/native SDK lifecycles and 98
complete headers, all responses/requests and SQLite rows in
`/tmp/issue301-raw-cookie-captures-9d66dff3.json`, SHA256
`454e85a6749bc8bf50bb1643a9ec44bf2929e24ec073395fdaa7fd9a11489e14`.
Docs and the actual Chromium wrapper pass in
`/tmp/issue301-docs-browser-9d66dff3.log` (wrapper 1/1).

The first extra fixture strict gate found an inherited CAPTCHA fixture
`unnecessary_lazy_evaluations` warning (`.then(|| application as Arc<dyn
ValidateBotIdRequest>)`) before canonical started. The correction is exactly
Clippy's `.then_some(...)` recommendation; it changes neither native CAPTCHA
production nor installed Source or the actual cookie observations.
The actual canonical independently passed all workspace strict checks, default
793, optional 845 and fixture 2, then stopped on the added foreign SDK token's
static `string | null` expectation type. Its actual runtime token was already
restored and verified; the test now explicitly asserts a string and uses that
nonnull type for the expectation. Both setup/strict failures are retained in
`/tmp/issue301-canonical-9d66dff3.log` and
`/tmp/issue301-actual-canonical-9d66dff3.log`; neither is presented as a passing
whole canonical or a native production regression.

Two real fresh coverage attempts on frozen 9d66dff3 passed Native 845 and
account/CAPTCHA wrappers, then stopped at JWT. Attempt1 retained only the known
remote configured-default expiry aliases
`finalReceipts.events.1/2/3.payload.exp`. Attempt2 retained only the keyring
manual key's `createdAt`/`expiresAt` on `manualState.events.0.key` and
`manualState.keys.1`, with literal Source 08:55:43.472 and Native 08:55:46.636
UTC issuance times. Full logs are `/tmp/issue301-clean-coverage-9d66dff3.log`
and `/tmp/issue301-clean-coverage-9d66dff3-attempt2.log`; OAuth/sessions/user
management were unreached and no floor was produced. No timestamp rule changed.
Final strict, canonical and fresh coverage remain pending on the fixture-only
corrected checkpoint; the reviewed three-line legacy token production repair
is unchanged.
