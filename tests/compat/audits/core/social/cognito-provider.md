# Cognito provider (issue #142)

The authority is the installed unchanged Better Auth 1.7.6 Cognito factory and
its declared options/profile, shared OAuth authorization/token helpers and raw
account-key resolver. The Source application calls that real factory. Only its
fixed hosted token/userinfo and region/pool JWKS destinations redirect to local
HTTP. Native calls public CognitoOptions and OAuthProvider::cognito with trusted
local transports. Controls supply endpoint responses and application policy;
they never supply an admission, physical row, authentication or fabricated
callback receipt. Full user/account/session columns and foreign principals are
observed through the existing physical SQL observer.

The authoring gate owns fixed/configured endpoints, ordered duplicate-preserving
scopes and their percent encoding, actual PKCE and client-secret transport,
authenticated exact-kid issuer/audience/age/nonce, profile fallback and the raw
subject, callback replay, scoped refresh and local logout. Existing generic
provider coverage cannot establish this missing factory's initialization,
ID-token profile enrichment or hosted-domain defaults. No test-only production
interface or comparison allowance is introduced.

## Native contract

CognitoOptions accepts domain, region and user pool; its factory rejects empty
values, strips a
lowercase http/https prefix and constructs HTTPS authorize/token/userinfo.
Authorization requires a primary client ID, optionally a client secret. Base
scopes are openid/profile/email, followed by configured and requested scopes,
retaining duplicates. Disabled defaults, prompt, identity-provider and trusted
endpoint/callback overrides are explicit. Caller additionalParams cannot
replace the eight reserved OAuth keys; a nonreserved request parameter can
replace an application parameter. Scope uses the published URI-component form,
including WHATWG's final apostrophe escaping and its placement after other keys.

The optional client key is sent in the authorization-code form only. The pinned
refresh helper accepts that option but ignores it; the configured owner retains
complete exchange and refresh forms to establish both behaviors.

Actual token helpers use client-secret post or public none; the factory does
not forward a basic-auth option, so no invented Source basic mode is claimed.
Absent/zero access expiry remains null; fractional expiry is retained. Missing
token-response scope is the empty persisted string, not authorization scopes.
Refresh rotates tokens/expiry but the public operation retains persisted scope.
The factory has no remote logout operation: actual signOut revokes its session
without provider HTTP.

ID admission uses real RS256/JWKS, exact kid and the JWK-declared algorithm,
fixed region/pool issuer, all configured client audiences, one-hour maximum age
and exact nonce. Decoded ID profiles enrich name using name/given_name/username
truthiness before an application mapper. Decode/mapper failure can fall back to
access-token userinfo; malformed raw subject is an admission failure after the mapper. Direct ID sign-in/link
validate email first; browser callbacks resolve the raw subject before the
email guard. HTTP userinfo passes the original unenriched profile to
the mapper. Mapped IDs and getUserInfo user IDs cannot replace the original
profile's subject. The native general provider interface therefore exposes an
optional raw account_subject resolver at the three actual identity-admission
boundaries; existing account-info retrieval retains mapped user data without
re-admitting a new subject. Other factories retain their existing semantics.
The raw data stays intact for identity validation. Existing whole provider
struct literals explicitly preserve or set this optional resolver to None.

## Measured proof and validation

The current program passes **83 actual Source/native owners / 2,446 assertions**
(`/tmp/issue142-83-owners-decoder-clientkey.log`, terminal exit 0). It covers
ordered configured authorization and duplicate reserved-query replacement,
reserved caller rejection, signed claim/profile positives and negatives,
removed/algorithm-mismatched/duplicate-first JWKS rejection and genuine key
restoration, exact nonce, every configured client audience, required credentials,
real secret-post/public exchanges and complete PKCE digest, configured redirect
URI at both authorization and exchange, full HTTP/decoded profile mapping
receipts, malformed-token fallback, actual replay, foreign refresh denial before
provider HTTP, owner rotation, and local logout. Browser cases retain actual
wrong-state/provider, remote token/userinfo HTTP errors, invalid raw subjects and
both signup-disable policies, including explicit requestSignUp under disableSignUp.

The isolated actual-main generic provider configured with genuine Cognito
endpoints failed the default authorization owner for the intended missing
factory behavior: Native forwarded login_hint, while Source's factory omits it
(29 assertions, `/tmp/issue142-generic-observed-before-owner.log`). Only the
Native application fixture adapted its unavailable new public constructor to
an existing generic provider literal; no old production implementation changed.
Real token/userinfo request observation endpoints remain present in that proof.

Further independently observed failures preceded the owning repairs: configured
URL queries appended a second stale response_type (28 assertions,
`/tmp/issue142-existing-query-before.log`), and central raw-subject validation
incorrectly rejected existing account-info retrieval after the provider omitted
sub (22 assertions, `/tmp/issue142-accountinfo-before.log`). The expanded browser
matrix passed 77/79 but Native returned 404 before valid state processing for an
unknown provider and prioritized missing email over missing raw subject
(`/tmp/issue142-browser-boundaries-before.log`). The callback now resolves the
provider after state/code processing and resolves its raw subject before email;
the direct ID flows retain their independently owned email-first guards.

Historical oracle-side expectation failures are retained: Source's WHATWG URL
escapes apostrophe as %27 (initial 44/46), missing token scope persists as an empty
string, and refresh retains it (53/56 runs). Those expectations were corrected
to actual published behavior; Source and comparators were unchanged. A later
67-owner run had two genuine Native configuration-error body differences and
one Source-side state assertion omitting the observer's actual receipt property.
The former were fixed at the authorization HTTP error boundary; the latter now
retains and compares the complete observed before/after state.

Three additional real RSA-signed JWS payloads contain array, null and numeric
JSON instead of a JWT claims object. The unchanged JOSE decoder rejects them and
the real Source factory falls back to access-token userinfo. On the frozen cc6
Native production all three owners failed at the actual browser callback
(60 assertions, `/tmp/issue142-decode-before-owner.log`); the object check now
selects the same fallback. Their signatures do not make them valid claims sets.

On frozen head 63d632ca, composed with main a632 (including user validation and
API-key background processing), strict default/optional-feature workspace and
fixture Clippy, Rustls checks, formatting and TypeScript checks passed. The real
combined Cognito/user-validation program passed **97/97 owners / 4,904 assertions**
(/tmp/issue142-main204-strict97.log, terminal exit 0). Documentation with warnings
denied and the actual repository browser wrapper passed (two browser owners,
22 assertions; /tmp/issue142-main204-docs.log and
/tmp/issue142-main204-browser.log, terminal exit 0).

The final canonical scripts/check.sh run passed 794 default native tests, 845
optional native tests, two fixture tests, 71 harness checks / 754 assertions,
36 Axum checks, three endpoint checks, two inventory checks and both strict
compilation matrices. Its complete SDK phase passed **1,069/1,074 owners /
76,020 assertions**, including all 83 Cognito owners
(/tmp/issue142-main204-final-canonical-cache.log, terminal exit 100). The five
remaining failures are independently timed organization membership (four
created/expiry aliases at observation7), JWT keyring timestamps (40 aliases in
corrupt/legacy/manual/private/recovered/rotated observations), and generated
seed12648430 default/no-refresh/deferred snapshot22 code/message. The latter
remains the public change-password Unauthorized guard owned by #221. Prior
actual-parent evidence establishes the organization timing aliases and earlier
runs establish keyring timing failures; the full current set of 40 aliases does
not claim an exact parent counterfactual. There is no observed Cognito decision,
profile, ownership, token-form or persistence drift. The canonical run stops at
the SDK failures, so it is not claimed green; docs/browser and coverage are
separately measured.

Clean local native coverage ran all 845 optional native tests. Its first wrapper
attempt failed only JWT clock comparisons; all five existing instrumented SDK
groups then passed on the same frozen source with both explicit fixture and
Cargo coverage targets (/tmp/issue142-main204-instrumented-five-groups.log,
terminal exit 0, five groups / 134.793 seconds). The complete native-plus-fixture
LLVM report covers **30,850/40,021 lines (77.084531%)** and passes the unchanged
75% floor (/tmp/issue142-main204-coverage-report.log, terminal exit 0). A previous
uninstrumented-fixture five-group run is retained only as SDK proof, not coverage.
The ordinary canonical attempt with MBX disabled hit a read-only shared-cache
artifact; its normal-cache restart is the final canonical run above. No cache
artifact permissions, checks, thresholds or comparison rules were changed.

Capability requirements are appended only from actual passing, recorded public
Cognito route/category cells, excluding foreign signup setup and callback denial
traces the unchanged collector cannot classify as rejection. All **3,522** parent
requirements remain intact in their original order; **239** measured Cognito
cells bring the ledger to **3,761**, with zero lost parent requirements or missing
new evidence (/tmp/issue142-final-measured-capabilities.json). Independent
provider authorization/persistence review found no remaining blocker.

The typed native profile uses strings and booleans plus supported scalar
coercions; complex user fields and arbitrary malformed callback results are not
claimed equivalent. Additional-field schemas (#184), generalized configured
callback contexts/error composition (#181/#188) and transport malformation
(#193) retain their independent scope. No local dependency patch, hook bypass,
Source code modification or reduced comparison/coverage requirement is used.
