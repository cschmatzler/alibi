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

## Measured proof and remaining publication

The current program passes **79 actual Source/native owners / 2,248 assertions**
(`/tmp/issue142-79-owners-admission-order-fixed.log`, terminal exit 0). It covers
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

All-target strict workspace/fixture Clippy and formatting passed after fixing
three pre-existing whole OAuthProvider test constructors and the shared helper
(`/tmp/issue142-current-strict-whole-literals.log`). The subsequent browser
production repair still requires final strict/canonical proof. Capability
requirements are appended only from actual passing, recorded public Cognito
route/category cells, excluding foreign signup setup and callback denial traces
that the unchanged collector cannot classify as rejection. All 3,433 parent
requirements remain intact in their original order. Final parent rebase,
independent review, canonical/docs/browser and clean coverage remain pending;
this draft does not claim a completed issue or a complete green gate.

The typed native profile uses strings and booleans plus supported scalar
coercions; complex user fields and arbitrary malformed callback results are not
claimed equivalent. Additional-field schemas (#184), generalized configured
callback contexts/error composition (#181/#188) and transport malformation
(#193) retain their independent scope. No local dependency patch, hook bypass,
Source code modification or reduced comparison/coverage requirement is used.
